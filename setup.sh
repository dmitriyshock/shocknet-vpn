#!/usr/bin/env bash
# ShockNet VPN — installer for Ubuntu 22.04/24.04
set -Eeuo pipefail
umask 077

REPO_URL="${REPO_URL:-https://github.com/dmitriyshock/shocknet-vpn.git}"
REPO_DIR="/opt/vpnserver/repo"
RUNTIME_DIR="/opt/vpnserver"
ENV_FILE="$RUNTIME_DIR/.env"
XRAY_VERSION="v25.3.6"

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root: sudo bash setup.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --help) echo "Usage: sudo bash setup.sh [--repo-url https://github.com/OWNER/REPO.git]"; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

if [[ -f "$ENV_FILE" ]]; then
  read -r -p "Existing installation detected. Update application files and keep its secrets? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || exit 0
  UPDATE_ONLY=1
else
  UPDATE_ONLY=0
fi

info "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git nginx openssl python3 python3-venv unzip certbot python3-certbot-nginx

mkdir -p "$RUNTIME_DIR" /opt/vpnbot /opt/subserver /opt/xray /opt/xray2 /opt/log-monitor
if [[ -d "$REPO_DIR/.git" ]]; then
  git -C "$REPO_DIR" fetch --quiet origin
  git -C "$REPO_DIR" pull --ff-only --quiet
else
  rm -rf "$REPO_DIR"
  git clone --depth 1 "$REPO_URL" "$REPO_DIR"
fi

info "Installing application files and Python dependencies"
install -m 700 -d "$RUNTIME_DIR/venv"
python3 -m venv "$RUNTIME_DIR/venv"
"$RUNTIME_DIR/venv/bin/pip" install --quiet --upgrade pip
"$RUNTIME_DIR/venv/bin/pip" install --quiet -r "$REPO_DIR/requirements.txt"
install -m 600 "$REPO_DIR/bot/bot.py" /opt/vpnbot/bot.py
install -m 600 "$REPO_DIR/webserver/server.py" /opt/subserver/server.py
install -m 644 "$REPO_DIR/webserver/chartjs.min.js" /opt/subserver/chartjs.min.js
install -m 600 "$REPO_DIR/log-monitor/monitor.py" /opt/log-monitor/monitor.py
install -m 644 "$REPO_DIR/systemd/"*.service /etc/systemd/system/

info "Installing Xray $XRAY_VERSION"
if [[ ! -x /opt/xray/xray ]]; then
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  curl --fail --location --silent --show-error \
    "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
    --output "$tmpdir/xray.zip"
  unzip -q "$tmpdir/xray.zip" -d "$tmpdir/xray"
  install -m 755 "$tmpdir/xray/xray" /opt/xray/xray
fi
install -m 755 /opt/xray/xray /opt/xray2/xray

if [[ "$UPDATE_ONLY" -eq 0 ]]; then
  read -r -p "Public server IP: " SERVER_IP
  read -r -p "Domain (DNS A record must already point to this server): " DOMAIN
  read -r -s -p "Telegram bot token: " BOT_TOKEN; echo
  read -r -p "Telegram administrator username (without @): " ADMIN_USERNAME
  read -r -p "Telegram bot username (without @): " BOT_USERNAME
  [[ -n "$SERVER_IP" && -n "$DOMAIN" && -n "$BOT_TOKEN" && -n "$ADMIN_USERNAME" && -n "$BOT_USERNAME" ]] || die "All fields are required"
  [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid domain"
  [[ "$BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || die "Invalid Telegram bot token format"
  [[ "$ADMIN_USERNAME" =~ ^[A-Za-z0-9_]{3,32}$ ]] || die "Invalid administrator username"
  [[ "$BOT_USERNAME" =~ ^[A-Za-z0-9_]{5,32}$ ]] || die "Invalid bot username"
  python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$SERVER_IP" || die "Invalid IPv4 address"

  keys=$(/opt/xray/xray x25519)
  XRAY_PRIVATE_KEY=$(awk '/Private/{print $3}' <<<"$keys")
  XRAY_PUBLIC_KEY=$(awk '/Public/{print $3}' <<<"$keys")
  [[ -n "$XRAY_PRIVATE_KEY" && -n "$XRAY_PUBLIC_KEY" ]] || die "Could not generate Reality keys"
  XRAY_SHORT_ID=$(openssl rand -hex 8)
  STATIC_UUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
  STATIC_TOKEN=$(openssl rand -hex 24)
  SESSION_SECRET=$(openssl rand -hex 32)

  cat > "$ENV_FILE" <<EOF
BOT_TOKEN=$BOT_TOKEN
ADMIN_USERNAME=$ADMIN_USERNAME
BOT_USERNAME=$BOT_USERNAME
SERVER_IP=$SERVER_IP
DOMAIN=$DOMAIN
XRAY_PRIVATE_KEY=$XRAY_PRIVATE_KEY
XRAY_PUBLIC_KEY=$XRAY_PUBLIC_KEY
XRAY_SHORT_ID=$XRAY_SHORT_ID
XRAY_SNI=www.microsoft.com
XRAY_PORT=4443
XRAY_PORT_HAPP=2053
STATIC_UUID=$STATIC_UUID
STATIC_LABEL=Administrator
STATIC_TOKEN=$STATIC_TOKEN
SESSION_SECRET=$SESSION_SECRET
EOF
  chmod 600 "$ENV_FILE"

  info "Generating fresh Xray configurations"
  cat > /opt/xray/config.json <<EOF
{"log":{"loglevel":"warning"},"stats":{},"api":{"tag":"api","services":["StatsService"]},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"inbounds":[{"tag":"api-in","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}},{"tag":"vless-ws","listen":"127.0.0.1","port":8880,"protocol":"vless","settings":{"clients":[{"id":"$STATIC_UUID","email":"admin_ws"}],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vless"}}},{"tag":"vless-reality","listen":"0.0.0.0","port":4443,"protocol":"vless","settings":{"clients":[{"id":"$STATIC_UUID","email":"admin","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"www.microsoft.com:443","serverNames":["www.microsoft.com"],"privateKey":"$XRAY_PRIVATE_KEY","shortIds":["$XRAY_SHORT_ID"]}}},{"tag":"vless-happ","listen":"0.0.0.0","port":2053,"protocol":"vless","settings":{"clients":[{"id":"$STATIC_UUID","email":"admin_happ"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"www.microsoft.com:443","serverNames":["www.microsoft.com"],"privateKey":"$XRAY_PRIVATE_KEY","shortIds":["$XRAY_SHORT_ID"]}}}],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"type":"field","inboundTag":["api-in"],"outboundTag":"api"}]}}
EOF
  cat > /opt/xray2/config.json <<EOF
{"log":{"loglevel":"warning"},"stats":{},"api":{"tag":"api","services":["StatsService"]},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},"inbounds":[{"tag":"api-in","listen":"127.0.0.1","port":10086,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}},$(for pair in '8443 vk.com' '8444 yandex.ru' '8445 ok.ru' '8446 dzen.ru'; do set -- $pair; printf '{"tag":"vless-reality-%s","listen":"0.0.0.0","port":%s,"protocol":"vless","settings":{"clients":[{"id":"%s","email":"admin","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"%s:443","serverNames":["%s"],"privateKey":"%s","shortIds":["%s"]}}},' "$1" "$1" "$STATIC_UUID" "$2" "$2" "$XRAY_PRIVATE_KEY" "$XRAY_SHORT_ID"; done | sed 's/,$//')],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"type":"field","inboundTag":["api-in"],"outboundTag":"api"}]}}
EOF
  chmod 600 /opt/xray/config.json /opt/xray2/config.json
fi

# A new installation must have a database before the Telegram bot starts.
# Preserve existing users and keys during subsequent updates.
if [[ ! -f /opt/vpnbot/users.json ]]; then
  printf '{"admin_id":0,"users":{},"trial_keys":{}}\n' > /opt/vpnbot/users.json
fi
chmod 600 /opt/vpnbot/users.json

# Read the preserved or newly created settings; never print this file.
set -a; . "$ENV_FILE"; set +a
info "Obtaining TLS certificate for $DOMAIN"
cat > /etc/nginx/sites-available/shocknet <<EOF
server { listen 80; server_name $DOMAIN; location / { return 200 "ShockNet certificate setup"; } }
EOF
ln -sfn /etc/nginx/sites-available/shocknet /etc/nginx/sites-enabled/shocknet
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable --now nginx
if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" --redirect
fi
cat > /etc/nginx/sites-available/shocknet <<EOF
server { listen 80; server_name $DOMAIN; return 301 https://\$host\$request_uri; }
server { listen 443 ssl http2; server_name $DOMAIN;
  ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
  add_header Strict-Transport-Security "max-age=31536000" always;
  location /vless { access_log off; proxy_pass http://127.0.0.1:8880; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; proxy_read_timeout 300s; }
  location ^~ /sub/ { access_log off; proxy_pass http://127.0.0.1:8008; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-Proto \$scheme; }
  location ^~ /api/user-stats/ { access_log off; proxy_pass http://127.0.0.1:8008; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-Proto \$scheme; }
  location / { proxy_pass http://127.0.0.1:8008; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-Proto \$scheme; }
}
EOF
nginx -t && systemctl reload-or-restart nginx

if [[ "${STATIC_TOKEN:-}" == "admin" || "${STATIC_TOKEN:-}" == "user1" ]]; then
  echo "WARNING: Legacy administrator subscription token detected. Run /opt/vpnserver/venv/bin/python /opt/vpnserver/repo/scripts/rotate_admin.py --apply (this disconnects admin clients)." >&2
fi

systemctl daemon-reload
for service in xray xray2 vpnbot subserver log-monitor; do
  systemctl enable "$service"
  systemctl restart "$service"   # Also load updated code on repeat installs.
done
info "Done. Web panel: https://$DOMAIN  Admin: https://$DOMAIN/admin"
