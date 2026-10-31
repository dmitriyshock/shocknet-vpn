# ShockNet VPN

Self-hosted VPN service based on Xray/VLESS+Reality, with a Telegram access-management bot, a subscription web panel, Nginx TLS termination, and visitor analytics.

The repository is deliberately safe to publish: it contains no server keys, user UUIDs, bot tokens, live configurations, databases, or logs. The installer generates fresh credentials on the target server.

## Components

| Component | Purpose |
| --- | --- |
| `xray/` | Primary VLESS endpoints: Reality (4443), HAPP/mobile (2053), and WebSocket behind Nginx |
| `xray2/` | Additional Reality endpoints on 8443–8446, using alternate SNI domains |
| `bot/` | Telegram bot that approves users and adds/removes them in both Xray configurations |
| `webserver/` | Subscription links, QR pages, Clash YAML, admin dashboard, and traffic display |
| `log-monitor/` | Nginx visitor-log analytics with local GeoIP cache |
| `systemd/` | Units for Xray, bot, panel, and monitoring |

## Requirements

- A new Ubuntu 22.04 or 24.04 server with root access.
- A public IPv4 address and a domain whose `A` record already points to the server.
- A Telegram bot token, its username, and the administrator's Telegram username.
- TCP ports `80`, `443`, `2053`, `4443`, and `8443–8446` open in the firewall/provider panel.

## Installation

Clone this repository, then run the installer as root:

```bash
git clone https://github.com/dmitriyshock/shocknet-vpn.git /tmp/shocknet-vpn
sudo bash /tmp/shocknet-vpn/setup.sh
```

The script installs OS and Python dependencies into `/opt/vpnserver/venv`, downloads Xray, creates fresh Reality keys, a **random** administrator subscription token and an initial administrator profile, obtains a Let's Encrypt certificate, configures Nginx, initializes `/opt/vpnbot/users.json`, and enables five services. It asks for secrets without echoing the bot token. Generated secrets are stored in `/opt/vpnserver/.env` (`0600`).

To update an existing installation, run the same command again. It preserves `.env` and Xray client configurations while updating application files and restarting services.

**Existing installations with `STATIC_TOKEN=admin` or `STATIC_TOKEN=user1` must rotate the administrator credentials after updating.** They were publicly guessable in older versions. On the VPS, after taking a backup and arranging to re-import your own VPN subscription, run:

```bash
sudo /opt/vpnserver/venv/bin/python /opt/vpnserver/repo/scripts/rotate_admin.py --apply
```

This backs up `.env` and both Xray JSON files, replaces the administrator token **and UUID**, and restarts `xray`, `xray2`, `vpnbot`, and `subserver`. Existing administrator VPN connections will briefly disconnect and must import the newly printed subscription URL. Other user UUIDs are preserved. The script does not run automatically during updates.

## Operations

```bash
systemctl status xray xray2 vpnbot subserver log-monitor
journalctl -u vpnbot -f
journalctl -u xray -f
```

The web panel is available at `https://YOUR_DOMAIN`; the Telegram login-protected dashboard is at `/admin`. The bot issues access through its approval flow and updates both Xray instances automatically.

The web service listens on `127.0.0.1:8008`; Nginx is the public entrypoint. Trial keys expire after seven days and a bot job revokes their Xray credentials every minute (as long as the bot runs). Users should not rely on subscription URLs as secure storage: anyone possessing a URL can import that profile until access is revoked.

Optional download links (`HAPP_DOWNLOAD_*`, `CLASH_DOWNLOAD_*`) can be configured in `/opt/vpnserver/.env` with official HTTPS URLs; until then, the panel deliberately shows no dead download buttons. The network metrics interface is auto-detected from the default route, or can be overridden with `METRICS_IFACE`.

The optional `turnproxy.service` unit is provided as an integration point for an existing binary and WireGuard installation. This installer does **not** install that separate component; the dashboard shows it as unavailable when not installed.

### Дополнительные Microsoft Reality-профили для тестов

Если на действующем VPS уже работают Google (`4443`), Cloudflare (`2053`) и другие Reality-профили, их можно **сохранить** и добавить два независимых Microsoft-подключения:

| Имя inbound | TCP-порт | Режим |
| --- | --- | --- |
| `vless-microsoft-8450` | 8450 | VLESS + Reality + Vision |
| `vless-microsoft-mobile-8451` | 8451 | VLESS + Reality без Vision |

Скрипт переносит клиентов и Reality-ключи из существующих профилей `4443` и `2053` только на новые порты. Ни один существующий inbound не удаляется. На сервере:

```bash
git -C /opt/vpnserver/repo pull --ff-only
python3 /opt/vpnserver/repo/scripts/add_microsoft_test_profiles.py
# Проверив вывод сухого прогона и сохранив снапшот VPS:
python3 /opt/vpnserver/repo/scripts/add_microsoft_test_profiles.py --apply
```

При `--apply` скрипт делает резервную копию Xray-конфигурации, проверяет свободные порты и новую конфигурацию настоящим Xray, а затем один раз перезапускает `xray.service`. **Активные сессии на мгновение прервутся.** При ошибке запуска конфигурация откатывается. Проверь также доступность TCP-портов 8450/8451 в firewall VPS и у провайдера: скрипт не открывает их автоматически.

Для ручного теста можно клонировать уже работающие VLESS-профили на клиенте: профиль `4443` → порт `8450`, SNI `www.microsoft.com`; профиль `2053` → порт `8451`, SNI `www.microsoft.com`. Остальные параметры, включая публичный Reality-ключ и short ID, остаются как в соответствующем исходном профиле. Новые тестовые порты пока не публикуются автоматически во всех подписках.

### Диагностика ошибки HTTPS-сертификата

На VPS с отдельным Nginx `stream` на публичном порту `443` нельзя добавлять глобальные NAT-правила вида `iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8443` или аналогичные правила в `PREROUTING`. Они перехватывают все исходящие HTTPS-соединения (включая GitHub) и обходят SNI-маршрутизацию Nginx для входящих подключений. Это может привести к тому, что `shocknet.ru` или внешний сайт получит сертификат `shocknet.online`, даже если оба Let's Encrypt-сертификата действительны.

При такой ошибке проверяйте `iptables -t nat -S OUTPUT`, `iptables -t nat -S PREROUTING` и `nft -a list ruleset`. Сначала сохраните резервную копию NAT-правил и определите их источник автозапуска. Исправлять нужно **только конкретное ошибочное правило**, сохраняя Docker, UFW и VPN-маршруты. Не отключайте проверку сертификата (`curl -k`) и не меняйте внутренние HTTPS-порты ради обхода глобального перенаправления.

Visitor GeoIP lookup is disabled by default to protect visitor privacy. To opt in, provide `GEOIP_HTTPS_ENDPOINT` as an HTTPS URL containing `{ip}` and returning `status/country/regionName/city/lat/lon/isp` fields (compatible with the old `ip-api.com` JSON structure). Visitor IP addresses will be transmitted to that service. Subscription paths and user-stats URLs are excluded from new Nginx access logs; the log monitor also redacts them when parsing old logs.

## Offline tests

The tests cover admin authentication, CSRF protection, subscriptions, basic HTTP routes, trial cleanup, secret rotation, Xray JSON generation, and log redaction. They do not contact Telegram or change a live VPS.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

For an additional check of both generated configs with the actual Xray executable, set `XRAY_TEST_BINARY=/path/to/xray` before the last command. This runs `xray run -test` without starting a tunnel. A full production test still requires a real domain, TLS certificate, firewall configuration and Telegram credentials.

## Security notes

- Do not commit `/opt/vpnserver/.env`, `/opt/xray*/config.json`, bot user data, logs, or databases. `.gitignore` covers these files.
- Back up `/opt/vpnserver/.env`, `/opt/xray/config.json`, `/opt/xray2/config.json`, and `/opt/vpnbot/users.json` securely before rebuilding a server.
- The web admin session is HMAC-signed, expires after seven days, and uses an HttpOnly, Secure, SameSite=Strict cookie. The server must be accessed through HTTPS Nginx.
- Rotate any credential that was ever present in a Git remote URL, configuration file, terminal history, or chat.
- This project is intended for lawful use and is operated at the administrator's responsibility.
