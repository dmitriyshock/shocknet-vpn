#!/usr/bin/env python3
import base64, collections, hashlib, hmac, io, json, os, secrets, subprocess, threading, time, urllib.parse, urllib.request, yaml
import qrcode
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from dotenv import load_dotenv

load_dotenv("/opt/vpnserver/.env")

# ── config ────────────────────────────────────────────────────────────────────
SERVER_IP   = os.getenv("SERVER_IP", "")
DOMAIN        = os.getenv("DOMAIN", "shocknet.online")

UUID        = os.getenv("STATIC_UUID", "")
PUBLIC_KEY  = os.getenv("XRAY_PUBLIC_KEY", "")
SHORT_ID    = os.getenv("XRAY_SHORT_ID", "")
PORT_VLESS  = int(os.getenv("XRAY_PORT", "4443"))
PORT_WS     = 443  # nginx TLS → xray WS на 8880
SNI         = os.getenv("XRAY_SNI", "www.microsoft.com")
REMARK      = "ShockNet"
WEB_PORT    = 8008
XRAY_API    = "127.0.0.1:10085"
XRAY_API2   = "127.0.0.1:10086"
USERS_FILE  = "/opt/vpnbot/users.json"
TOTAL_LIMIT = 3 * 1024 ** 4

BOT_TOKEN      = os.getenv("BOT_TOKEN", "")
BOT_USERNAME   = os.getenv("BOT_USERNAME", "myvpngift_bot")
SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_hex(32)

STATIC_USER = {
    "email": os.getenv("STATIC_TOKEN", "user1"),
    "label": os.getenv("STATIC_LABEL", "Администратор"),
    "token": os.getenv("STATIC_TOKEN", "user1"),
    "uuid":  UUID,
    "username": os.getenv("ADMIN_USERNAME", ""),
    "approved": True,
}

DL_CLASH = {"win": "#", "mac": "#", "linux": "#"}
DL_HAPP  = {"android": "#", "ios": "#"}

# ── auth ──────────────────────────────────────────────────────────────────────
def make_session_token():
    return hmac.new(SESSION_SECRET.encode(), b"admin", hashlib.sha256).hexdigest()

SESSION_TOKEN = make_session_token()

def is_authenticated(cookie_header: str) -> bool:
    if not cookie_header:
        return False
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == "session" and v.strip() == SESSION_TOKEN:
            return True
    return False

def verify_telegram_auth(data: dict) -> bool:
    """Проверяем подпись от Telegram Login Widget."""
    check_hash = data.get("hash", "")
    auth_date  = int(data.get("auth_date", 0))
    # Подпись не старше 24 часов
    if abs(time.time() - auth_date) > 86400:
        return False
    fields = {k: v for k, v in data.items() if k != "hash"}
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    computed = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, check_hash)

LOGIN_HTML = f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyVPN — Вход</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d0d12;color:#e2e8f0;font-family:-apple-system,'Segoe UI',sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.box{{background:#16161f;border:1px solid rgba(255,255,255,0.07);border-radius:20px;
  padding:40px;width:100%;max-width:360px;text-align:center}}
h2{{font-size:1.5rem;font-weight:700;margin-bottom:6px;
  background:linear-gradient(135deg,#e2e8f0,#a78bfa);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.sub{{color:#64748b;font-size:.85rem;margin-bottom:32px}}
.tg-wrap{{display:flex;justify-content:center}}
.err{{color:#f87171;font-size:.8rem;margin-top:16px;display:none}}
.err.show{{display:block}}
</style></head>
<body>
<div class="box">
  <h2>MyVPN Admin</h2>
  <p class="sub">Войдите через Telegram</p>
  <div class="tg-wrap">
    <script async src="https://telegram.org/js/telegram-widget.js?22"
      data-telegram-login="{BOT_USERNAME}"
      data-size="large"
      data-auth-url="https://{DOMAIN}/tg-auth"
      data-request-access="write"></script>
  </div>
  <div class="err ERRCLASS" id="err">ERRMSG</div>
</div>
</body></html>"""

# ── users ─────────────────────────────────────────────────────────────────────
def load_db() -> dict:
    try:
        return json.loads(open(USERS_FILE).read())
    except Exception:
        return {"admin_id": 0, "users": {}}

def active_users() -> list:
    """Approved users for subscriptions."""
    db = load_db()
    out = []
    for tuid, u in db.get("users", {}).items():
        if u.get("approved") and u.get("token"):
            out.append({
                "email":    u.get("email", f"tg_{tuid}"),
                "label":    u.get("name", f"User {tuid}"),
                "username": u.get("username", ""),
                "token":    u["token"],
                "uuid":     u.get("uuid", UUID),
                "approved": True,
            })
    return out

def all_users_for_stats() -> list:
    """All users that ever had an email — for traffic accounting."""
    db = load_db()
    out = [STATIC_USER]
    for tuid, u in db.get("users", {}).items():
        email = u.get("email")
        if not email:
            continue
        out.append({
            "email":    email,
            "label":    u.get("name", f"User {tuid}"),
            "approved": u.get("approved", False),
        })
    # Тестовые (trial) ключи — полноценно в статистике, с пометкой
    for token, t in db.get("trial_keys", {}).items():
        email = t.get("email")
        if not email:
            continue
        base_label = t.get("label", "Тестовый")
        out.append({
            "email":    email,
            "label":    f"🧪 {base_label} (тестовый ключ)",
            "approved": True,
            "trial":    True,
        })
    return out

def find_user(token: str):
    import time
    if token == STATIC_USER["token"]:
        return STATIC_USER
    for u in active_users():
        if u["token"] == token:
            return u
    # Trial keys
    db = load_db()
    t  = db.get("trial_keys", {}).get(token)
    if t and t.get("expires_at", 0) > time.time():
        return {
            "email":    t["email"],
            "label":    t.get("label", "Тестовый"),
            "token":    token,
            "uuid":     t["uuid"],
            "approved": True,
        }
    return None

# ── xray stats (persistent across restarts) ───────────────────────────────────
STATS_FILE = "/opt/vpnbot/stats_persistent.json"

def _load_persistent() -> dict:
    try:
        return json.loads(open(STATS_FILE).read())
    except Exception:
        return {}

def _save_persistent(data: dict):
    try:
        open(STATS_FILE, "w").write(json.dumps(data))
    except Exception:
        pass

def _query_xray(reset: bool = False, api: str = XRAY_API, binary: str = "/opt/xray/xray") -> dict:
    cmd = [binary, "api", "statsquery", f"--server={api}"]
    if reset:
        cmd.append("--reset")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        data = json.loads(r.stdout)
        out = {}
        for item in data.get("stat", []):
            n, v = item["name"], int(item.get("value", 0))
            if "user>>>" in n:
                parts = n.split(">>>")
                email, direction = parts[1], parts[3]
                if email not in out:
                    out[email] = {"uplink": 0, "downlink": 0}
                out[email][direction] = v
        return out
    except Exception:
        return {}

def _query_live() -> dict:
    return _merge_aliases(_query_xray(reset=False, api=XRAY_API))

def _query_live2() -> dict:
    return _merge_aliases(_query_xray(reset=False, api=XRAY_API2, binary="/opt/xray2/xray"))

def snapshot_stats():
    """Считываем счётчики с --reset (дельта с прошлого snapshot) и прибавляем к persistent."""
    delta = _merge_aliases(_query_xray(reset=True, api=XRAY_API))
    delta2 = _merge_aliases(_query_xray(reset=True, api=XRAY_API2, binary="/opt/xray2/xray"))
    saved = _merge_aliases(_load_persistent())
    for email, vals in delta.items():
        if email not in saved:
            saved[email] = {"uplink": 0, "downlink": 0}
        saved[email]["uplink"]   += vals.get("uplink", 0)
        saved[email]["downlink"] += vals.get("downlink", 0)
    for email, vals in delta2.items():
        if email not in saved:
            saved[email] = {"uplink": 0, "downlink": 0}
        saved[email]["uplink"]   += vals.get("uplink", 0)
        saved[email]["downlink"] += vals.get("downlink", 0)
    _save_persistent(saved)

def get_stats() -> dict:
    """persistent (всё до последнего snapshot) + live (с момента последнего snapshot)."""
    saved = _merge_aliases(_load_persistent())
    live  = _merge_aliases(_query_live())
    live2 = _merge_aliases(_query_live2())
    out   = {}
    for email in set(saved) | set(live) | set(live2):
        s = saved.get(email, {})
        l = live.get(email, {})
        l2 = live2.get(email, {})
        out[email] = {
            "uplink":   s.get("uplink", 0)   + l.get("uplink", 0)   + l2.get("uplink", 0),
            "downlink": s.get("downlink", 0) + l.get("downlink", 0) + l2.get("downlink", 0),
        }
    return out

def user_traffic(stats: dict, email: str) -> tuple:
    """Суммарный трафик пользователя — основной + _happ алиас. Единая точка расчёта."""
    s1 = stats.get(email, {})
    s2 = stats.get(email + "_happ", {})
    ul = s1.get("uplink", 0)   + s2.get("uplink", 0)
    dl = s1.get("downlink", 0) + s2.get("downlink", 0)
    return ul, dl

EMAIL_ALIASES = {
    "user1_admin":      "user1",
    "user1_admin_happ": "user1_happ",
    "user1_ws":         "user1",
    "user1_admin_ws":   "user1",
    "tg_8677536826_ws": "tg_8677536826",
    "tg_1483599707_ws": "tg_1483599707",
    "user1_8443":          "user1",
    "user1_admin_8443":    "user1",
    "tg_8677536826_8443":  "tg_8677536826",
    "user1_happ_8443":     "user1_happ",
    "user1_admin_happ_8443": "user1_happ",
    "tg_8677536826_happ_8443": "tg_8677536826_happ",
    "tg_1483599707_happ_8443": "tg_1483599707_happ",
}

def _merge_aliases(d: dict) -> dict:
    out = {}
    for email, vals in d.items():
        key = EMAIL_ALIASES.get(email, email)
        if key not in out:
            out[key] = {"uplink": 0, "downlink": 0}
        out[key]["uplink"]   += vals.get("uplink", 0)
        out[key]["downlink"] += vals.get("downlink", 0)
    return out

def _autosave_stats():
    def loop():
        while True:
            time.sleep(300)
            snapshot_stats()
    threading.Thread(target=loop, daemon=True).start()

# ── system metrics ────────────────────────────────────────────────────────────
METRICS_IFACE   = "ens1"
METRICS_MAXLEN  = 720   # 1 час при интервале 5 сек
METRICS_INTERVAL = 5
metrics_buf  = collections.deque(maxlen=METRICS_MAXLEN)
metrics_on   = True   # флаг сбора
_prev_cpu    = None
_prev_net    = None

def _read_cpu():
    with open("/proc/stat") as f:
        line = f.readline()
    vals = list(map(int, line.split()[1:]))
    total = sum(vals)
    idle  = vals[3] + vals[4]  # idle + iowait
    return total, idle

def _read_net():
    with open("/proc/net/dev") as f:
        for line in f:
            if METRICS_IFACE + ":" in line:
                parts = line.split()
                return int(parts[1]), int(parts[9])  # rx_bytes, tx_bytes
    return 0, 0

def _read_ram():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            info[k.strip()] = int(v.split()[0])
    total = info["MemTotal"]
    avail = info["MemAvailable"]
    used  = total - avail
    return round(used / total * 100, 1), used // 1024, total // 1024  # %, MB, MB

def _read_disk():
    st = os.statvfs("/")
    total = st.f_blocks * st.f_frsize
    free  = st.f_bavail * st.f_frsize
    used  = total - free
    return round(used / total * 100, 1), used // (1024**3), total // (1024**3)

def _collect_metrics():
    global _prev_cpu, _prev_net, metrics_on
    while True:
        time.sleep(METRICS_INTERVAL)
        if not metrics_on:
            continue
        try:
            # CPU
            cur_cpu = _read_cpu()
            cpu_pct = 0.0
            if _prev_cpu:
                d_total = cur_cpu[0] - _prev_cpu[0]
                d_idle  = cur_cpu[1] - _prev_cpu[1]
                cpu_pct = round((1 - d_idle / max(d_total, 1)) * 100, 1)
            _prev_cpu = cur_cpu

            # Net bytes/s
            cur_net = _read_net()
            rx_s = tx_s = 0
            if _prev_net:
                rx_s = max(0, cur_net[0] - _prev_net[0]) // METRICS_INTERVAL
                tx_s = max(0, cur_net[1] - _prev_net[1]) // METRICS_INTERVAL
            _prev_net = cur_net

            ram_pct, ram_used_mb, ram_total_mb = _read_ram()
            disk_pct, disk_used_gb, disk_total_gb = _read_disk()

            metrics_buf.append({
                "ts":       int(time.time()),
                "cpu":      cpu_pct,
                "ram":      ram_pct,
                "ram_used": ram_used_mb,
                "ram_total":ram_total_mb,
                "rx":       rx_s,
                "tx":       tx_s,
                "disk":     disk_pct,
                "disk_used":disk_used_gb,
                "disk_total":disk_total_gb,
            })
        except Exception:
            pass

def _start_metrics():
    # прогреваем prev-значения
    global _prev_cpu, _prev_net
    _prev_cpu = _read_cpu()
    _prev_net = _read_net()
    threading.Thread(target=_collect_metrics, daemon=True).start()

def fmt(b):
    b = int(b)
    if b < 1024:      return f"{b} B"
    if b < 1024**2:   return f"{b/1024:.1f} KB"
    if b < 1024**3:   return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"

def make_qr_b64(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# ── vless / subs ──────────────────────────────────────────────────────────────
PORT_HAPP = 2053  # fallback Reality без flow
PORT_R2   = 8443  # xray2 standalone (Reality+Vision), vk.com SNI
R2_SNI    = "vk.com"

# Reality-профили с разными whitelisted SNI (порт, sni, метка) — авто-выбор лучшего
SNI_PROFILES = [
    (8443, "vk.com",     "VK"),
    (8444, "yandex.ru",  "Yandex"),
    (8445, "ok.ru",      "OK"),
    (8446, "dzen.ru",    "Dzen"),
]

def vless_link(uid=None, flow=True, port=None, name=None, sni=None):
    uid  = uid or UUID
    port = port or PORT_VLESS
    params = {
        "security": "reality", "sni": sni or SNI, "fp": "firefox",
        "pbk": PUBLIC_KEY, "sid": SHORT_ID,
        "type": "tcp", "headerType": "none", "encryption": "none",
    }
    if flow:
        params["flow"] = "xtls-rprx-vision"
    p = urllib.parse.urlencode(params)
    label = name or REMARK
    return f"vless://{uid}@{SERVER_IP}:{port}?{p}#{urllib.parse.quote(label)}"

def ws_link(uid=None, name=None):
    """VLESS+WS+TLS через домен — обход DPI на WiFi."""
    uid = uid or UUID
    params = {
        "security": "tls", "sni": DOMAIN, "fp": "chrome",
        "type": "ws", "path": "/vless", "encryption": "none",
    }
    p = urllib.parse.urlencode(params)
    label = name or (REMARK + " · WS")
    return f"vless://{uid}@{DOMAIN}:{PORT_WS}?{p}#{urllib.parse.quote(label)}"

def v2ray_sub(uid=None):
    # Reality-профили на разных whitelisted SNI — выбираешь в HAPP какой работает лучше
    links = [vless_link(uid, flow=False, port=port, name=REMARK + " · " + label, sni=sni)
             for port, sni, label in SNI_PROFILES]
    combined = "\n".join(links)
    return base64.b64encode(combined.encode()).decode()

RU_DOMAINS = [
    "vk.com","vk.ru","vkontakte.ru","userapi.com","vkuseraudio.net",
    "ok.ru","odnoklassniki.ru",
    "yandex.ru","yandex.net","yandex.com","yandex.st","yandex-team.ru",
    "ya.ru","yastatic.net","yandexcloud.net","yandex.kz",
    "mail.ru","my.mail.ru","imgsmail.ru","mradx.net",
    "sber.ru","sberbank.ru","sberpay.ru","sbermarket.ru","domclick.ru",
    "gosuslugi.ru","mos.ru","nalog.gov.ru","nalog.ru","pfr.gov.ru",
    "kremlin.ru","government.ru","cbr.ru","rkn.gov.ru",
    "ozon.ru","wildberries.ru","avito.ru","youla.ru","cian.ru",
    "lamoda.ru","dns-shop.ru","mvideo.ru","eldorado.ru",
    "kinopoisk.ru","ivi.ru","okko.tv","more.tv","premier.one",
    "rbc.ru","ria.ru","tass.ru","lenta.ru","kommersant.ru",
    "interfax.ru","rt.com","1tv.ru","russia.tv","ntv.ru",
    "rambler.ru","gazeta.ru","iz.ru","mk.ru","aif.ru",
    "mts.ru","beeline.ru","megafon.ru","tele2.ru","rostelecom.ru",
    "2gis.ru","pochta.ru","russianpost.ru","hh.ru","superjob.ru",
    "tinkoff.ru","vtb.ru","alfabank.ru","raiffeisen.ru","gazprombank.ru",
    "habr.com","pikabu.ru","dzen.ru","zen.yandex.ru",
    "2ip.ru","reg.ru","beget.ru","timeweb.ru",
]

def clash_yaml(uid=None):
    uid = uid or UUID
    # Reality-профили на разных whitelisted SNI
    proxies_list = [{
        "name": REMARK + " · " + label,
        "type": "vless",
        "server": SERVER_IP, "port": port, "uuid": uid,
        "network": "tcp", "tls": True, "udp": True,
        "packet-encoding": "xudp",
        "reality-opts": {"public-key": PUBLIC_KEY, "short-id": SHORT_ID},
        "servername": sni, "client-fingerprint": "chrome",
    } for port, sni, label in SNI_PROFILES]
    proxy_names = [REMARK + " · " + label for _, _, label in SNI_PROFILES]
    GRP = "ShockNet"
    rules = (
        [f"IP-CIDR,{SERVER_IP}/32,DIRECT,no-resolve",
         f"DOMAIN,{DOMAIN},DIRECT",
         "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
         "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
         "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
         "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"]
        + [f"DOMAIN-SUFFIX,{d},DIRECT" for d in RU_DOMAINS]   # ручной список (работает без баз)
        + ["GEOSITE,category-ru,DIRECT",      # все РФ-домены из базы — мимо VPN
           "GEOSITE,category-gov-ru,DIRECT",  # госуслуги, gov-сайты
           "GEOIP,RU,DIRECT,no-resolve"]      # любой IP в России — мимо VPN
        + [f"MATCH,{GRP}"]
    )
    return yaml.dump({
        "mixed-port": 7890, "allow-lan": True,
        "mode": "rule", "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "geodata-mode": True,
        "geo-auto-update": True,
        "geo-update-interval": 168,
        "geox-url": {
            "geoip": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
            "geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        },
        "dns": {
            "enable": True,
            "use-hosts": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["1.1.1.1", "8.8.8.8"],
            "nameserver": ["1.1.1.1", "8.8.8.8"],
            "fake-ip-filter": [
                "*.lan", "stun.*.*.*", "stun.*.*",
                "time.windows.com", "time.nist.gov", "time.apple.com",
                "*.msftconnecttest.com", "*.msftncsi.com",
                "+.xboxlive.com", "*.ipv6.microsoft.com",
            ],
        },
        "proxies": proxies_list,
        "proxy-groups": [
            # Одна группа url-test: сама тестит все SNI и берёт самый быстрый рабочий
            {"name": GRP, "type": "url-test", "proxies": proxy_names,
             "url": "http://www.gstatic.com/generate_204", "interval": 120, "tolerance": 80},
        ],
        "rules": rules,
    }, allow_unicode=True, default_flow_style=False)

# ── CSS / JS (shared) ─────────────────────────────────────────────────────────
CSS = """
:root{--bg:#0d0d12;--s:#16161f;--s2:#1e1e2a;--br:rgba(255,255,255,0.07);
  --p:#a78bfa;--g:#34d399;--r:#f87171;--t:#e2e8f0;--m:#64748b}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:-apple-system,'Segoe UI',sans-serif;
  min-height:100vh;padding:32px 16px 60px}
.wrap{max-width:680px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
h1{font-size:1.9rem;font-weight:700;
  background:linear-gradient(135deg,#e2e8f0,var(--p));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sub{color:var(--m);font-size:.9rem}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(167,139,250,.1);
  border:1px solid rgba(167,139,250,.25);border-radius:100px;padding:5px 12px;
  font-size:.72rem;color:var(--p);text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px}
.dot{width:6px;height:6px;border-radius:50%;background:var(--g);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.card{background:var(--s);border:1px solid var(--br);border-radius:16px;overflow:hidden}
.card:hover{border-color:rgba(167,139,250,.25)}
.card-head{display:flex;align-items:center;gap:14px;padding:20px;border-bottom:1px solid var(--br)}
.icon{width:46px;height:46px;border-radius:12px;display:flex;align-items:center;
  justify-content:center;font-size:1.4rem;flex-shrink:0}
.icon-stat{background:rgba(167,139,250,.12);border:1px solid rgba(167,139,250,.2)}
.icon-clash{background:linear-gradient(135deg,#f59e0b,#dc2626)}
.icon-happ{background:linear-gradient(135deg,#06b6d4,#10b981)}
.card-title{font-size:1rem;font-weight:700}
.card-sub{font-size:.75rem;color:var(--m);margin-top:2px}
.card-body{padding:16px 20px;display:flex;flex-direction:column;gap:10px}
.ptag{display:inline-block;background:var(--s2);border:1px solid var(--br);
  border-radius:6px;padding:2px 8px;font-size:.68rem;color:var(--m);margin:2px 2px 0 0}
.tblock{padding:16px 20px;border-bottom:1px solid var(--br)}
.trow{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:8px}
.tlabel{font-size:.72rem;color:var(--m);text-transform:uppercase;letter-spacing:.05em}
.tval{font-size:.9rem}
.track{height:6px;background:rgba(255,255,255,.07);border-radius:100px;overflow:hidden;margin-bottom:6px}
.fill{height:100%;border-radius:100px;transition:width .6s}
.tmeta{display:flex;justify-content:space-between;font-size:.73rem}
.urow{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--br)}
.urow:last-child{border-bottom:none}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#4f46e5);
  display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.78rem;color:#fff;flex-shrink:0}
.avatar.rev{background:linear-gradient(135deg,#4b5563,#374151)}
.uinfo{flex:1}.uname{font-weight:600;font-size:.88rem}.uemail{font-size:.7rem;color:var(--m);font-family:monospace}
.urev{font-size:.68rem;color:var(--r);background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.2);
  border-radius:5px;padding:1px 6px;margin-left:6px}
.tstats{display:flex;gap:14px;align-items:center}
.si{text-align:center}.sv{font-size:.9rem;font-weight:700;font-family:monospace}
.sv.up{color:var(--g)}.sv.dn{color:#60a5fa}
.sl{font-size:.62rem;color:var(--m);text-transform:uppercase;margin-top:1px}
.stotal{font-size:.76rem;font-weight:600;color:var(--p);background:rgba(167,139,250,.08);
  border:1px solid rgba(167,139,250,.15);border-radius:7px;padding:5px 9px;white-space:nowrap}
.crow{display:flex;align-items:center;gap:8px;background:var(--s2);
  border:1px solid var(--br);border-radius:9px;padding:9px 12px;transition:border-color .15s}
.crow.flash{border-color:var(--g)!important}
.cv{flex:1;font-family:'Courier New',monospace;font-size:.75rem;color:#c4b5fd;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;user-select:all}
.cb{background:none;border:1px solid rgba(167,139,250,.3);border-radius:6px;
  color:var(--p);padding:5px 10px;font-size:.72rem;font-weight:600;cursor:pointer;
  white-space:nowrap;flex-shrink:0;transition:all .15s}
.cb:hover{background:rgba(167,139,250,.12);border-color:var(--p)}
.cb.ok{background:rgba(52,211,153,.12);border-color:var(--g);color:var(--g)}
.flabel{font-size:.68rem;color:var(--m);text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px}
.divider{border:none;border-top:1px solid var(--br);margin:2px 0}
.qr-wrap{display:flex;flex-direction:column;align-items:center;gap:10px;padding:14px 0 4px}
.qr-wrap canvas,.qr-wrap img{border-radius:12px;border:3px solid rgba(255,255,255,.08);
  background:#fff;padding:10px;width:180px;height:180px}
.qr-hint{font-size:.72rem;color:var(--m);text-align:center}
.dlrow{display:flex;flex-wrap:wrap;gap:7px;padding:14px 20px;border-top:1px solid var(--br)}
.dllabel{font-size:.68rem;color:var(--m);text-transform:uppercase;letter-spacing:.05em;padding:10px 20px 0}
.dlbtn{display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.04);
  border:1px solid var(--br);border-radius:7px;padding:7px 13px;text-decoration:none;
  color:var(--m);font-size:.78rem;transition:all .15s}
.dlbtn:hover{border-color:var(--p);color:var(--p);background:rgba(167,139,250,.06)}
.strip{background:var(--s);border:1px solid var(--br);border-radius:12px;
  display:flex;flex-wrap:wrap;overflow:hidden}
.si2{padding:12px 24px;text-align:center;border-right:1px solid var(--br);flex:1;min-width:120px}
.si2:last-child{border-right:none}
.sl2{font-size:.68rem;color:var(--m);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px}
.sv2{font-size:.9rem;font-weight:600;color:var(--p);font-family:monospace}
.pxbtn{display:flex;align-items:center;gap:14px;
  background:linear-gradient(135deg,rgba(229,112,0,.1),rgba(229,112,0,.04));
  border:1px solid rgba(229,112,0,.3);border-radius:16px;padding:18px 20px;
  text-decoration:none;color:var(--t);transition:all .2s}
.pxbtn:hover{border-color:rgba(229,112,0,.65);transform:translateY(-1px)}
.pxtxt{flex:1;display:flex;flex-direction:column;gap:2px}
.pxname{font-size:1.05rem;font-weight:700;color:#fb923c}
.pxsub{font-size:.78rem;color:var(--m)}
.pxport{font-family:monospace;font-size:.82rem;font-weight:700;color:#fb923c;
  background:rgba(229,112,0,.13);border:1px solid rgba(229,112,0,.22);
  border-radius:7px;padding:5px 11px;flex-shrink:0}
.refresh-area{padding:10px 20px;font-size:.72rem;color:var(--m);
  display:flex;justify-content:space-between;border-top:1px solid var(--br)}
.rbtn{background:none;border:1px solid var(--br);border-radius:6px;color:var(--m);
  padding:4px 10px;cursor:pointer;font-size:.72rem;transition:all .15s}
.rbtn:hover{border-color:var(--p);color:var(--p)}

/* system controls */
.sys-row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.sys-info{flex:1}
.sys-name{font-weight:600;font-size:.92rem;margin-bottom:4px}
.sys-status{font-size:.78rem;display:flex;align-items:center;gap:6px}
.st-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;display:inline-block}
.st-on{background:#34d399;box-shadow:0 0 6px #34d399}
.st-off{background:#f87171;box-shadow:0 0 6px #f87171}
.st-unknown{background:#64748b}
.sys-btns{display:flex;gap:8px;flex-shrink:0}
.sys-btn{border:none;border-radius:8px;padding:8px 16px;font-size:.8rem;font-weight:600;
  cursor:pointer;transition:all .15s;white-space:nowrap}
.sys-btn:disabled{opacity:.45;cursor:not-allowed}
.sys-btn-on{background:rgba(52,211,153,.15);border:1px solid rgba(52,211,153,.35);color:#34d399}
.sys-btn-on:hover:not(:disabled){background:rgba(52,211,153,.25)}
.sys-btn-off{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.3);color:#f87171}
.sys-btn-off:hover:not(:disabled){background:rgba(248,113,113,.22)}
.sys-btn-danger{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#ef4444}
.sys-btn-danger:hover:not(:disabled){background:rgba(239,68,68,.25)}
@media(max-width:480px){h1{font-size:1.5rem}.tstats{gap:8px}.stotal{display:none}}
"""

JS = """
function fmt(b){b=parseInt(b)||0;
  if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';
  if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}
function renderStats(data){
  const LIMIT=3*1024*1024*1024*1024;
  let tot=0;
  (data.users||[]).forEach(u=>{tot+=(parseInt(u.uplink)||0)+(parseInt(u.downlink)||0)});
  const pct=Math.min(100,tot/LIMIT*100),pctS=pct.toFixed(1);
  const col=pct>85?'#f87171':pct>60?'#fb923c':'#34d399';
  const srv=document.getElementById('srv-stats');
  if(srv) srv.innerHTML=`
    <div class="trow"><span class="tlabel">Всего на сервере (3 ТБ)</span>
      <span class="tval"><b style="color:var(--t)">${fmt(tot)}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
    <div class="track"><div class="fill" style="width:${pctS}%;background:${col}"></div></div>
    <div class="tmeta"><span style="color:${col}">${pctS}% использовано</span>
      <span style="color:var(--m)">Осталось: ${fmt(LIMIT-tot)}</span></div>`;
  // personal
  const uid=document.getElementById('user-email')?.value;
  if(uid){
    const u=(data.users||[]).find(x=>x.email===uid);
    const el=document.getElementById('user-stats');
    if(el&&u){
      const up=parseInt(u.uplink)||0,dn=parseInt(u.downlink)||0,t=up+dn;
      const up2=Math.min(100,t/LIMIT*100),uc=up2>85?'#f87171':up2>60?'#fb923c':'#34d399';
      el.innerHTML=`
        <div class="trow"><span class="tlabel">Твой расход</span>
          <span class="tval"><b style="color:var(--t)">${fmt(t)}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
        <div class="track"><div class="fill" style="width:${up2.toFixed(1)}%;background:${uc}"></div></div>
        <div class="tmeta">
          <span>↑ <b style="color:#34d399">${fmt(up)}</b> &nbsp; ↓ <b style="color:#60a5fa">${fmt(dn)}</b></span>
          <span style="color:var(--m)">${up2.toFixed(1)}%</span></div>`;
    }
  }
  // admin table
  const tbl=document.getElementById('all-users');
  if(tbl&&data.users) tbl.innerHTML=data.users.map(u=>{
    const up=parseInt(u.uplink)||0,dn=parseInt(u.downlink)||0,tot2=up+dn;
    const init=(u.label||'?').split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2);
    const revBadge=u.approved?'':'<span class="urev">отозван</span>';
    return `<div class="urow">
      <div class="avatar${u.approved?'':' rev'}">${init}</div>
      <div class="uinfo"><div class="uname">${u.label}${revBadge}</div>
        <div class="uemail">${u.email}</div></div>
      <div class="tstats">
        <div class="si"><div class="sv up">↑ ${fmt(up)}</div><div class="sl">Отправлено</div></div>
        <div class="si"><div class="sv dn">↓ ${fmt(dn)}</div><div class="sl">Получено</div></div>
        <div class="stotal">Всего: ${fmt(tot2)}</div>
      </div></div>`;
  }).join('');
  document.getElementById('last-upd').textContent='Обновлено: '+new Date().toLocaleTimeString('ru-RU');
}
function jsonOrLogin(r){
  if(r.redirected || r.status===401 || r.status===302){location.href='/login';throw new Error('auth');}
  const ct=r.headers.get('content-type')||'';
  if(!ct.includes('json')){location.href='/login';throw new Error('notjson');}
  return r.json();
}
function loadStats(){fetch('/api/stats',{credentials:'same-origin'}).then(jsonOrLogin).then(renderStats).catch(()=>{})}
function doCopy(t){
  if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(t);
  return new Promise((res,rej)=>{const e=document.createElement('textarea');
    e.value=t;e.style.cssText='position:fixed;top:-9999px;opacity:0';
    document.body.appendChild(e);e.focus();e.select();
    try{document.execCommand('copy')?res():rej()}catch(ex){rej(ex)}
    document.body.removeChild(e)});
}
function copy(id,txt,btn){
  doCopy((txt||document.querySelector('#'+id+' .cv').textContent).trim())
    .then(()=>flash(id,btn)).catch(()=>flash(id,btn));
}
function flash(id,btn){
  document.getElementById(id)?.classList.add('flash');
  const o=btn.textContent;btn.textContent='✓ Скопировано';btn.classList.add('ok');
  setTimeout(()=>{document.getElementById(id)?.classList.remove('flash');
    btn.textContent=o;btn.classList.remove('ok');},2000);
}
loadStats();setInterval(loadStats,30000);

function loadSystem(){
  fetch('/api/system',{credentials:'same-origin'}).then(jsonOrLogin).then(d=>{
    const bs=document.getElementById('bot-status');
    const ts=document.getElementById('turn-status');
    if(bs){
      bs.innerHTML=d.bot
        ? '<span class="st-dot st-on"></span> Работает'
        : '<span class="st-dot st-off"></span> Остановлен';
      document.getElementById('bot-start').disabled=d.bot;
      document.getElementById('bot-stop').disabled=!d.bot;
    }
    if(ts){
      ts.innerHTML=d.turn
        ? '<span class="st-dot st-on"></span> Работает'
        : '<span class="st-dot st-off"></span> Остановлен';
      document.getElementById('turn-start').disabled=d.turn;
      document.getElementById('turn-stop').disabled=!d.turn;
    }
  }).catch(e=>{
    if(e&&e.message==='auth')return;
    const bs=document.getElementById('bot-status');
    if(bs)bs.innerHTML='<span class="st-dot st-off"></span> ошибка связи: '+(e&&e.message||e);
  });
}

function turnAction(action){
  const btn=document.getElementById(action==='start'?'turn-start':'turn-stop');
  btn.disabled=true;
  fetch('/api/turn/'+action,{method:'POST'})
    .then(r=>r.json()).then(()=>setTimeout(loadSystem,1000))
    .catch(()=>setTimeout(loadSystem,1000));
}

function botAction(action){
  const btn=document.getElementById(action==='start'?'bot-start':'bot-stop');
  btn.disabled=true;
  fetch('/api/bot/'+action,{method:'POST'})
    .then(r=>r.json()).then(()=>setTimeout(loadSystem,1000))
    .catch(()=>setTimeout(loadSystem,1000));
}

if(document.getElementById('sys-card')){loadSystem();setInterval(loadSystem,10000);}
"""

# ── landing page ─────────────────────────────────────────────────────────────
def landing_page() -> str:
    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShockNet VPN</title>
<style>
:root{{--bg:#0d0d12;--s:#16161f;--s2:#1e1e2a;--br:rgba(255,255,255,0.07);
  --p:#a78bfa;--g:#34d399;--t:#e2e8f0;--m:#64748b}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--t);font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh}}

/* hero */
.hero{{text-align:center;padding:80px 20px 60px;position:relative;overflow:hidden}}
.hero::before{{content:'';position:absolute;top:-120px;left:50%;transform:translateX(-50%);
  width:600px;height:600px;border-radius:50%;
  background:radial-gradient(circle,rgba(124,58,237,.15) 0%,transparent 70%);
  pointer-events:none}}
.badge{{display:inline-flex;align-items:center;gap:6px;
  background:rgba(167,139,250,.08);border:1px solid rgba(167,139,250,.2);
  border-radius:100px;padding:6px 16px;font-size:.78rem;color:var(--p);margin-bottom:24px}}
.dot{{width:6px;height:6px;border-radius:50%;background:var(--g);animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
h1{{font-size:clamp(2.2rem,6vw,3.5rem);font-weight:800;line-height:1.1;margin-bottom:16px;
  background:linear-gradient(135deg,#fff 30%,var(--p));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.hero-sub{{color:var(--m);font-size:1.05rem;max-width:480px;margin:0 auto 36px;line-height:1.6}}
.hero-btns{{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}}
.btn-main{{background:linear-gradient(135deg,#7c3aed,#4f46e5);border:none;border-radius:10px;
  color:#fff;padding:13px 28px;font-size:.95rem;font-weight:600;cursor:pointer;
  text-decoration:none;display:inline-block;transition:opacity .15s}}
.btn-main:hover{{opacity:.85}}
.btn-ghost{{background:transparent;border:1px solid var(--br);border-radius:10px;
  color:var(--t);padding:13px 28px;font-size:.95rem;font-weight:600;cursor:pointer;
  text-decoration:none;display:inline-block;transition:all .15s}}
.btn-ghost:hover{{border-color:var(--p);color:var(--p)}}

/* stats strip */
.strip{{display:flex;justify-content:center;gap:0;max-width:560px;margin:0 auto 60px;
  background:var(--s);border:1px solid var(--br);border-radius:16px;overflow:hidden;flex-wrap:wrap}}
.si{{padding:20px 32px;text-align:center;border-right:1px solid var(--br);flex:1;min-width:120px}}
.si:last-child{{border-right:none}}
.sv{{font-size:1.4rem;font-weight:700;color:var(--p);font-family:monospace}}
.sl{{font-size:.72rem;color:var(--m);text-transform:uppercase;letter-spacing:.06em;margin-top:4px}}

/* steps */
.section{{max-width:720px;margin:0 auto;padding:0 20px 60px}}
.section-title{{font-size:1.5rem;font-weight:700;margin-bottom:8px}}
.section-sub{{color:var(--m);font-size:.9rem;margin-bottom:28px}}
.steps{{display:flex;flex-direction:column;gap:12px}}
.step{{background:var(--s);border:1px solid var(--br);border-radius:14px;
  padding:20px 22px;display:flex;gap:16px;align-items:flex-start}}
.step:hover{{border-color:rgba(167,139,250,.25)}}
.step-num{{width:36px;height:36px;border-radius:10px;flex-shrink:0;
  background:linear-gradient(135deg,rgba(124,58,237,.3),rgba(79,70,229,.2));
  border:1px solid rgba(124,58,237,.35);display:flex;align-items:center;
  justify-content:center;font-weight:800;font-size:.9rem;color:var(--p)}}
.step-body{{flex:1}}
.step-title{{font-weight:600;font-size:.95rem;margin-bottom:4px}}
.step-desc{{color:var(--m);font-size:.83rem;line-height:1.5}}
.step-desc a{{color:var(--p);text-decoration:none}}
.step-desc a:hover{{text-decoration:underline}}

/* apps */
.apps{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:60px}}
.app-card{{background:var(--s);border:1px solid var(--br);border-radius:14px;padding:20px;
  text-align:center;text-decoration:none;color:var(--t);transition:all .15s;display:block}}
.app-card:hover{{border-color:rgba(167,139,250,.3);transform:translateY(-2px)}}
.app-icon{{font-size:2.2rem;margin-bottom:10px}}
.app-name{{font-weight:700;font-size:.95rem;margin-bottom:4px}}
.app-desc{{font-size:.75rem;color:var(--m)}}

/* faq */
.faq{{display:flex;flex-direction:column;gap:10px}}
.faq-item{{background:var(--s);border:1px solid var(--br);border-radius:12px;overflow:hidden}}
.faq-q{{padding:16px 20px;font-weight:600;font-size:.9rem;cursor:pointer;
  display:flex;justify-content:space-between;align-items:center;user-select:none}}
.faq-q:hover{{color:var(--p)}}
.faq-arrow{{color:var(--m);transition:transform .2s;font-size:.8rem}}
.faq-a{{color:var(--m);font-size:.85rem;line-height:1.6;padding:0 20px 16px;display:none}}
.faq-item.open .faq-arrow{{transform:rotate(180deg)}}
.faq-item.open .faq-a{{display:block}}

/* tg block */
.tg-block{{background:linear-gradient(135deg,rgba(124,58,237,.1),rgba(79,70,229,.05));
  border:1px solid rgba(124,58,237,.2);border-radius:16px;padding:32px;
  text-align:center;margin-bottom:60px}}
.tg-block h3{{font-size:1.2rem;font-weight:700;margin-bottom:8px}}
.tg-block p{{color:var(--m);font-size:.88rem;margin-bottom:20px}}
.tg-btn{{display:inline-flex;align-items:center;gap:8px;
  background:linear-gradient(135deg,#2AABEE,#229ED9);
  border:none;border-radius:10px;color:#fff;padding:12px 24px;
  font-size:.92rem;font-weight:600;text-decoration:none;transition:opacity .15s}}
.tg-btn:hover{{opacity:.85}}

footer{{border-top:1px solid var(--br);padding:24px 20px;text-align:center;
  color:var(--m);font-size:.78rem}}
@media(max-width:480px){{.si{{padding:16px 20px}}.btn-main,.btn-ghost{{width:100%;text-align:center}}
  .hero-btns{{flex-direction:column;align-items:center}}}}
</style></head>
<body>

<div class="hero">
  <div class="badge"><span class="dot"></span> Сервер работает</div>
  <h1>ShockNet VPN</h1>
  <p class="hero-sub">Быстрый и надёжный VPN без ограничений.<br>Работает на любом WiFi и мобильном интернете.</p>
  <div class="hero-btns">
    <a href="https://t.me/myvpngift_bot" class="btn-main">📱 Получить доступ</a>
    <a href="#how" class="btn-ghost">Как подключиться?</a>
  </div>
</div>

<div style="max-width:560px;margin:0 auto 60px;padding:0 20px">
  <div class="strip">
    <div class="si"><div class="sv">VLESS</div><div class="sl">Протокол</div></div>
    <div class="si"><div class="sv">3 ТБ</div><div class="sl">В месяц</div></div>
    <div class="si"><div class="sv">443</div><div class="sl">Порт</div></div>
  </div>
</div>

<div class="section" id="how">
  <div class="section-title">Как подключиться</div>
  <div class="section-sub">Три шага и ты внутри</div>
  <div class="steps">
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">
        <div class="step-title">Запроси доступ в боте</div>
        <div class="step-desc">Напиши <a href="https://t.me/myvpngift_bot">@myvpngift_bot</a> команду /start и нажми кнопку запроса доступа. Администратор одобрит в течение нескольких минут.</div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">
        <div class="step-title">Открой личную страницу</div>
        <div class="step-desc">После одобрения бот пришлёт ссылку на твою личную страницу с ключами, QR-кодами и инструкциями.</div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        <div class="step-title">Скачай приложение и подключись</div>
        <div class="step-desc">Используй HAPP (Android/iOS) или Koala Clash (Windows/macOS). Отсканируй QR или вставь ссылку подписки — всё настроится автоматически.</div>
      </div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Приложения</div>
  <div class="section-sub">Выбери под своё устройство</div>
  <div class="apps">
    <a href="#" class="app-card">
      <div class="app-icon">🤖</div>
      <div class="app-name">HAPP</div>
      <div class="app-desc">Android</div>
    </a>
    <a href="#" class="app-card">
      <div class="app-icon">🍎</div>
      <div class="app-name">HAPP</div>
      <div class="app-desc">iOS / iPhone</div>
    </a>
    <a href="#" class="app-card">
      <div class="app-icon">🪟</div>
      <div class="app-name">Koala Clash</div>
      <div class="app-desc">Windows</div>
    </a>
    <a href="#" class="app-card">
      <div class="app-icon">🍏</div>
      <div class="app-name">Koala Clash</div>
      <div class="app-desc">macOS</div>
    </a>
  </div>
</div>

<div class="section">
  <div class="section-title">Вопросы и ответы</div>
  <div class="section-sub">Часто спрашивают</div>
  <div class="faq">
    <div class="faq-item">
      <div class="faq-q" onclick="toggle(this)">Не работает на домашнем WiFi <span class="faq-arrow">▾</span></div>
      <div class="faq-a">Некоторые роутеры блокируют VPN трафик. В подписке есть профиль <b>WiFi</b> — он работает через домен и обходит такие блокировки. В HAPP выбери профиль с пометкой "WiFi".</div>
    </div>
    <div class="faq-item">
      <div class="faq-q" onclick="toggle(this)">Не работает на рабочем компьютере <span class="faq-arrow">▾</span></div>
      <div class="faq-a">Корпоративные сети с Squid-прокси блокируют весь внешний трафик — это политика компании и обойти её штатными средствами не получится. Используй мобильный интернет или личный компьютер.</div>
    </div>
    <div class="faq-item">
      <div class="faq-q" onclick="toggle(this)">Как обновить конфигурацию? <span class="faq-arrow">▾</span></div>
      <div class="faq-a">В HAPP и Koala Clash нажми "Обновить подписку". Конфиг подтянется автоматически с актуальными настройками.</div>
    </div>
    <div class="faq-item">
      <div class="faq-q" onclick="toggle(this)">Сколько устройств можно подключить? <span class="faq-arrow">▾</span></div>
      <div class="faq-a">Ограничений по количеству устройств нет. Одна ссылка подписки — все твои устройства.</div>
    </div>
    <div class="faq-item">
      <div class="faq-q" onclick="toggle(this)">Что делать если бот не отвечает? <span class="faq-arrow">▾</span></div>
      <div class="faq-a">Напиши /start ещё раз. Если не помогает — свяжись с администратором напрямую в Telegram.</div>
    </div>
  </div>
</div>

<div class="section">
  <div class="tg-block">
    <h3>Готов подключиться?</h3>
    <p>Запроси доступ через Telegram бот — это займёт меньше минуты</p>
    <a href="https://t.me/myvpngift_bot" class="tg-btn">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.562 8.248l-2.012 9.482c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12L7.48 14.617l-2.95-.924c-.64-.203-.654-.64.136-.948l11.532-4.448c.533-.194 1 .13.826.95h-.001l-.462.001z"/></svg>
      Написать боту
    </a>
  </div>
</div>

<footer>ShockNet VPN · {DOMAIN} · Все права защищены</footer>

<script>
function toggle(el){{
  const item=el.parentElement;
  item.classList.toggle('open');
}}
</script>
</body></html>"""

# ── user personal page ────────────────────────────────────────────────────────
def user_page(user: dict) -> str:
    token = user["token"]
    uid   = user["uuid"]
    email = user["email"]
    label = user["label"]
    sub_url = f"https://{DOMAIN}/sub/{token}"
    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyVPN</title><style>{CSS}</style></head>
<body>
<input type="hidden" id="user-email" value="{email}">
<div class="wrap">
  <div>
    <div class="badge"><span class="dot"></span> Сервер активен</div>
    <h1>MyVPN</h1>
    <p class="sub">Привет, {label}!</p>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-stat">📊</div>
      <div><div class="card-title">Твой трафик</div></div>
    </div>
    <div class="tblock" id="user-stats"><div style="color:var(--m);font-size:.85rem">Загрузка...</div></div>
    <div class="tblock" id="srv-stats" style="border-top:1px solid var(--br)"><div style="color:var(--m);font-size:.85rem">Загрузка...</div></div>
    <div class="refresh-area"><span id="last-upd">—</span><button class="rbtn" onclick="loadStats()">↻ Обновить</button></div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-happ">📱</div>
      <div><div class="card-title">HAPP</div>
        <div><span class="ptag">Android</span><span class="ptag">iOS</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Ссылка подписки</div>
        <div class="crow" id="r-happ">
          <span class="cv">{sub_url}</span>
          <button class="cb" onclick="copy('r-happ','{sub_url}',this)">Копировать</button>
        </div>
      </div>
      <hr class="divider">
      <div>
        <div class="flabel">VLESS+WS ссылка (ручная, WiFi)</div>
        <div class="crow" id="r-vless-happ">
          <span class="cv">{ws_link(uid)}</span>
          <button class="cb" onclick="copy('r-vless-happ',null,this)">Копировать</button>
        </div>
      </div>
      <hr class="divider">
      <div>
        <div class="flabel">QR-код для HAPP</div>
        <div class="qr-wrap">
          <img src="data:image/png;base64,{make_qr_b64(sub_url)}" alt="QR" width="180" height="180">
          <p class="qr-hint">Открой HAPP → Добавить сервер → Сканировать QR</p>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать HAPP</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_HAPP['android']}" target="_blank">🤖 Android</a>
      <a class="dlbtn" href="{DL_HAPP['ios']}" target="_blank">🍎 iOS</a>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-clash">⚡</div>
      <div><div class="card-title">Koala Clash</div>
        <div><span class="ptag">Windows</span><span class="ptag">macOS</span><span class="ptag">Linux</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Ссылка подписки (Clash YAML)</div>
        <div class="crow" id="r-clash">
          <span class="cv">https://{DOMAIN}/sub/clash/{token}</span>
          <button class="cb" onclick="copy('r-clash','https://{DOMAIN}/sub/clash/{token}',this)">Копировать</button>
        </div>
      </div>
      <hr class="divider">
      <div>
        <div class="flabel">VLESS+WS ссылка (ручная, WiFi)</div>
        <div class="crow" id="r-vless-clash">
          <span class="cv">{ws_link(uid)}</span>
          <button class="cb" onclick="copy('r-vless-clash',null,this)">Копировать</button>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать Koala Clash</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_CLASH['win']}" target="_blank">🪟 Windows</a>
      <a class="dlbtn" href="{DL_CLASH['mac']}" target="_blank">🍎 macOS</a>
      <a class="dlbtn" href="{DL_CLASH['linux']}" target="_blank">🐧 Linux</a>
    </div>
  </div>

</div>
<script>{JS}
// Override loadStats for user page — use public endpoint
(function(){{
  const TOKEN="{token}";
  loadStats=function(){{
    fetch('/api/user-stats/'+TOKEN).then(r=>r.json()).then(function(d){{
      const LIMIT=d.limit||3*1024*1024*1024*1024;
      const up=parseInt(d.uplink)||0,dn=parseInt(d.downlink)||0,t=up+dn;
      const tot=parseInt(d.total_server)||0;
      // user block
      const el=document.getElementById('user-stats');
      if(el){{
        const pct=Math.min(100,t/LIMIT*100);
        const col=pct>85?'#f87171':pct>60?'#fb923c':'#34d399';
        el.innerHTML=`<div class="trow"><span class="tlabel">Твой расход</span>
          <span class="tval"><b style="color:var(--t)">${{fmt(t)}}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
          <div class="track"><div class="fill" style="width:${{pct.toFixed(1)}}%;background:${{col}}"></div></div>
          <div class="tmeta"><span>↑ <b style="color:#34d399">${{fmt(up)}}</b> &nbsp; ↓ <b style="color:#60a5fa">${{fmt(dn)}}</b></span>
          <span style="color:var(--m)">${{pct.toFixed(1)}}%</span></div>`;
      }}
      // server block
      const srv=document.getElementById('srv-stats');
      if(srv){{
        const p2=Math.min(100,tot/LIMIT*100);
        const c2=p2>85?'#f87171':p2>60?'#fb923c':'#34d399';
        srv.innerHTML=`<div class="trow"><span class="tlabel">Всего на сервере</span>
          <span class="tval"><b style="color:var(--t)">${{fmt(tot)}}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
          <div class="track"><div class="fill" style="width:${{p2.toFixed(1)}}%;background:${{c2}}"></div></div>
          <div class="tmeta"><span style="color:${{c2}}">${{p2.toFixed(1)}}% использовано</span>
          <span style="color:var(--m)">Осталось: ${{fmt(LIMIT-tot)}}</span></div>`;
      }}
      document.getElementById('last-upd').textContent='Обновлено: '+new Date().toLocaleTimeString('ru-RU');
    }}).catch(()=>{{}});
  }};
  loadStats();setInterval(loadStats,30000);
}})();
</script>
</body></html>"""

# ── admin page ────────────────────────────────────────────────────────────────
def admin_page() -> str:
    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyVPN — Admin</title><style>{CSS}
.logout{{font-size:.75rem;color:var(--m);text-decoration:none;border:1px solid var(--br);
  border-radius:6px;padding:4px 10px;transition:all .15s}}
.logout:hover{{border-color:var(--r);color:var(--r)}}
</style></head>
<body>
<div class="wrap">
  <div style="display:flex;align-items:flex-start;justify-content:space-between">
    <div>
      <div class="badge"><span class="dot"></span> Сервер активен</div>
      <h1>MyVPN Admin</h1>
      <p class="sub">Дмитрий Орлов</p>
    </div>
    <a href="/logout" class="logout">Выйти</a>
  </div>

  <div class="strip">
    <div class="si2"><div class="sl2">IP сервера</div><div class="sv2">{SERVER_IP}</div></div>
    <div class="si2"><div class="sl2">Протокол</div><div class="sv2">VLESS+Reality</div></div>
    <div class="si2"><div class="sl2">Порт</div><div class="sv2">{PORT_VLESS}</div></div>
  </div>

  <!-- Monitoring -->
  <div class="card" id="mon-card">
    <div class="card-head">
      <div class="icon icon-stat">📈</div>
      <div style="flex:1"><div class="card-title">Мониторинг сервера</div>
        <div class="card-sub" id="mon-range">За последний час · каждые 5 сек</div></div>
      <button id="mon-toggle" class="sys-btn sys-btn-off" onclick="toggleMetrics()" style="flex-shrink:0">■ Пауза</button>
    </div>

    <!-- Current values -->
    <div style="display:flex;flex-wrap:wrap;border-bottom:1px solid var(--br)">
      <div class="si2" style="min-width:90px"><div class="sl2">CPU</div><div class="sv2" id="m-cpu">—</div></div>
      <div class="si2" style="min-width:90px"><div class="sl2">RAM</div><div class="sv2" id="m-ram">—</div></div>
      <div class="si2" style="min-width:90px"><div class="sl2">Диск</div><div class="sv2" id="m-disk">—</div></div>
      <div class="si2" style="min-width:110px"><div class="sl2">↓ Входящий</div><div class="sv2" id="m-rx" style="color:#34d399">—</div></div>
      <div class="si2" style="min-width:110px"><div class="sl2">↑ Исходящий</div><div class="sv2" id="m-tx" style="color:#60a5fa">—</div></div>
    </div>

    <!-- Charts -->
    <div style="padding:16px 20px;display:flex;flex-direction:column;gap:20px">
      <div>
        <div class="flabel" style="margin-bottom:8px">CPU % / RAM %</div>
        <canvas id="chart-cpu" height="80"></canvas>
      </div>
      <div>
        <div class="flabel" style="margin-bottom:8px">Сеть (байт/с)</div>
        <canvas id="chart-net" height="80"></canvas>
      </div>
    </div>
    <div class="refresh-area"><span id="mon-upd">—</span></div>
  </div>

  <!-- System controls -->
  <div class="card" id="sys-card">
    <div class="card-head">
      <div class="icon icon-stat">⚙️</div>
      <div><div class="card-title">Управление системой</div>
        <div class="card-sub">Бот и домашний сервер</div></div>
    </div>
    <div class="card-body" style="gap:14px">

      <!-- Bot -->
      <div class="sys-row">
        <div class="sys-info">
          <div class="sys-name">🤖 Telegram Бот</div>
          <div class="sys-status" id="bot-status"><span class="st-dot st-unknown"></span> Загрузка...</div>
        </div>
        <div class="sys-btns">
          <button class="sys-btn sys-btn-on"  id="bot-start" onclick="botAction('start')">▶ Вкл</button>
          <button class="sys-btn sys-btn-off" id="bot-stop"  onclick="botAction('stop')">■ Выкл</button>
        </div>
      </div>

      <hr class="divider">

      <hr class="divider">

    </div>
  </div>

  <!-- VK TURN -->
  <div class="card" id="turn-card">
    <div class="card-head">
      <div class="icon" style="background:linear-gradient(135deg,#0284c7,#0ea5e9)">🔀</div>
      <div><div class="card-title">VK TURN</div>
        <div class="card-sub">Relay для обхода белых списков · WireGuard</div></div>
    </div>
    <div class="card-body" style="gap:14px">
      <div class="sys-row">
        <div class="sys-info">
          <div class="sys-name">🔀 turnproxy</div>
          <div class="sys-status" id="turn-status"><span class="st-dot st-unknown"></span> Загрузка...</div>
        </div>
        <div class="sys-btns">
          <button class="sys-btn sys-btn-on"  id="turn-start" onclick="turnAction('start')">▶ Вкл</button>
          <button class="sys-btn sys-btn-off" id="turn-stop"  onclick="turnAction('stop')">■ Выкл</button>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-stat">📊</div>
      <div><div class="card-title">Трафик пользователей</div>
        <div class="card-sub">3 ТБ в месяц · включая отозванных</div></div>
      <button class="rbtn" style="margin-left:auto" onclick="loadStats()">↻</button>
    </div>
    <div class="tblock" id="srv-stats"><div style="color:var(--m);font-size:.85rem">Загрузка...</div></div>
    <div id="all-users"></div>
    <div class="refresh-area"><span id="last-upd">—</span></div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-clash">⚡</div>
      <div><div class="card-title">Koala Clash</div>
        <div><span class="ptag">Windows</span><span class="ptag">macOS</span><span class="ptag">Linux</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Clash YAML</div>
        <div class="crow" id="r-clash">
          <span class="cv">https://{DOMAIN}/sub/clash/user1</span>
          <button class="cb" onclick="copy('r-clash','https://{DOMAIN}/sub/clash/user1',this)">Копировать</button>
        </div>
      </div>
      <hr class="divider">
      <div>
        <div class="flabel">VLESS+WS ссылка (WiFi)</div>
        <div class="crow" id="r-vless">
          <span class="cv">{ws_link()}</span>
          <button class="cb" onclick="copy('r-vless',null,this)">Копировать</button>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_CLASH['win']}" target="_blank">🪟 Windows</a>
      <a class="dlbtn" href="{DL_CLASH['mac']}" target="_blank">🍎 macOS</a>
      <a class="dlbtn" href="{DL_CLASH['linux']}" target="_blank">🐧 Linux</a>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-happ">📱</div>
      <div><div class="card-title">HAPP</div>
        <div><span class="ptag">Android</span><span class="ptag">iOS</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Ссылка подписки</div>
        <div class="crow" id="r-happ">
          <span class="cv">https://{DOMAIN}/sub/user1</span>
          <button class="cb" onclick="copy('r-happ','https://{DOMAIN}/sub/user1',this)">Копировать</button>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_HAPP['android']}" target="_blank">🤖 Android</a>
      <a class="dlbtn" href="{DL_HAPP['ios']}" target="_blank">🍎 iOS</a>
    </div>
  </div>
</div>
<script>{JS}</script>
<script src="/static/chart.min.js"></script>
<script>
(function(){{
  const C = Chart.defaults;
  C.color = '#64748b';
  C.borderColor = 'rgba(255,255,255,0.05)';

  function fmtBytes(b){{
    if(b<1024) return b+' Б/с';
    if(b<1048576) return (b/1024).toFixed(1)+' КБ/с';
    return (b/1048576).toFixed(2)+' МБ/с';
  }}
  function fmtTime(ts){{
    const d=new Date(ts*1000);
    return d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0')+':'+d.getSeconds().toString().padStart(2,'0');
  }}

  const cpuChart = new Chart(document.getElementById('chart-cpu'),{{
    type:'line',
    data:{{labels:[],datasets:[
      {{label:'CPU %',data:[],borderColor:'#a78bfa',backgroundColor:'rgba(167,139,250,.1)',
        fill:true,tension:.3,pointRadius:0,borderWidth:1.5}},
      {{label:'RAM %',data:[],borderColor:'#60a5fa',backgroundColor:'rgba(96,165,250,.08)',
        fill:true,tension:.3,pointRadius:0,borderWidth:1.5}},
    ]}},
    options:{{animation:false,plugins:{{legend:{{labels:{{boxWidth:12,font:{{size:11}}}}}}}},
      scales:{{x:{{ticks:{{maxTicksLimit:6,font:{{size:10}}}},grid:{{color:'rgba(255,255,255,0.04)'}}}},
               y:{{min:0,max:100,ticks:{{callback:v=>v+'%',font:{{size:10}}}},
                   grid:{{color:'rgba(255,255,255,0.04)'}}}}}}}},
  }});

  const netChart = new Chart(document.getElementById('chart-net'),{{
    type:'line',
    data:{{labels:[],datasets:[
      {{label:'↓ Вход',data:[],borderColor:'#34d399',backgroundColor:'rgba(52,211,153,.08)',
        fill:true,tension:.3,pointRadius:0,borderWidth:1.5}},
      {{label:'↑ Выход',data:[],borderColor:'#60a5fa',backgroundColor:'rgba(96,165,250,.06)',
        fill:true,tension:.3,pointRadius:0,borderWidth:1.5}},
    ]}},
    options:{{animation:false,plugins:{{legend:{{labels:{{boxWidth:12,font:{{size:11}}}}}}}},
      scales:{{x:{{ticks:{{maxTicksLimit:6,font:{{size:10}}}},grid:{{color:'rgba(255,255,255,0.04)'}}}},
               y:{{min:0,ticks:{{callback:fmtBytes,font:{{size:10}}}},
                   grid:{{color:'rgba(255,255,255,0.04)'}}}}}}}},
  }});

  function loadMetrics(){{
    fetch('/api/metrics').then(r=>r.json()).then(d=>{{
      const pts=d.points;
      if(!pts||!pts.length) return;
      const labels=pts.map(p=>fmtTime(p.ts));
      cpuChart.data.labels=labels;
      cpuChart.data.datasets[0].data=pts.map(p=>p.cpu);
      cpuChart.data.datasets[1].data=pts.map(p=>p.ram);
      cpuChart.update('none');
      netChart.data.labels=labels;
      netChart.data.datasets[0].data=pts.map(p=>p.rx);
      netChart.data.datasets[1].data=pts.map(p=>p.tx);
      netChart.update('none');
      // current values
      const last=pts[pts.length-1];
      document.getElementById('m-cpu').textContent=last.cpu+'%';
      document.getElementById('m-ram').textContent=last.ram+'% ('+last.ram_used+'/'+last.ram_total+' МБ)';
      document.getElementById('m-disk').textContent=last.disk+'% ('+last.disk_used+'/'+last.disk_total+' ГБ)';
      document.getElementById('m-rx').textContent=fmtBytes(last.rx);
      document.getElementById('m-tx').textContent=fmtBytes(last.tx);
      // toggle btn
      const btn=document.getElementById('mon-toggle');
      if(d.collecting){{btn.textContent='■ Пауза';btn.className='sys-btn sys-btn-off';}}
      else{{btn.textContent='▶ Запись';btn.className='sys-btn sys-btn-on';}}
      document.getElementById('mon-upd').textContent='Обновлено: '+new Date().toLocaleTimeString('ru-RU')+' · '+pts.length+' точек';
    }}).catch(()=>{{}});
  }}

  function toggleMetrics(){{
    fetch('/api/metrics/toggle',{{method:'POST'}}).then(r=>r.json()).then(loadMetrics);
  }}
  window.toggleMetrics=toggleMetrics;

  if(document.getElementById('mon-card')){{
    loadMetrics();
    setInterval(loadMetrics,5000);
  }}
}})();
</script>
</body></html>"""

# ── HTTP handler ──────────────────────────────────────────────────────────────
def get_system_status() -> dict:
    bot = subprocess.run(["systemctl", "is-active", "vpnbot"],
                         capture_output=True, text=True).stdout.strip()
    turn = subprocess.run(["systemctl", "is-active", "turnproxy"],
                          capture_output=True, text=True).stdout.strip()
    return {"bot": bot == "active", "turn": turn == "active"}

def turn_control(action: str) -> bool:
    cmd = "start" if action == "start" else "stop"
    r = subprocess.run(["systemctl", cmd, "turnproxy"], capture_output=True)
    return r.returncode == 0

def bot_control(action: str) -> bool:
    cmd = "start" if action == "start" else "stop"
    r = subprocess.run(["systemctl", cmd, "vpnbot"], capture_output=True)
    return r.returncode == 0



def is_browser(ua: str) -> bool:
    ua = ua.lower()
    # Known subscription client identifiers — never HTML
    if any(k in ua for k in ("clash", "sing-box", "happ", "hiddify", "v2ray", "xray",
                              "okhttp", "go-http-client", "python-requests", "curl", "wget",
                              "shadowrocket", "streisand", "quantumult", "dalvik")):
        return False
    # Any real browser (desktop or mobile) has Mozilla in UA
    return "mozilla" in ua

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def cookies(self):
        return self.headers.get("Cookie", "")

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def html(self, body: str, status=200):
        b = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def sub_response(self, data: bytes, ul: int, dl: int, token: str = "",
                     content_type: str = "text/plain", filename: str = "myvpn"):
        page_url = f"https://{DOMAIN}/sub/{token}" if token else f"https://{DOMAIN}"
        title_b64 = base64.b64encode(REMARK.encode()).decode()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("subscription-userinfo",
                         f"upload=0; download={ul+dl}; total={TOTAL_LIMIT}")
        self.send_header("profile-title",         f"base64:{title_b64}")
        self.send_header("profile-web-page-url",  page_url)
        self.send_header("profile-update-interval", "24")
        self.send_header("support-url",           page_url)
        self.send_header("update-always",         "true")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        ua   = self.headers.get("User-Agent", "")

        # ── static assets ──
        if path == "/static/chart.min.js":
            try:
                data = open("/opt/subserver/chartjs.min.js", "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_response(404); self.end_headers()
            return

        # ── login page ──
        if path == "/login":
            self.html(LOGIN_HTML.replace("ERRCLASS", "").replace("ERRMSG", ""))
            return

        # ── telegram auth callback ──
        if path == "/tg-auth":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            data = {k: v[0] for k, v in qs.items()}
            db = load_db()
            tg_id = int(data.get("id", 0))
            if verify_telegram_auth(data) and tg_id == db.get("admin_id", 0):
                self.send_response(302)
                self.send_header("Location", "/admin")
                self.send_header("Set-Cookie",
                    f"session={SESSION_TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000")
                self.end_headers()
            else:
                self.html(LOGIN_HTML
                    .replace("ERRCLASS", "show")
                    .replace("ERRMSG", "Доступ запрещён"))
            return

        # ── logout ──
        if path == "/logout":
            self.send_response(302)
            self.send_header("Location", "/admin")
            self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/")
            self.end_headers()
            return

        # ── public user stats (no auth) ──
        if path.startswith("/api/user-stats/"):
            token = path[len("/api/user-stats/"):]
            user  = find_user(token)
            if not user:
                self.send_response(404); self.end_headers(); return
            raw = get_stats()
            all_ul = sum(v.get("uplink", 0)   for v in raw.values())
            all_dl = sum(v.get("downlink", 0) for v in raw.values())
            email = user["email"]
            ul, dl = user_traffic(raw, email)
            resp = json.dumps({
                "uplink":       ul,
                "downlink":     dl,
                "total_server": all_ul + all_dl,
                "limit":        TOTAL_LIMIT,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)
            return

        # ── landing page (public) ──
        if path in ("/", "/index.html"):
            self.html(landing_page())
            return

        # ── admin pages (require auth) ──
        if path in ("/admin", "/admin/") or path.startswith("/api/"):
            if not is_authenticated(self.cookies()):
                self.redirect("/login")
                return

            if path == "/api/metrics":
                resp = json.dumps({
                    "points": list(metrics_buf),
                    "collecting": metrics_on,
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp)
                return

            if path == "/api/system":
                resp = json.dumps(get_system_status()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp)
                return

            if path == "/api/stats":
                raw = get_stats()
                users_out = []
                for u in all_users_for_stats():
                    ul, dl = user_traffic(raw, u["email"])
                    users_out.append({
                        "email":    u["email"],
                        "label":    u["label"],
                        "approved": u.get("approved", True),
                        "trial":    u.get("trial", False),
                        "uplink":   ul,
                        "downlink": dl,
                    })
                resp = json.dumps({"users": users_out}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp)
                return

            self.html(admin_page())
            return

        # ── clash sub ──
        if path.startswith("/sub/clash/"):
            token = path[len("/sub/clash/"):]
            user  = find_user(token)
            if not user:
                self.send_response(404); self.end_headers(); return
            email = user.get("email", "myvpn")
            stats = get_stats()
            ul, dl = user_traffic(stats, email)
            data = clash_yaml(user["uuid"]).encode()
            self.sub_response(data, ul, dl,
                              token, content_type="text/yaml", filename=email)
            return

        # ── user sub / personal page ──
        if path.startswith("/sub/"):
            token = path[len("/sub/"):]
            user  = find_user(token)
            if not user:
                self.html("<h2 style='font-family:sans-serif;color:#f87171;padding:40px'>Ссылка недействительна или доступ отозван.</h2>", 404)
                return
            email = user.get("email", "myvpn")
            if is_browser(ua):
                self.html(user_page(user))
            else:
                stats = get_stats()
                ul, dl = user_traffic(stats, email)
                data = v2ray_sub(user["uuid"]).encode()
                self.sub_response(data, ul, dl, token, filename=email)
            return

        self.send_response(404); self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        if self.path.startswith("/api/") and not is_authenticated(self.cookies()):
            self.send_response(401); self.end_headers(); return

        if self.path == "/api/bot/start":
            ok = bot_control("start")
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode()); return

        if self.path == "/api/bot/stop":
            ok = bot_control("stop")
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode()); return

        if self.path == "/api/metrics/toggle":
            global metrics_on
            metrics_on = not metrics_on
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"collecting": metrics_on}).encode()); return

        if self.path == "/api/turn/start":
            ok = turn_control("start")
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode()); return

        if self.path == "/api/turn/stop":
            ok = turn_control("stop")
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode()); return

        self.send_response(405); self.end_headers()


if __name__ == "__main__":
    _autosave_stats()
    _start_metrics()
    server = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler)
    print(f"Running on :{WEB_PORT}")
    server.serve_forever()
