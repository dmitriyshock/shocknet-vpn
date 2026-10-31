#!/usr/bin/env python3
import re
import os
import sys
import json
import time
import sqlite3
import hashlib
import signal
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen, Request
from urllib.error import URLError

NGINX_LOGS = [
    "/var/log/nginx/access.log",
    "/var/log/nginx/access.log.1",
]
VISITOR_LOG_DIR = Path("/var/log/visitors")
DB_PATH = Path("/opt/log-monitor/geo_cache.db")
STATE_FILE = Path("/opt/log-monitor/.state")
GEOIP_HTTPS_ENDPOINT = os.getenv("GEOIP_HTTPS_ENDPOINT", "")
MOSCOW_TZ = timezone(timedelta(hours=3))

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<page>\S+) [^"]*" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)

BOT_PATTERNS = [
    'zgrab', 'python-requests', 'Go-http-client', 'AHC/', 'libredtail',
    'HeadlessChrome', 'Applebot', 'Googlebot', 'Bingbot', 'YandexBot',
    'SemrushBot', 'AhrefsBot', 'MJ12bot', 'DotBot', 'PetalBot',
]

BOT_IPS = {'204.76.203.18'}

LOCAL_IPS = {'127.0.0.1', '::1'}


def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS geo (
            ip TEXT PRIMARY KEY,
            country TEXT,
            region TEXT,
            city TEXT,
            lat REAL,
            lon REAL,
            isp TEXT,
            updated_at INTEGER
        )
    """)
    conn.commit()
    return conn


def get_geo(conn, ip):
    if ip in BOT_IPS or ip in LOCAL_IPS:
        return None
    row = conn.execute("SELECT country, region, city, lat, lon, isp, updated_at FROM geo WHERE ip=?", (ip,)).fetchone()
    now = int(time.time())
    if row and (now - row[6]) < 604800:
        return {"country": row[0], "region": row[1], "city": row[2], "lat": row[3], "lon": row[4], "isp": row[5]}
    # External geolocation transmits visitor IPs; opt-in and HTTPS only.
    if not GEOIP_HTTPS_ENDPOINT.startswith("https://"):
        return {"country": row[0], "region": row[1], "city": row[2], "lat": row[3], "lon": row[4], "isp": row[5]} if row else None
    try:
        api_url = GEOIP_HTTPS_ENDPOINT.replace("{ip}", quote(ip, safe=""))
        req = Request(api_url, headers={"User-Agent": "log-monitor/1.0"})
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            geo = {"country": data.get("country", ""), "region": data.get("regionName", ""), "city": data.get("city", ""), "lat": data.get("lat", 0), "lon": data.get("lon", 0), "isp": data.get("isp", "")}
            conn.execute("INSERT OR REPLACE INTO geo VALUES(?,?,?,?,?,?,?,?)", (ip, geo["country"], geo["region"], geo["city"], geo["lat"], geo["lon"], geo["isp"], now))
            conn.commit()
            return geo
    except Exception:
        pass
    if row:
        return {"country": row[0], "region": row[1], "city": row[2], "lat": row[3], "lon": row[4], "isp": row[5]}
    return None


def parse_ua(ua_string):
    if not ua_string or ua_string == "-":
        return {"browser": "Unknown", "os": "Unknown", "device": "Unknown"}
    device = "Desktop"
    os_name = "Unknown"
    browser = "Unknown"

    if "iPhone" in ua_string:
        device = "iPhone"
    elif "iPad" in ua_string:
        device = "iPad"
    elif "Android" in ua_string:
        device = "Android"
    elif "Linux" in ua_string:
        device = "Linux"
    elif "Macintosh" in ua_string or "Mac OS X" in ua_string:
        device = "Mac"
    elif "Windows" in ua_string:
        device = "Windows"

    if "SamsungBrowser" in ua_string:
        browser = "SamsungBrowser"
    elif "Edg/" in ua_string:
        browser = "Edge"
    elif "Chrome/" in ua_string and "Safari/" in ua_string:
        browser = "Chrome"
    elif "Firefox/" in ua_string:
        browser = "Firefox"
    elif "Safari/" in ua_string:
        browser = "Safari"
    elif "Opera" in ua_string or "OPR/" in ua_string:
        browser = "Opera"

    if "Android" in ua_string:
        os_name = "Android"
    elif "iPhone" in ua_string or "iPad" in ua_string:
        m = re.search(r'OS (\d+[._]\d+)', ua_string)
        os_name = f"iOS {m.group(1).replace('_', '.')}" if m else "iOS"
    elif "Windows NT 10" in ua_string:
        os_name = "Windows 10"
    elif "Windows NT 6.1" in ua_string:
        os_name = "Windows 7"
    elif "Windows" in ua_string:
        os_name = "Windows"
    elif "Mac OS X" in ua_string:
        m = re.search(r'Mac OS X (\d+[._]\d+[._]?\d*)', ua_string)
        os_name = f"macOS {m.group(1).replace('_', '.')}" if m else "macOS"
    elif "Linux" in ua_string:
        os_name = "Linux"
    elif "CrOS" in ua_string:
        os_name = "ChromeOS"

    return {"browser": browser, "os": os_name, "device": device}


def parse_time(time_str):
    try:
        dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(MOSCOW_TZ)
    except Exception:
        return None


def is_bot(ua_string, ip):
    if ip in BOT_IPS:
        return True
    for pattern in BOT_PATTERNS:
        if pattern in ua_string:
            return True
    return False

def sanitize_path(page):
    """Never persist subscription bearer tokens or URL query credentials."""
    page = page.split("?", 1)[0]
    for prefix in ("/sub/clash/", "/sub/", "/api/user-stats/"):
        if page.startswith(prefix):
            return prefix + "[redacted]"
    return page

def sanitize_referrer(referrer):
    if "/sub/" in referrer or "/api/user-stats/" in referrer:
        return "[redacted]"
    return referrer.split("?", 1)[0]


def get_log_path(dt):
    return VISITOR_LOG_DIR / f"{dt.strftime('%Y-%m-%d')}.log"


def tail_file(filepath, start_pos=0):
    try:
        with open(filepath, 'r') as f:
            f.seek(0, 2)
            size = f.tell()
            if start_pos > size:
                start_pos = 0
            f.seek(start_pos)
            while True:
                line = f.readline()
                if line:
                    yield line, f.tell()
                else:
                    break
    except FileNotFoundError:
        pass


def read_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def write_state(state):
    STATE_FILE.write_text(json.dumps(state))


def write_visitor_log(entry):
    path = get_log_path(entry["datetime"])
    is_append = path.exists()
    with open(path, "a") as f:
        if not is_append:
            f.write("=" * 80 + "\n")
            f.write(f"  VISITOR LOG - {entry['datetime'].strftime('%d.%m.%Y')}\n")
            f.write("=" * 80 + "\n\n")

        f.write(f"[{entry['datetime'].strftime('%H:%M:%S')}] ")
        f.write(f"IP: {entry['ip']}")
        if entry.get("geo"):
            g = entry["geo"]
            loc = ", ".join(filter(None, [g.get("city"), g.get("region"), g.get("country")]))
            if loc:
                f.write(f"  |  Location: {loc}")
            if g.get("isp"):
                f.write(f"  |  ISP: {g['isp']}")
        f.write("\n")
        f.write(f"    Page: {entry['page']}  |  Status: {entry['status']}  |  Method: {entry['method']}\n")
        f.write(f"    Device: {entry['device_info']['device']}  |  OS: {entry['device_info']['os']}  |  Browser: {entry['device_info']['browser']}\n")
        if entry.get("referrer") and entry["referrer"] != "-":
            f.write(f"    Referrer: {entry['referrer']}\n")
        f.write(f"    User-Agent: {entry['ua']}\n")
        f.write("\n")


def write_stats(entry):
    stats_path = VISITOR_LOG_DIR / "stats.json"
    stats = {}
    if stats_path.exists():
        try:
            stats = json.loads(stats_path.read_text())
        except Exception:
            pass

    today = entry["datetime"].strftime("%Y-%m-%d")
    ip = entry["ip"]

    if "daily" not in stats:
        stats["daily"] = {}
    if today not in stats["daily"]:
        stats["daily"][today] = {"total": 0, "unique_ips": [], "pages": {}}

    day = stats["daily"][today]
    day["total"] += 1
    if ip not in day["unique_ips"]:
        day["unique_ips"].append(ip)

    page = entry["page"]
    if page not in day["pages"]:
        day["pages"][page] = 0
    day["pages"][page] += 1

    if "last_updated" not in stats:
        stats["last_updated"] = {}
    stats["last_updated"][ip] = {
        "time": entry["datetime"].strftime("%Y-%m-%d %H:%M:%S"),
        "page": page,
        "device": entry["device_info"]["device"],
        "browser": entry["device_info"]["browser"],
        "city": entry.get("geo", {}).get("city", ""),
        "country": entry.get("geo", {}).get("country", ""),
    }

    for d in list(stats["daily"].keys()):
        if len(stats["daily"]) > 90:
            del stats["daily"][d]
        else:
            break

    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2))


def process_line(line, geo_conn, state):
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return

    ip = m.group("ip")
    if ip in LOCAL_IPS:
        return

    ua_string = m.group("ua")
    dt = parse_time(m.group("time"))
    if not dt:
        return

    if is_bot(ua_string, ip):
        return

    page = m.group("page")
    if page.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.svg', '.ttf', '.eot')):
        return

    geo = get_geo(geo_conn, ip)
    device_info = parse_ua(ua_string)

    entry = {
        "ip": ip,
        "datetime": dt,
        "method": m.group("method"),
        "page": sanitize_path(page),
        "status": m.group("status"),
        "size": m.group("size"),
        "referrer": sanitize_referrer(m.group("referrer")),
        "ua": ua_string,
        "device_info": device_info,
        "geo": geo,
    }

    write_visitor_log(entry)
    write_stats(entry)


def monitor():
    VISITOR_LOG_DIR.mkdir(parents=True, exist_ok=True)
    geo_conn = init_db()
    state = read_state()

    running = True
    def handle_signal(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    print("[log-monitor] Starting visitor monitor...", flush=True)

    for log_file in NGINX_LOGS:
        if log_file in state:
            print(f"[log-monitor] Resuming {log_file} from pos {state[log_file]}", flush=True)
        else:
            try:
                with open(log_file, 'r') as f:
                    f.seek(0, 2)
                    state[log_file] = f.tell()
                print(f"[log-monitor] Tailing {log_file} from end", flush=True)
            except FileNotFoundError:
                state[log_file] = 0

    write_state(state)

    while running:
        for log_file in NGINX_LOGS:
            if not os.path.exists(log_file):
                continue
            pos = state.get(log_file, 0)
            try:
                with open(log_file, 'r') as f:
                    f.seek(0, 2)
                    size = f.tell()
                    if pos > size:
                        pos = 0
                    f.seek(pos)
                    while True:
                        line = f.readline()
                        if line:
                            process_line(line, geo_conn, state)
                            pos = f.tell()
                        else:
                            break
                state[log_file] = pos
            except Exception as e:
                print(f"[log-monitor] Error reading {log_file}: {e}", flush=True)
            write_state(state)
        time.sleep(2)

    geo_conn.close()
    print("[log-monitor] Stopped.", flush=True)


if __name__ == "__main__":
    monitor()
