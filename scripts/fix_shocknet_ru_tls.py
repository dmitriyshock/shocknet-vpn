#!/usr/bin/env python3
"""Isolate shocknet.ru TLS on a local Nginx backend without touching Xray.

The live setup uses Nginx stream SSL preread on public TCP/443, with
shocknet.online and shocknet.ru sharing a PROXY-protocol TLS backend on 9443.
On affected hosts the stream hop selects the .online certificate for .ru even
though both SNI names work when sent directly to 9443. This opt-in repair gives
shocknet.ru a dedicated backend on 127.0.0.1:9444.
"""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time


SITE_FILE = Path("/etc/nginx/sites-enabled/shocknet.ru")
STREAM_FILE = Path("/etc/nginx/streams-enabled/shocknet-vpn.conf")
BACKUP_DIR = Path("/etc/nginx/shocknet-backups")

LISTEN_OLD = re.compile(r"(?m)^([ \t]*listen[ \t]+127\.0\.0\.1:)9443([ \t]+ssl[ \t]+proxy_protocol[ \t]*;[ \t]*)$")
LISTEN_NEW = re.compile(r"(?m)^[ \t]*listen[ \t]+127\.0\.0\.1:9444[ \t]+ssl[ \t]+proxy_protocol[ \t]*;[ \t]*$")
MAP_DEFAULT = re.compile(r"(?m)^([ \t]*)default([ \t]+)127\.0\.0\.1:9443[ \t]*;[ \t]*$")
MAP_RU = re.compile(r"(?m)^[ \t]*shocknet\.ru[ \t]+127\.0\.0\.1:9444[ \t]*;[ \t]*$")


def prepare(site: str, stream: str) -> tuple[str, str, bool]:
    """Build an additive routing change, or reject unexpected topology."""
    if "map $ssl_preread_server_name $shocknet_tls_backend" not in stream:
        raise ValueError("The expected stream SNI map is absent")
    if len(LISTEN_NEW.findall(site)) == 1 and len(MAP_RU.findall(stream)) == 1:
        if LISTEN_OLD.search(site):
            raise ValueError("Both old and new shocknet.ru listeners are present")
        return site, stream, False
    if LISTEN_NEW.search(site) or MAP_RU.search(stream):
        raise ValueError("Partial 9444 migration detected; inspect both files manually")
    if len(LISTEN_OLD.findall(site)) != 1 or len(MAP_DEFAULT.findall(stream)) != 1:
        raise ValueError("Unexpected Nginx topology; no changes made")
    if "server_name shocknet.ru;" not in site:
        raise ValueError("Unexpected shocknet.ru server block")

    new_site = LISTEN_OLD.sub(lambda m: m.group(1) + "9444" + m.group(2), site)
    new_stream = MAP_DEFAULT.sub(
        lambda m: m.group(1) + "shocknet.ru" + m.group(2) + "127.0.0.1:9444;\n" + m.group(0),
        stream,
    )
    return new_site, new_stream, True


def check_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 9444))


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr[-1200:]}")
    return result.stdout


def verify_https():
    for domain in ("shocknet.online", "shocknet.ru"):
        # HTTPS verification is enabled. Connect locally but preserve URL/SNI.
        result = subprocess.run(
            ["curl", "--noproxy", "*", "--silent", "--show-error", "--output", "/dev/null",
             "--write-out", "%{http_code} %{ssl_verify_result}", "--max-time", "10",
             "--resolve", f"{domain}:443:127.0.0.1", f"https://{domain}/"],
            text=True, capture_output=True, timeout=15,
        )
        if result.returncode != 0 or not result.stdout.endswith(" 0"):
            raise RuntimeError(f"HTTPS verification failed for {domain}: {result.stderr[-350:]}")
        print(f"{domain}: HTTPS OK (HTTP {result.stdout.split()[0]})")


def replace_atomic(path: Path, data: bytes):
    original_stat = path.stat()
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=".shocknet-tls-", delete=False) as f:
            temp_name = f.name
            os.fchmod(f.fileno(), stat.S_IMODE(original_stat.st_mode))
            if os.geteuid() == 0:
                os.fchown(f.fileno(), original_stat.st_uid, original_stat.st_gid)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def install(apply: bool):
    # Resolve symlinks so sites-enabled symlinks remain intact.
    site_path, stream_path = SITE_FILE.resolve(strict=True), STREAM_FILE.resolve(strict=True)
    site_original, stream_original = site_path.read_bytes(), stream_path.read_bytes()
    site, stream = site_original.decode(), stream_original.decode()
    candidate_site, candidate_stream, needed = prepare(site, stream)
    if not needed:
        print("Dedicated shocknet.ru TLS backend already configured. No changes made.")
        return

    check_port()
    run("nginx", "-t")
    if not apply:
        print("Dry run passed. Would route shocknet.ru via 127.0.0.1:9444.")
        return
    run("systemctl", "is-active", "--quiet", "nginx")

    backup_dir = BACKUP_DIR / (datetime.now(timezone.utc).strftime("before-ru-tls-%Y%m%dT%H%M%SZ") + f"-{os.getpid()}")
    backup_dir.mkdir(parents=True, mode=0o700)
    shutil.copy2(site_path, backup_dir / "shocknet.ru")
    shutil.copy2(stream_path, backup_dir / "shocknet-vpn.conf")
    (backup_dir / "shocknet.ru").chmod(0o600)
    (backup_dir / "shocknet-vpn.conf").chmod(0o600)

    try:
        replace_atomic(site_path, candidate_site.encode())
        replace_atomic(stream_path, candidate_stream.encode())
        run("nginx", "-t")
        run("systemctl", "reload", "nginx")
        # reload completes before all workers necessarily accept connections.
        last_error = None
        for attempt in range(4):
            try:
                verify_https()
                last_error = None
                break
            except RuntimeError as exc:
                last_error = exc
                if attempt < 3:
                    time.sleep(1)
        if last_error:
            raise last_error
    except Exception:
        replace_atomic(site_path, site_original)
        replace_atomic(stream_path, stream_original)
        try:
            run("nginx", "-t")
            run("systemctl", "reload", "nginx")
        except Exception as rollback_error:
            print(f"WARNING: rollback reload failed: {rollback_error}")
        print(f"Restored original Nginx files. Backups remain in {backup_dir}")
        raise

    print(f"Repair complete. Backup: {backup_dir}")


def main():
    parser = argparse.ArgumentParser(description="Repair shocknet.ru TLS routing via dedicated port 9444")
    parser.add_argument("--apply", action="store_true", help="Back up configs, change routing, reload and verify Nginx")
    args = parser.parse_args()
    if args.apply and os.geteuid() != 0:
        parser.error("Run as root to apply")
    install(args.apply)


if __name__ == "__main__":
    main()
