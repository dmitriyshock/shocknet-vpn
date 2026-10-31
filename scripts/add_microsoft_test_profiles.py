#!/usr/bin/env python3
"""Safely add extra Reality test inbounds without replacing active VPN profiles.

This is an explicit, opt-in migration for an existing Shocknet VPS. It preserves
all existing inbounds, users, private keys and outbounds; only the new inbounds
are appended. No tokens or private keys are printed.
"""

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile


DEFAULT_CONFIG = Path("/opt/xray/config.json")
DEFAULT_BINARY = Path("/opt/xray/xray")
DEFAULT_BACKUPS = Path("/opt/xray/backups")

PROFILES = (
    {"source_port": 4443, "port": 8450, "tag": "vless-microsoft-8450",
     "flow": "xtls-rprx-vision"},
    {"source_port": 2053, "port": 8451, "tag": "vless-microsoft-mobile-8451",
     "flow": None},
)


def prepare_config(original: dict) -> tuple[dict, list[int]]:
    """Return an additive config and the newly allocated ports, or raise."""
    result = copy.deepcopy(original)
    inbounds = result.get("inbounds")
    if not isinstance(inbounds, list):
        raise ValueError("Xray config must contain an inbounds array")
    added = []
    for spec in PROFILES:
        matching = [i for i in inbounds if i.get("port") == spec["port"] or i.get("tag") == spec["tag"]]
        if matching:
            if (len(matching) == 1 and matching[0].get("port") == spec["port"]
                    and matching[0].get("tag") == spec["tag"]
                    and (matching[0].get("streamSettings") or {}).get("realitySettings", {}).get("dest")
                    == "www.microsoft.com:443"):
                continue  # Already installed, keep its live client list untouched.
            raise ValueError(f"Port or tag collision: {spec['port']} / {spec['tag']}")

        sources = [i for i in inbounds if i.get("port") == spec["source_port"]
                   and i.get("protocol") == "vless"
                   and (i.get("streamSettings") or {}).get("security") == "reality"]
        if len(sources) != 1:
            raise ValueError(f"Expected one Reality source inbound on port {spec['source_port']}")
        source = sources[0]
        reality = (source.get("streamSettings") or {}).get("realitySettings") or {}
        if not reality.get("privateKey") or not reality.get("shortIds"):
            raise ValueError(f"Missing Reality credentials in source port {spec['source_port']}")

        new = copy.deepcopy(source)
        new.update(tag=spec["tag"], port=spec["port"], listen="0.0.0.0")
        new["streamSettings"]["realitySettings"].update({
            "dest": "www.microsoft.com:443",
            "serverNames": ["www.microsoft.com", "microsoft.com"],
        })
        for client in new["settings"].get("clients", []):
            if spec["flow"]:
                client["flow"] = spec["flow"]
            else:
                client.pop("flow", None)
        inbounds.append(new)
        added.append(spec["port"])
    return result, added


def assert_ports_available(ports: list[int]):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("0.0.0.0", port))
            except OSError as exc:
                raise RuntimeError(f"Port {port} is already in use: {exc}") from exc


def validate_with_xray(config: dict, binary: Path):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
            tmp_path = Path(f.name)
            os.fchmod(f.fileno(), 0o600)
            json.dump(config, f)
        checked = subprocess.run([str(binary), "run", "-test", "-config", str(tmp_path)],
                                 capture_output=True, text=True, timeout=15)
        if checked.returncode:
            raise RuntimeError("Xray rejected the proposed configuration: " + checked.stderr[-1200:])
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def write_atomic(path: Path, content: bytes):
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=".shocknet-", delete=False) as f:
            temp_name = f.name
            os.fchmod(f.fileno(), 0o600)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def restart_and_check(service: str, ports: list[int]):
    subprocess.run(["systemctl", "restart", service], check=True, timeout=20)
    subprocess.run(["systemctl", "is-active", "--quiet", service], check=True, timeout=5)
    for port in ports:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass


def install(config_path: Path, binary: Path, backups: Path, apply: bool,
            check_ports=assert_ports_available, validate=validate_with_xray,
            restart=restart_and_check) -> tuple[list[int], Path | None]:
    config_path = Path(config_path)
    binary = Path(binary)
    original_bytes = config_path.read_bytes()
    original = json.loads(original_bytes)
    candidate, added = prepare_config(original)
    if not added:
        return [], None
    check_ports(added)
    validate(candidate, binary)
    if not apply:
        return added, None

    subprocess.run(["systemctl", "is-active", "--quiet", "xray"], check=True, timeout=5)
    backups = Path(backups)
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    backups.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("before-microsoft-%Y%m%dT%H%M%SZ")
    backup_path = backups / f"{stamp}-{os.getpid()}.json"
    shutil.copy2(config_path, backup_path)
    backup_path.chmod(0o600)
    try:
        write_atomic(config_path, (json.dumps(candidate, indent=2, ensure_ascii=False) + "\n").encode())
        restart("xray", added)
    except Exception:
        write_atomic(config_path, original_bytes)
        try:
            restart("xray", [])
        except Exception:
            pass
        raise
    return added, backup_path


def main():
    parser = argparse.ArgumentParser(description="Add Microsoft Reality test profiles on ports 8450 and 8451")
    parser.add_argument("--apply", action="store_true", help="Back up config, add profiles, restart and verify Xray")
    args = parser.parse_args()
    if args.apply and os.geteuid() != 0:
        parser.error("Run as root to apply changes")
    ports, backup = install(DEFAULT_CONFIG, DEFAULT_BINARY, DEFAULT_BACKUPS, apply=args.apply)
    if not ports:
        print("Profiles already exist. No changes made.")
    elif not args.apply:
        print(f"Dry run passed. Would add Microsoft Reality profiles on TCP ports: {ports}.")
        print("Run this script with --apply after reviewing the plan.")
    else:
        print(f"Added profiles on TCP ports {ports}; Xray restarted and local listeners verified.")
        print(f"Backup: {backup}")
        print("If external clients cannot connect, check the VPS provider firewall for these TCP ports.")


if __name__ == "__main__":
    main()
