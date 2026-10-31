#!/usr/bin/env python3
"""Explicit, backed-up rotation of a legacy static administrator VPN profile.

This changes the admin subscription token AND the Xray UUID. Existing admin
clients must re-import the new subscription; other clients are left untouched.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import uuid

ENV = Path("/opt/vpnserver/.env")
CONFIGS = (Path("/opt/xray/config.json"), Path("/opt/xray2/config.json"))
BACKUPS = Path("/opt/vpnserver/backups")


def replace_env_key(content: str, key: str, value: str) -> str:
    lines = content.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.startswith(key + "=")]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {key} entry in .env")
    lines[matches[0]] = key + "=" + value + "\n"
    return "".join(lines)


def replace_uuid(config: dict, old_uuid: str, new_uuid: str) -> int:
    count = 0
    for inbound in config.get("inbounds", []):
        if inbound.get("protocol") != "vless":
            continue
        for client in inbound.get("settings", {}).get("clients", []):
            if client.get("id") == old_uuid:
                client["id"] = new_uuid
                count += 1
    return count


def atomic_replace(path: Path, content: str):
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".rotation-", delete=False) as f:
            temp_name = f.name
            os.fchmod(f.fileno(), 0o600)
            f.write(content)
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def rotate_admin(env_path=ENV, config_paths=CONFIGS, backup_root=BACKUPS,
                 restart=None):
    """Validate everything before writing, back up and roll back on failures."""
    env_path = Path(env_path)
    config_paths = tuple(map(Path, config_paths))
    original_env = env_path.read_text(encoding="utf-8")
    values = dict(line.split("=", 1) for line in original_env.splitlines()
                  if "=" in line and not line.lstrip().startswith("#"))
    old_uuid = values.get("STATIC_UUID", "")
    if not old_uuid or not values.get("STATIC_TOKEN"):
        raise ValueError("STATIC_UUID or STATIC_TOKEN missing")
    uuid.UUID(old_uuid)

    new_token = secrets.token_hex(24)
    new_uuid = str(uuid.uuid4())
    new_env = replace_env_key(original_env, "STATIC_UUID", new_uuid)
    new_env = replace_env_key(new_env, "STATIC_TOKEN", new_token)
    originals = {env_path: original_env}
    updated = {env_path: new_env}
    for path in config_paths:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        if replace_uuid(data, old_uuid, new_uuid) == 0:
            raise ValueError(f"Old administrator UUID not found in {path}")
        originals[path] = content
        updated[path] = json.dumps(data, ensure_ascii=False, indent=2) + "\n"

    backup_root = Path(backup_root)
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_dir = backup_root / (datetime.now(timezone.utc).strftime("admin-%Y%m%dT%H%M%SZ-") + secrets.token_hex(4))
    backup_dir.mkdir(mode=0o700)
    for index, path in enumerate(updated):
        shutil.copy2(path, backup_dir / f"{index}-{path.name}")

    def do_restart():
        if restart:
            restart()

    try:
        for path, content in updated.items():
            atomic_replace(path, content)
        do_restart()
    except Exception:
        for path, content in originals.items():
            atomic_replace(path, content)
        do_restart()
        raise
    return new_token, new_uuid, backup_dir


def restart_xray():
    for service in ("xray", "xray2", "vpnbot", "subserver"):
        subprocess.run(["systemctl", "restart", service], check=True)


def main():
    parser = argparse.ArgumentParser(description="Back up and rotate the administrator VPN credentials")
    parser.add_argument("--apply", action="store_true", help="Actually rotate, restart and invalidate old admin credentials")
    args = parser.parse_args()
    if not args.apply:
        print("No changes made. Run with --apply on the VPS to rotate the administrator UUID and subscription token.")
        return
    if os.geteuid() != 0:
        parser.error("Run as root")
    token, _, backup = rotate_admin(restart=restart_xray)
    from dotenv import dotenv_values
    domain = dotenv_values(ENV).get("DOMAIN", "YOUR_DOMAIN")
    print(f"Rotation successful. New admin subscription: https://{domain}/sub/{token}")
    print(f"Backup: {backup}. Existing admin clients must re-import this subscription.")


if __name__ == "__main__":
    main()
