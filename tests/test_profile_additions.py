"""Regression tests for additive Microsoft Reality test profiles."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("shocknet_add_profiles", ROOT / "scripts/add_microsoft_test_profiles.py")
profiles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profiles)


def source_config(private_key="test-private-key"):
    def inbound(tag, port, sni, flow):
        client = {"id": "01234567-89ab-4cde-8fab-0123456789ab", "email": "test_user"}
        if flow:
            client["flow"] = flow
        return {
            "tag": tag, "listen": "0.0.0.0", "port": port,
            "protocol": "vless", "settings": {"clients": [client], "decryption": "none"},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {"dest": sni + ":443", "serverNames": [sni],
                                    "privateKey": private_key, "shortIds": ["deadbeefcafe1234"]},
            },
        }
    return {"log": {"loglevel": "warning"}, "inbounds": [
        inbound("vless-google-4443", 4443, "www.google.com", "xtls-rprx-vision"),
        inbound("vless-cloudflare-2053", 2053, "www.cloudflare.com", None),
    ], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}


class AddProfilesTests(unittest.TestCase):
    def test_additive_and_idempotent(self):
        original = source_config()
        before = copy.deepcopy(original)
        candidate, added = profiles.prepare_config(original)
        self.assertEqual(added, [8450, 8451])
        self.assertEqual(original, before)
        self.assertEqual(len(candidate["inbounds"]), 4)
        self.assertEqual(candidate["inbounds"][:2], original["inbounds"])
        self.assertEqual(candidate["outbounds"], original["outbounds"])
        a, b = candidate["inbounds"][2:]
        self.assertEqual((a["tag"], a["port"]), ("vless-microsoft-8450", 8450))
        self.assertEqual((b["tag"], b["port"]), ("vless-microsoft-mobile-8451", 8451))
        self.assertEqual(a["streamSettings"]["realitySettings"]["dest"], "www.microsoft.com:443")
        self.assertEqual(b["streamSettings"]["realitySettings"]["serverNames"],
                         ["www.microsoft.com", "microsoft.com"])
        self.assertEqual(a["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        self.assertNotIn("flow", b["settings"]["clients"][0])
        self.assertEqual(a["settings"]["clients"][0]["id"], original["inbounds"][0]["settings"]["clients"][0]["id"])
        again, added_again = profiles.prepare_config(candidate)
        self.assertEqual(added_again, [])
        self.assertEqual(again, candidate)

    def test_conflicts_are_rejected_without_mutation(self):
        original = source_config()
        original["inbounds"].append({"tag": "some-other-service", "port": 8450})
        before = copy.deepcopy(original)
        with self.assertRaisesRegex(ValueError, "collision"):
            profiles.prepare_config(original)
        self.assertEqual(original, before)

    def test_missing_reality_credentials_rejected(self):
        original = source_config()
        del original["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
        with self.assertRaisesRegex(ValueError, "Missing Reality credentials"):
            profiles.prepare_config(original)

    def test_dry_run_does_not_write_or_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            original = json.dumps(source_config())
            path.write_text(original)
            checked = []
            added, backup = profiles.install(path, Path("/not-needed/xray"), Path(tmp) / "backups",
                                             apply=False, check_ports=lambda ports: checked.append(ports),
                                             validate=lambda config, binary: checked.append("validated"),
                                             restart=lambda service, ports: self.fail("must not restart"))
            self.assertEqual(added, [8450, 8451])
            self.assertIsNone(backup)
            self.assertEqual(checked, [[8450, 8451], "validated"])
            self.assertEqual(path.read_text(), original)

    def test_apply_creates_backup_and_rollback_on_restart_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            original = json.dumps(source_config())
            path.write_text(original)
            restarts = []
            def fail_first(service, ports):
                restarts.append(ports)
                if len(restarts) == 1:
                    raise RuntimeError("simulated restart failure")
            with patch.object(profiles.subprocess, "run"):
                with self.assertRaises(RuntimeError):
                    profiles.install(path, Path("/not-needed/xray"), Path(tmp) / "backups",
                                     apply=True, check_ports=lambda _: None,
                                     validate=lambda *_: None, restart=fail_first)
            self.assertEqual(path.read_text(), original)
            self.assertEqual(restarts, [[8450, 8451], []])
            self.assertEqual(len(list((Path(tmp) / "backups").glob("*.json"))), 1)

    def test_real_xray_accepts_new_profiles(self):
        binary = os.getenv("XRAY_TEST_BINARY")
        if not binary:
            self.skipTest("XRAY_TEST_BINARY not set")
        keys = subprocess.run([binary, "x25519"], capture_output=True, text=True, check=True).stdout
        private_key = re.search(r"Private key:\s*(\S+)", keys).group(1)
        candidate, _ = profiles.prepare_config(source_config(private_key))
        profiles.validate_with_xray(candidate, Path(binary))


if __name__ == "__main__":
    unittest.main()
