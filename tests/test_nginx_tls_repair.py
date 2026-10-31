"""Guard rails for opt-in shocknet.ru TLS repair on a shared Nginx server."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("shocknet_tls_repair", ROOT / "scripts/fix_shocknet_ru_tls.py")
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


SITE = """server {
    listen 80;
    server_name shocknet.ru;
}
server {
    listen 127.0.0.1:9443 ssl proxy_protocol;
    server_name shocknet.ru;
    ssl_certificate /etc/letsencrypt/live/shocknet.ru/fullchain.pem;
}
"""
STREAM = """map $ssl_preread_server_name $shocknet_tls_backend {
    ok.ru        127.0.0.1:19445;
    www.ok.ru    127.0.0.1:19445;
    default      127.0.0.1:9443;
}
server {
    listen 443;
    ssl_preread on;
    proxy_pass $shocknet_tls_backend;
}
"""


class NginxRepairTests(unittest.TestCase):
    def test_adds_isolated_backend_without_changing_vpn_routes(self):
        site, stream, needed = repair.prepare(SITE, STREAM)
        self.assertTrue(needed)
        self.assertIn("listen 127.0.0.1:9444 ssl proxy_protocol;", site)
        self.assertRegex(stream, r"shocknet\.ru\s+127\.0\.0\.1:9444;")
        self.assertIn("ok.ru        127.0.0.1:19445;", stream)
        self.assertIn("default      127.0.0.1:9443;", stream)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/shocknet.ru/fullchain.pem;", site)

    def test_idempotent(self):
        site, stream, _ = repair.prepare(SITE, STREAM)
        again_site, again_stream, needed = repair.prepare(site, stream)
        self.assertFalse(needed)
        self.assertEqual((site, stream), (again_site, again_stream))

    def test_rejects_partial_or_unexpected_config(self):
        site, _, _ = repair.prepare(SITE, STREAM)
        with self.assertRaisesRegex(ValueError, "Partial"):
            repair.prepare(site, STREAM)
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            repair.prepare(SITE.replace("9443", "9555"), STREAM)
        with self.assertRaisesRegex(ValueError, "absent"):
            repair.prepare(SITE, STREAM.replace("$ssl_preread_server_name", "$other"))

    def test_dry_run_does_not_write_or_reload(self):
        with tempfile.TemporaryDirectory() as temp:
            site_path, stream_path = self._write(temp)
            with patch.object(repair, "SITE_FILE", site_path), \
                 patch.object(repair, "STREAM_FILE", stream_path), \
                 patch.object(repair, "check_port"), \
                 patch.object(repair, "run") as run:
                repair.install(False)
            self.assertEqual(site_path.read_text(), SITE)
            self.assertEqual(stream_path.read_text(), STREAM)
            run.assert_called_once_with("nginx", "-t")

    def test_apply_and_rollback_when_ssl_still_mismatches(self):
        with tempfile.TemporaryDirectory() as temp:
            site_path, stream_path = self._write(temp)
            with patch.object(repair, "SITE_FILE", site_path), \
                 patch.object(repair, "STREAM_FILE", stream_path), \
                 patch.object(repair, "BACKUP_DIR", Path(temp) / "backups"), \
                 patch.object(repair, "check_port"), \
                 patch.object(repair, "run") as run, \
                 patch.object(repair, "verify_https", side_effect=RuntimeError("bad cert")), \
                 patch.object(repair.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, "bad cert"):
                    repair.install(True)
            self.assertEqual(site_path.read_text(), SITE)
            self.assertEqual(stream_path.read_text(), STREAM)
            self.assertEqual(len(list((Path(temp) / "backups").glob("*/shocknet.ru"))), 1)
            self.assertEqual(sum(1 for c in run.call_args_list if c.args == ("systemctl", "reload", "nginx")), 2)

    def test_apply_success_keeps_originals_in_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            site_path, stream_path = self._write(temp)
            with patch.object(repair, "SITE_FILE", site_path), \
                 patch.object(repair, "STREAM_FILE", stream_path), \
                 patch.object(repair, "BACKUP_DIR", Path(temp) / "backups"), \
                 patch.object(repair, "check_port"), \
                 patch.object(repair, "run"), \
                 patch.object(repair, "verify_https") as verify:
                repair.install(True)
            self.assertIn("9444 ssl proxy_protocol", site_path.read_text())
            self.assertRegex(stream_path.read_text(), r"shocknet\.ru\s+127\.0\.0\.1:9444")
            backup = next((Path(temp) / "backups").glob("*"))
            self.assertEqual((backup / "shocknet.ru").read_text(), SITE)
            self.assertEqual((backup / "shocknet-vpn.conf").read_text(), STREAM)
            verify.assert_called_once()

    @staticmethod
    def _write(temp):
        site_path, stream_path = Path(temp) / "shocknet.ru", Path(temp) / "shocknet-vpn.conf"
        site_path.write_text(SITE)
        stream_path.write_text(STREAM)
        return site_path, stream_path


if __name__ == "__main__":
    unittest.main()
