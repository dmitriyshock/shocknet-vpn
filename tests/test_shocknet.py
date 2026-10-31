"""Offline regression tests for the VPN control plane.

Run: .venv/bin/python -m unittest discover -s tests -v
No Telegram or VPS credentials are required.
"""

import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


with patch.dict(os.environ, {
    "BOT_TOKEN": "123456:offline-test-token", "BOT_USERNAME": "test_shocknet_bot",
    "DOMAIN": "vpn.test.example", "SERVER_IP": "198.51.100.10",
    "STATIC_UUID": "a2c4a5d0-5b36-4717-9508-4df884130001",
    "STATIC_TOKEN": "random-administrator-token-for-tests",
    "SESSION_SECRET": "test-only-secret-with-adequate-entropy",
    "XRAY_PUBLIC_KEY": "public-key-placeholder", "XRAY_SHORT_ID": "123456abcdef0000",
    "GEOIP_HTTPS_ENDPOINT": "",
}):
    web = load_module("shocknet_web", "webserver/server.py")
    bot = load_module("shocknet_bot", "bot/bot.py")
    monitor = load_module("shocknet_monitor", "log-monitor/monitor.py")
    rotation = load_module("shocknet_rotation", "scripts/rotate_admin.py")


class WebAuthTests(unittest.TestCase):
    def test_session_signed_and_expires(self):
        now = int(time.time())
        token = web.make_session_token(now)
        self.assertTrue(web.is_authenticated("foo=bar; session=" + token))
        self.assertFalse(web.is_authenticated("session=" + token + "tampered"))
        self.assertFalse(web.is_authenticated("session=" + web.make_session_token(now - 9 * 86400)))
        self.assertFalse(web.is_authenticated("session=" + web.make_session_token(now + 1000)))
        self.assertFalse(web.is_authenticated("session=broken"))

    def test_bad_telegram_date_fails_closed(self):
        self.assertFalse(web.verify_telegram_auth({"auth_date": "not-an-int", "hash": "x"}))

    def test_public_admin_token_has_no_default(self):
        with patch.dict(web.STATIC_USER, {"token": ""}):
            self.assertIsNone(web.find_user("admin"))


class SubscriptionTests(unittest.TestCase):
    def test_all_active_xray_endpoints_are_in_v2ray_subscription(self):
        links = base64.b64decode(web.v2ray_sub()).decode().splitlines()
        self.assertEqual(len(links), 7)
        for port in (4443, 2053, 8443, 8444, 8445, 8446):
            self.assertTrue(any(f":{port}?" in s for s in links), port)
        self.assertTrue(any("@vpn.test.example:443?" in s and "type=ws" in s for s in links))
        self.assertTrue(all("flow=xtls-rprx-vision" in s for s in links if ":844" in s))
        self.assertTrue(any(":2053?" in s and "flow=" not in s for s in links))

    def test_clash_profiles_and_secure_lan_default(self):
        import yaml
        config = yaml.safe_load(web.clash_yaml())
        self.assertFalse(config["allow-lan"])
        self.assertEqual(len(config["proxies"]), 7)
        self.assertEqual(len(config["proxy-groups"][0]["proxies"]), 7)
        self.assertEqual(next(p for p in config["proxies"] if p["port"] == 8443)["flow"], "xtls-rprx-vision")
        self.assertEqual(next(p for p in config["proxies"] if p["port"] == 443)["network"], "ws")

    def test_html_escapes_user_data(self):
        payload = '<img src=x onerror="alert(1)">'
        page = web.user_page({"token": "test-token", "uuid": web.UUID, "email": "tg_123", "label": payload})
        self.assertNotIn(payload, page)
        self.assertIn("&lt;img", page)
        self.assertIn("escapeHtml(u.label)", web.JS)

    def test_no_placeholder_download_links(self):
        self.assertNotIn('href="#"', web.user_page({"token": "abc", "uuid": web.UUID,
                                                   "email": "tg_1", "label": "A"}))
        self.assertNotIn('href="#"', web.landing_page())

    def test_legacy_traffic_aliases_generalized(self):
        result = web._merge_aliases({"tg_123_ws": {"uplink": 1, "downlink": 2},
                                     "tg_456_8443": {"uplink": 3, "downlink": 4}})
        self.assertEqual(result["tg_123"]["uplink"], 1)
        self.assertEqual(result["tg_456"]["downlink"], 4)


class BotTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.users = Path(self.tempdir.name) / "users.json"
        self.patch_db = patch.object(bot, "USERS_FILE", self.users)
        self.patch_db.start()
        self.addCleanup(self.patch_db.stop)

    def test_initial_database_and_atomic_save(self):
        self.assertEqual(bot.load_db(), {"admin_id": 0, "users": {}, "trial_keys": {}})
        bot.save_db({"admin_id": 42, "users": {}, "trial_keys": {}})
        self.assertEqual(bot.get_admin_id(), 42)
        self.assertEqual(self.users.stat().st_mode & 0o777, 0o600)

    def test_trial_expiry_revokes_xray(self):
        now = time.time()
        bot.save_db({"admin_id": 1, "users": {}, "trial_keys": {
            "expired": {"email": "trial_expired", "expires_at": now - 2},
            "active": {"email": "trial_active", "expires_at": now + 5000},
        }})
        with patch.object(bot, "xray_remove") as remove:
            bot.cleanup_expired_trials()
        remove.assert_called_once_with("trial_expired")
        self.assertNotIn("expired", bot.load_db()["trial_keys"])
        self.assertIn("active", bot.load_db()["trial_keys"])

    def test_new_user_is_added_to_every_vless_endpoint(self):
        config_path = Path(self.tempdir.name) / "xray.json"
        config_path.write_text(json.dumps({"inbounds": [
            {"protocol": "dokodemo-door", "settings": {}},
            *({"protocol": "vless", "port": port, "settings": {"clients": []}}
              for port in (4443, 2053, 8880, 8443, 8444, 8445, 8446)),
        ]}))
        uid = "fd48b407-7eb6-456a-98f6-e172a7245274"
        self.assertTrue(bot._cfg_add(config_path, uid, "tg_123"))
        self.assertFalse(bot._cfg_add(config_path, uid, "tg_123"))
        data = json.loads(config_path.read_text())
        for inbound in data["inbounds"]:
            if inbound["protocol"] != "vless":
                continue
            client = inbound["settings"]["clients"][0]
            self.assertEqual(client["id"], uid)
            self.assertEqual(client.get("flow"), "xtls-rprx-vision" if inbound["port"] in (4443, 8443, 8444, 8445, 8446) else None)
        self.assertTrue(bot._cfg_remove(config_path, "tg_123"))
        self.assertFalse(bot._cfg_remove(config_path, "tg_123"))
        self.assertTrue(all(not inbound.get("settings", {}).get("clients") for inbound in json.loads(config_path.read_text())["inbounds"]))
        self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

    def test_failed_xray_restart_is_reported(self):
        with patch.object(bot, "_cfg_remove", return_value=True), patch.object(bot, "_snapshot_stats"), \
             patch.object(bot.subprocess, "run", side_effect=[SimpleNamespace(returncode=0), SimpleNamespace(returncode=1)]):
            self.assertFalse(bot.xray_remove("tg_123"))


class BotApprovalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.user_path = Path(self.tmp.name) / "users.json"
        self.path_patch = patch.object(bot, "USERS_FILE", self.user_path)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        bot.save_db({"admin_id": 1, "users": {"123": {"pending": True, "approved": False,
                                                     "name": "Test User", "username": "tester"}}, "trial_keys": {}})

    async def approve(self, xray_success):
        query = SimpleNamespace(from_user=SimpleNamespace(id=1), data="ok:123",
                                message=SimpleNamespace(text="Access request"),
                                answer=AsyncMock(), edit_message_text=AsyncMock())
        update = SimpleNamespace(callback_query=query)
        ctx = SimpleNamespace(bot=SimpleNamespace(send_message=AsyncMock()))
        with patch.object(bot, "xray_add", return_value=xray_success):
            await bot.cb_approve(update, ctx)
        return query, ctx

    async def test_approve_writes_key_only_after_xray_restart(self):
        _, ctx = await self.approve(True)
        self.assertTrue(bot.load_db()["users"]["123"]["approved"])
        ctx.bot.send_message.assert_awaited_once()

    async def test_failed_xray_does_not_approve_user(self):
        query, ctx = await self.approve(False)
        self.assertFalse(bot.load_db()["users"]["123"]["approved"])
        ctx.bot.send_message.assert_not_awaited()
        query.edit_message_text.assert_awaited_once()


class MonitorTests(unittest.TestCase):
    def test_sensitive_subscription_paths_redacted(self):
        self.assertEqual(monitor.sanitize_path("/sub/secret?foo=bar"), "/sub/[redacted]")
        self.assertEqual(monitor.sanitize_path("/sub/clash/secret"), "/sub/clash/[redacted]")
        self.assertEqual(monitor.sanitize_path("/api/user-stats/secret"), "/api/user-stats/[redacted]")
        self.assertEqual(monitor.sanitize_referrer("https://x.test/sub/secret"), "[redacted]")

    def test_geoip_outbound_is_opt_in(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE geo (ip TEXT PRIMARY KEY, country TEXT, region TEXT, city TEXT, lat REAL, lon REAL, isp TEXT, updated_at INTEGER)")
        with patch.object(monitor, "GEOIP_HTTPS_ENDPOINT", ""), patch.object(monitor, "urlopen") as outgoing:
            self.assertIsNone(monitor.get_geo(conn, "8.8.8.8"))
            outgoing.assert_not_called()
        conn.close()


class InstallerTests(unittest.TestCase):
    def test_bash_syntax_and_expansion_of_nginx_template(self):
        script = (ROOT / "setup.sh").read_text()
        subprocess.run(["bash", "-n", str(ROOT / "setup.sh")], check=True)
        matches = re.findall(r"cat > /etc/nginx/sites-available/shocknet <<EOF\n(.*?)\nEOF", script, re.S)
        self.assertEqual(len(matches), 2)
        # Render nginx to stdout under the installer's `set -u` guard.
        result = subprocess.run(["bash", "-eu", "-c", "DOMAIN=vpn.test.example\ncat <<EOF\n" + matches[1] + "\nEOF"],
                                text=True, capture_output=True, check=True)
        self.assertIn("$host$request_uri", result.stdout)
        self.assertIn("$http_upgrade", result.stdout)
        self.assertIn("access_log off", result.stdout)
        self.assertIn("127.0.0.1:8008", result.stdout)
        self.assertIn("STATIC_TOKEN=$(openssl rand -hex 24)", script)

    def test_generated_xray_configurations_are_valid_json(self):
        script = (ROOT / "setup.sh").read_text()
        for name in ("xray", "xray2"):
            match = re.search(r"cat > /opt/" + name + r"/config.json <<EOF\n(.*?)\nEOF", script, re.S)
            self.assertIsNotNone(match)
            shell = "STATIC_UUID=40b5b347-2e67-4829-a172-9e409aa50f2b\nXRAY_PRIVATE_KEY=testkey\nXRAY_SHORT_ID=deadbeefcafe1234\n"
            result = subprocess.run(["bash", "-eu", "-c", shell + "cat <<EOF\n" + match.group(1) + "\nEOF"],
                                    text=True, capture_output=True, check=True)
            config = json.loads(result.stdout)
            self.assertGreaterEqual(len(config["inbounds"]), 4 if name == "xray" else 5)
            self.assertTrue(all("id" in c for i in config["inbounds"] if i.get("protocol") == "vless"
                                for c in i["settings"]["clients"]))

    def test_real_xray_binary_accepts_both_configs(self):
        binary = os.getenv("XRAY_TEST_BINARY")
        if not binary:
            self.skipTest("Set XRAY_TEST_BINARY to run Xray-core's config validator")
        keys = subprocess.run([binary, "x25519"], text=True, capture_output=True, check=True).stdout
        key = re.search(r"Private key:\s*(\S+)", keys).group(1)
        installer = (ROOT / "setup.sh").read_text()
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("xray", "xray2"):
                template = re.search(r"cat > /opt/" + name + r"/config.json <<EOF\n(.*?)\nEOF", installer, re.S).group(1)
                shell = ("STATIC_UUID=40b5b347-2e67-4829-a172-9e409aa50f2b\n"
                         f"XRAY_PRIVATE_KEY={key}\nXRAY_SHORT_ID=deadbeefcafe1234\n")
                rendered = subprocess.run(["bash", "-eu", "-c", shell + "cat <<EOF\n" + template + "\nEOF"],
                                          text=True, capture_output=True, check=True).stdout
                path = Path(tmp) / (name + ".json")
                path.write_text(rendered)
                checked = subprocess.run([binary, "run", "-test", "-config", str(path)],
                                         text=True, capture_output=True)
                self.assertEqual(checked.returncode, 0, f"{name}: {checked.stderr}")


class RotationTests(unittest.TestCase):
    def test_rotates_only_admin_and_creates_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / ".env"
            old = "00000000-0000-4000-8000-000000000001"
            env.write_text(f"STATIC_UUID={old}\nSTATIC_TOKEN=admin\nDOMAIN=vpn.test.example\n")
            paths = [root / "xray.json", root / "xray2.json"]
            for path in paths:
                path.write_text(json.dumps({"inbounds": [{"protocol": "vless", "settings": {"clients": [
                    {"id": old, "email": "admin"},
                    {"id": "00000000-0000-4000-8000-000000000002", "email": "tg_22"},
                ]}}]}))
            restarts = []
            token, new_uuid, backup = rotation.rotate_admin(env, paths, root / "backups", lambda: restarts.append(1))
            self.assertNotIn("admin", token)
            self.assertEqual(len(token), 48)
            self.assertNotEqual(old, new_uuid)
            self.assertIn(f"STATIC_TOKEN={token}", env.read_text())
            for path in paths:
                clients = json.loads(path.read_text())["inbounds"][0]["settings"]["clients"]
                self.assertEqual(clients[0]["id"], new_uuid)
                self.assertEqual(clients[1]["email"], "tg_22")
            self.assertEqual(len(list(backup.iterdir())), 3)
            self.assertEqual(len(restarts), 1)

    def test_failed_restart_rolls_back_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_uuid = "00000000-0000-4000-8000-000000000001"
            env = root / ".env"
            env.write_text(f"STATIC_UUID={old_uuid}\nSTATIC_TOKEN=admin\n")
            configs = [root / "one.json", root / "two.json"]
            original = json.dumps({"inbounds": [{"protocol": "vless", "settings": {"clients": [{"id": old_uuid}]}}]})
            for path in configs:
                path.write_text(original)
            def failure():
                raise RuntimeError("simulated restart failure")
            with self.assertRaises(RuntimeError):
                rotation.rotate_admin(env, configs, root / "backups", failure)
            self.assertIn("STATIC_TOKEN=admin", env.read_text())
            self.assertTrue(all(path.read_text() == original for path in configs))


class HttpSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.original_path = web.USERS_FILE
        cls.original_lock = web.STATS_LOCK_FILE
        cls.original_stats = web.STATS_FILE
        web.USERS_FILE = str(Path(cls.tmp.name) / "users.json")
        web.STATS_LOCK_FILE = str(Path(cls.tmp.name) / "stats.lock")
        web.STATS_FILE = str(Path(cls.tmp.name) / "stats.json")
        Path(web.USERS_FILE).write_text(json.dumps({"admin_id": 1, "users": {
            "123": {"approved": True, "token": "user-token", "uuid": web.UUID,
                    "email": "tg_123", "name": "<b>danger</b>", "username": "visitor"},
        }, "trial_keys": {}}))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        web.USERS_FILE = cls.original_path
        web.STATS_LOCK_FILE = cls.original_lock
        web.STATS_FILE = cls.original_stats
        cls.tmp.cleanup()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_routes_auth_and_subscription(self):
        with urlopen(self.url("/"), timeout=5) as r:
            self.assertEqual(r.status, 200)
            self.assertIn(b"ShockNet VPN", r.read())
        with urlopen(self.url("/sub/user-token"), timeout=5) as r:
            links = base64.b64decode(r.read()).decode()
            self.assertIn(":8443?", links)
        browser = Request(self.url("/sub/user-token"), headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(browser, timeout=5) as r:
            page = r.read().decode()
            self.assertIn("&lt;b&gt;danger&lt;/b&gt;", page)
        with urlopen(self.url("/api/user-stats/user-token"), timeout=5) as r:
            self.assertIn("uplink", json.loads(r.read()))
        with urlopen(self.url("/admin"), timeout=5) as r:
            self.assertTrue(r.geturl().endswith("/login"))

    def test_api_rejects_unauthenticated_and_cross_origin_post(self):
        req = Request(self.url("/api/bot/stop"), data=b"", method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 401)
        req = Request(self.url("/api/bot/stop"), data=b"", method="POST",
                      headers={"Cookie": "session=" + web.make_session_token(), "Origin": "https://attacker.example"})
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
