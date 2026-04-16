"""
Unit tests for pure helpers in multi_frames.py.

These tests import the single-file distribution as a module in a throwaway
tempdir so the module's on-import config write does not touch real state.
"""

import os
import tempfile
import unittest

from tests._import_mf import load


class _MFTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir_obj = tempfile.TemporaryDirectory()
        cls.tmpdir = cls._tmpdir_obj.name
        cls._prev_cwd = os.getcwd()
        cls.mf = load(cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        try:
            os.chdir(cls._prev_cwd)
        finally:
            cls._tmpdir_obj.cleanup()


class PasswordHashingTests(_MFTestBase):
    def test_hash_is_deterministic(self):
        self.assertEqual(self.mf.hash_password("hunter2"),
                         self.mf.hash_password("hunter2"))

    def test_hash_changes_with_input(self):
        self.assertNotEqual(self.mf.hash_password("a"),
                            self.mf.hash_password("b"))

    def test_hash_is_hex_sha256(self):
        h = self.mf.hash_password("x")
        self.assertEqual(len(h), 64)
        int(h, 16)  # must parse as hex

    def test_known_default_admin_hash(self):
        # Regression: changing the hash scheme without a migration would
        # lock every deployed admin out of their server.
        self.assertEqual(
            self.mf.hash_password("admin123"),
            "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
        )


class LocalIpValidationTests(_MFTestBase):
    def test_rejects_public_ip(self):
        self.assertFalse(self.mf.validate_local_ip("http://8.8.8.8/"))

    def test_allows_localhost(self):
        self.assertTrue(self.mf.validate_local_ip("http://localhost/"))
        self.assertTrue(self.mf.validate_local_ip("http://127.0.0.1:8080/"))

    def test_allows_private_ranges(self):
        for url in (
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
        ):
            with self.subTest(url=url):
                self.assertTrue(self.mf.validate_local_ip(url))

    def test_rejects_mixed_case_public_hostname(self):
        self.assertFalse(self.mf.validate_local_ip("http://Example.COM/"))

    def test_allows_local_suffixes(self):
        self.assertTrue(self.mf.validate_local_ip("http://printer.local/"))
        self.assertTrue(self.mf.validate_local_ip("http://hub.lan/"))

    def test_bad_input_returns_false(self):
        self.assertFalse(self.mf.validate_local_ip(""))
        self.assertFalse(self.mf.validate_local_ip("not a url"))


class EscapeHtmlTests(_MFTestBase):
    def test_escapes_special_chars(self):
        self.assertEqual(
            self.mf.escape_html('<script>alert("x")</script>'),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;",
        )

    def test_none_returns_empty(self):
        self.assertEqual(self.mf.escape_html(None), "")

    def test_ampersand_is_escaped_first(self):
        self.assertEqual(self.mf.escape_html("&lt;"), "&amp;lt;")


class RateLimiterTests(_MFTestBase):
    def setUp(self):
        # isolate state between tests
        self.mf.failed_login_attempts.clear()
        self.ip = "198.51.100.42"

    def test_permits_when_empty(self):
        allowed, msg = self.mf.check_login_allowed(self.ip)
        self.assertTrue(allowed)
        self.assertIsNone(msg)

    def test_locks_out_after_max_attempts(self):
        for _ in range(self.mf.MAX_LOGIN_ATTEMPTS):
            self.mf.record_failed_login(self.ip)
        allowed, msg = self.mf.check_login_allowed(self.ip)
        self.assertFalse(allowed)
        self.assertIn("Try again", msg)

    def test_clear_resets_counter(self):
        for _ in range(self.mf.MAX_LOGIN_ATTEMPTS):
            self.mf.record_failed_login(self.ip)
        self.mf.clear_failed_logins(self.ip)
        allowed, _ = self.mf.check_login_allowed(self.ip)
        self.assertTrue(allowed)


class ConfigRoundTripTests(_MFTestBase):
    def test_save_then_load(self):
        cfg = self.mf.DEFAULT_CONFIG.copy()
        cfg["sentinel"] = "round-trip"
        ok, err = self.mf.save_config(cfg)
        self.assertTrue(ok, err)
        loaded = self.mf.load_config()
        self.assertEqual(loaded.get("sentinel"), "round-trip")


class SessionTests(_MFTestBase):
    def setUp(self):
        self.mf.sessions.clear()

    def test_create_and_retrieve_session(self):
        sid = self.mf.create_session("alice")
        self.assertIn(sid, self.mf.sessions)
        sess = self.mf.get_session(sid)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["username"], "alice")

    def test_unknown_session_returns_none(self):
        self.assertIsNone(self.mf.get_session("does-not-exist"))


class IdBackfillTests(_MFTestBase):
    def test_ensure_ids_fills_missing(self):
        cfg = {
            "iframes": [{"name": "a"}, {"name": "b", "id": "keepmeid"}],
            "widgets": [{"name": "w1"}],
        }
        changed = self.mf._ensure_ids(cfg)
        self.assertTrue(changed)
        self.assertEqual(cfg["iframes"][1]["id"], "keepmeid")
        # Every item now has an id; newly-generated ones are 8-char hex.
        self.assertIn("id", cfg["iframes"][0])
        self.assertEqual(len(cfg["iframes"][0]["id"]), 8)
        int(cfg["iframes"][0]["id"], 16)
        self.assertIn("id", cfg["widgets"][0])
        self.assertEqual(len(cfg["widgets"][0]["id"]), 8)
        int(cfg["widgets"][0]["id"], 16)

    def test_ensure_ids_noop_when_all_present(self):
        cfg = {
            "iframes": [{"name": "a", "id": "aa11aa11"}],
            "widgets": [],
        }
        self.assertFalse(self.mf._ensure_ids(cfg))

    def test_load_config_backfills_and_persists(self):
        # Write a pre-upgrade config with no IDs.
        import json
        raw = {
            "users": {"admin": {"password_hash": "x", "is_admin": True}},
            "iframes": [{"name": "legacy", "url": "http://127.0.0.1/"}],
            "widgets": [{"name": "legacy-widget", "type": "text"}],
            "settings": {},
        }
        with open(self.mf.CONFIG_FILE, "w") as f:
            json.dump(raw, f)
        loaded = self.mf.load_config()
        self.assertIn("id", loaded["iframes"][0])
        self.assertIn("id", loaded["widgets"][0])
        # Persisted to disk, so a second load returns the same IDs.
        iframe_id_first = loaded["iframes"][0]["id"]
        loaded2 = self.mf.load_config()
        self.assertEqual(loaded2["iframes"][0]["id"], iframe_id_first)


class PermissionFilterTests(_MFTestBase):
    def setUp(self):
        self.iframes = [
            {"id": "aaaaaaaa", "name": "Alpha"},
            {"id": "bbbbbbbb", "name": "Beta"},
        ]
        self.widgets = [
            {"id": "11111111", "name": "One"},
            {"id": "22222222", "name": "Two"},
        ]

    def test_admin_sees_all_even_with_empty_allowlist(self):
        user_rec = {"is_admin": True, "allowed_iframes": [], "allowed_widgets": []}
        ifs, wgs = self.mf.filter_by_permissions(self.iframes, self.widgets, user_rec)
        self.assertEqual(len(ifs), 2)
        self.assertEqual(len(wgs), 2)

    def test_unset_permissions_sees_all(self):
        user_rec = {"is_admin": False}
        ifs, wgs = self.mf.filter_by_permissions(self.iframes, self.widgets, user_rec)
        self.assertEqual(len(ifs), 2)
        self.assertEqual(len(wgs), 2)

    def test_empty_list_sees_none(self):
        user_rec = {"is_admin": False, "allowed_iframes": [], "allowed_widgets": []}
        ifs, wgs = self.mf.filter_by_permissions(self.iframes, self.widgets, user_rec)
        self.assertEqual(ifs, [])
        self.assertEqual(wgs, [])

    def test_partial_whitelist(self):
        user_rec = {
            "is_admin": False,
            "allowed_iframes": ["aaaaaaaa"],
            "allowed_widgets": ["22222222"],
        }
        ifs, wgs = self.mf.filter_by_permissions(self.iframes, self.widgets, user_rec)
        self.assertEqual([f["name"] for f in ifs], ["Alpha"])
        self.assertEqual([w["name"] for w in wgs], ["Two"])

    def test_orphan_ids_silently_ignored(self):
        # A stale permission referencing a deleted iframe should just
        # not show up — no crash, no other side effects.
        user_rec = {
            "is_admin": False,
            "allowed_iframes": ["gone-id", "aaaaaaaa"],
            "allowed_widgets": None,
        }
        ifs, wgs = self.mf.filter_by_permissions(self.iframes, self.widgets, user_rec)
        self.assertEqual([f["name"] for f in ifs], ["Alpha"])
        self.assertEqual(len(wgs), 2)  # None => see all widgets


if __name__ == "__main__":
    unittest.main()
