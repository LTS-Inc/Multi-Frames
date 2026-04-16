"""
End-to-end HTTP tests. Spin up the real server on an ephemeral port in a
background thread, drive it with urllib, and assert key behaviors.

These tests are lightweight by design — they don't exercise the admin UI or
cloud sync. They verify the authentication path, admin gating, and the
proxy SSRF regression identified in REVIEW.md §1.1.
"""

import http.server
import os
import socket
import socketserver
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from tests._import_mf import load


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ServerFixture:
    """Runs a Multi-Frames server in a background thread."""

    def __init__(self, mf):
        self.mf = mf
        self.port = _free_port()
        self.httpd = mf.ThreadedTCPServer(("127.0.0.1", self.port), mf.MFHandler) \
            if hasattr(mf, "MFHandler") else None
        if self.httpd is None:
            # Handler class is named differently in single-file; find it.
            handler_cls = _find_handler_class(mf)
            self.httpd = mf.ThreadedTCPServer(("127.0.0.1", self.port), handler_cls)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _find_handler_class(mf):
    for name in dir(mf):
        obj = getattr(mf, name)
        if isinstance(obj, type) and issubclass(obj, http.server.BaseHTTPRequestHandler) \
                and obj is not http.server.BaseHTTPRequestHandler:
            return obj
    raise RuntimeError("Could not locate request handler class in multi_frames module")


class _RedirectingUpstream:
    """Tiny HTTP server that 302s to a chosen external URL. Used to test SSRF."""

    def __init__(self, target_url):
        self.target = target_url
        port = _free_port()
        target = self.target

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self_inner):
                self_inner.send_response(302)
                self_inner.send_header("Location", target)
                self_inner.end_headers()

            def log_message(self_inner, *_a, **_k):
                return

        self.port = port
        self.httpd = socketserver.TCPServer(("127.0.0.1", port), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir_obj = tempfile.TemporaryDirectory()
        cls._prev_cwd = os.getcwd()
        cls.mf = load(cls._tmpdir_obj.name)
        cls.server = _ServerFixture(cls.mf)
        time.sleep(0.1)  # let the listener come up

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        os.chdir(cls._prev_cwd)
        cls._tmpdir_obj.cleanup()

    def _get(self, path, cookie=None, allow_redirects=False):
        req = urllib.request.Request(self.server.base + path)
        if cookie:
            req.add_header("Cookie", f"session={cookie}")
        try:
            return urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            return e

    def _post_form(self, path, fields, cookie=None):
        data = urllib.parse.urlencode(fields).encode("utf-8")
        req = urllib.request.Request(self.server.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if cookie:
            req.add_header("Cookie", f"session={cookie}")
        # Don't follow 302s — we need to inspect them.
        opener = urllib.request.build_opener(NoRedirect())
        try:
            return opener.open(req, timeout=5)
        except urllib.error.HTTPError as e:
            return e

    # ---- tests -------------------------------------------------------------

    def test_login_page_served_when_unauthenticated(self):
        resp = self._get("/")
        self.assertIn(resp.status, (200, 302))

    def test_login_rejects_wrong_password(self):
        resp = self._post_form("/login", {"username": "admin", "password": "wrong"})
        # Failed logins re-render the login page (200), not a redirect.
        self.assertEqual(resp.status, 200)
        body = resp.read().decode("utf-8", "replace")
        self.assertIn("Invalid", body)

    def test_login_accepts_default_admin(self):
        resp = self._post_form("/login", {"username": "admin", "password": "admin123"})
        self.assertEqual(resp.status, 302)
        cookies = resp.headers.get("Set-Cookie", "")
        self.assertIn("session=", cookies)

    def test_proxy_rejects_external_url(self):
        # Ensure an iframe pointing at a non-local URL is rejected.
        cfg = self.mf.load_config()
        cfg.setdefault("iframes", []).append({
            "url": "http://example.com/",
            "name": "external",
        })
        self.mf.save_config(cfg)
        # Need an auth cookie first.
        login = self._post_form("/login", {"username": "admin", "password": "admin123"})
        session = _extract_session(login.headers.get("Set-Cookie", ""))
        idx = len(cfg["iframes"]) - 1
        resp = self._get(f"/proxy/{idx}/", cookie=session)
        self.assertEqual(resp.status, 403)

    def test_permissions_restrict_non_admin_user(self):
        """Admin restricts alice to one iframe; alice's dashboard reflects it."""
        mf = self.mf
        cfg = mf.load_config()
        iframe_a_id = mf.secrets.token_hex(4)
        iframe_b_id = mf.secrets.token_hex(4)
        cfg["iframes"] = [
            {"id": iframe_a_id, "name": "DASHBOARD_ALPHA_MARKER",
             "url": "http://127.0.0.1/", "use_embed_code": False,
             "embed_code": "", "height": 200, "width": 100, "zoom": 100,
             "allow_external": False},
            {"id": iframe_b_id, "name": "DASHBOARD_BETA_MARKER",
             "url": "http://127.0.0.1/", "use_embed_code": False,
             "embed_code": "", "height": 200, "width": 100, "zoom": 100,
             "allow_external": False},
        ]
        cfg["users"]["alice"] = {
            "password_hash": mf.hash_password("wonderland"),
            "is_admin": False,
            "allowed_iframes": [iframe_a_id],
            "allowed_widgets": None,
        }
        mf.save_config(cfg)

        login = self._post_form("/login", {"username": "alice", "password": "wonderland"})
        self.assertEqual(login.status, 302)
        session = _extract_session(login.headers.get("Set-Cookie", ""))
        home = self._get("/", cookie=session)
        body = home.read().decode("utf-8", "replace")
        self.assertIn("DASHBOARD_ALPHA_MARKER", body)
        self.assertNotIn("DASHBOARD_BETA_MARKER", body)

    def test_admin_always_sees_everything(self):
        """Even if the admin's own record has an empty allow-list, admin sees all."""
        mf = self.mf
        cfg = mf.load_config()
        iframe_a_id = mf.secrets.token_hex(4)
        iframe_b_id = mf.secrets.token_hex(4)
        cfg["iframes"] = [
            {"id": iframe_a_id, "name": "ADMIN_SEES_ALPHA",
             "url": "http://127.0.0.1/", "use_embed_code": False,
             "embed_code": "", "height": 200, "width": 100, "zoom": 100,
             "allow_external": False},
            {"id": iframe_b_id, "name": "ADMIN_SEES_BETA",
             "url": "http://127.0.0.1/", "use_embed_code": False,
             "embed_code": "", "height": 200, "width": 100, "zoom": 100,
             "allow_external": False},
        ]
        cfg["users"]["admin"]["allowed_iframes"] = []  # deny-all would apply if not bypassed
        cfg["users"]["admin"]["allowed_widgets"] = []
        mf.save_config(cfg)

        login = self._post_form("/login", {"username": "admin", "password": "admin123"})
        session = _extract_session(login.headers.get("Set-Cookie", ""))
        home = self._get("/", cookie=session)
        body = home.read().decode("utf-8", "replace")
        self.assertIn("ADMIN_SEES_ALPHA", body)
        self.assertIn("ADMIN_SEES_BETA", body)

    def test_proxy_rejects_redirect_to_external(self):
        """Regression for REVIEW.md §1.1 — will FAIL on unpatched code."""
        upstream = _RedirectingUpstream("http://example.com/")
        try:
            cfg = self.mf.load_config()
            cfg.setdefault("iframes", []).append({
                "url": upstream.url,  # local (127.0.0.1) → passes validate_local_ip
                "name": "redirector",
            })
            self.mf.save_config(cfg)
            login = self._post_form("/login", {"username": "admin", "password": "admin123"})
            session = _extract_session(login.headers.get("Set-Cookie", ""))
            idx = len(cfg["iframes"]) - 1
            resp = self._get(f"/proxy/{idx}/", cookie=session)
            body = b""
            try:
                body = resp.read()
            except Exception:
                pass
            # Expected once patched: 403 Forbidden.
            # Current (unpatched) behavior: 200 + external body.
            self.assertNotIn(b"Example Domain", body,
                             "SSRF: proxy followed redirect to external host")
        finally:
            upstream.close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _extract_session(set_cookie_header):
    for part in set_cookie_header.split(","):
        part = part.strip()
        if part.startswith("session="):
            return part.split(";", 1)[0].split("=", 1)[1]
    return ""


if __name__ == "__main__":
    unittest.main()
