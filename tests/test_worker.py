"""
Static analysis of cloud/worker.js.

Heavy dynamic tests belong in a Cloudflare Miniflare harness; this file is
deliberately minimal so it runs without extra tooling.

Checks:
  - Worker file parses as JavaScript (via Node if available; skipped otherwise).
  - Sanity: no accidental duplicate top-level ``const`` declarations of the
    same identifier.
  - Each route referenced from the Python client is present in the worker.
"""

import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKER = os.path.join(ROOT, "cloud", "worker.js")
CLIENT = os.path.join(ROOT, "multi_frames.py")


class WorkerStaticChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(WORKER, "r", encoding="utf-8") as f:
            cls.src = f.read()

    def test_file_exists(self):
        self.assertTrue(os.path.isfile(WORKER))
        self.assertGreater(len(self.src), 1000)

    def test_node_syntax_check(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        proc = subprocess.run(
            [node, "--check", WORKER],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0,
                         f"node --check failed:\n{proc.stderr}")

    def test_no_duplicate_top_level_const(self):
        names = re.findall(r"^const\s+(\w+)\s*=", self.src, flags=re.MULTILINE)
        dups = {n for n in names if names.count(n) > 1}
        self.assertFalse(dups, f"duplicate top-level const: {dups}")

    def test_handles_cors_preflight(self):
        self.assertRegex(self.src, r"['\"]OPTIONS['\"]")

    def test_client_referenced_routes_exist_in_worker(self):
        """
        Pull /api/... strings that the Python client POSTs/GETs against the
        cloud base URL and make sure each one shows up in worker.js.
        """
        with open(CLIENT, "r", encoding="utf-8") as f:
            client_src = f.read()

        # Only match routes that appear to be sent to the cloud. A route is a
        # cloud endpoint if the string appears next to `cloud_url` or under a
        # function name containing 'cloud'.
        cloud_routes = set()
        for match in re.finditer(r"/api/[a-zA-Z0-9_\-/]+", client_src):
            route = match.group(0).rstrip("/")
            ctx = client_src[max(0, match.start() - 200): match.end() + 50]
            if "cloud" in ctx.lower():
                cloud_routes.add(route)

        missing = [r for r in sorted(cloud_routes) if r not in self.src]
        self.assertFalse(
            missing,
            f"client calls these cloud routes but worker.js does not define them: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
