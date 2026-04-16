# Multi-Frames Tests

Zero-dependency test suite for the Multi-Frames project. Uses only the Python
standard library, matching the project's no-pip constraint.

## Layout

| File | What it covers |
|------|----------------|
| `run_tests.py` | Discovery + runner (no pytest required) |
| `_import_mf.py` | Helper that imports `multi_frames.py` into a scratch tempdir |
| `test_unit.py` | Pure helpers: hashing, URL validation, HTML escaping, rate limiter, config round-trip, sessions |
| `test_server.py` | Boots the real server on an ephemeral port and exercises login, admin gating, and the proxy SSRF regression (see [REVIEW.md §1.1](../REVIEW.md)) |
| `test_worker.py` | Static checks on `cloud/worker.js` — Node syntax check (if Node is installed), duplicate-declaration scan, client/worker route-parity |

## Running

```bash
# full suite
python tests/run_tests.py

# verbose
python tests/run_tests.py -v

# just tests whose id contains 'proxy'
python tests/run_tests.py -k proxy
```

The suite creates its own `multi_frames_config.json` inside a `TemporaryDirectory`
— your real `~/.multi_frames_config.json` is never touched.

## Manual release checklist

Automated tests are a floor, not a ceiling. Before tagging a release, run
through the manual checklist:

1. **Clean install.** Remove `~/.multi_frames_config.json`, start the server,
   change the default admin password, confirm it persists after restart.
2. **iFrame CRUD + connectivity test.** Add, edit, reorder, delete; run the
   connectivity tester against a live local URL.
3. **SSRF regression.** Add an iframe at a local redirector that 302s to a
   public URL. Fetch `/proxy/<idx>/` — must be `403`.
4. **Rate limit.** Six bad logins from one IP must lock that IP out for 15 min.
5. **Admin gating.** Non-admin user must be blocked from `/admin` and every
   `/admin/...` POST.
6. **Network command.** Send `dummy` then `tcp` to a closed port; verify
   graceful error handling.
7. **Raspberry Pi card.** On a Pi: temp and throttled flags render. Off a Pi:
   card says "not detected" without a stack trace.
8. **Cloud sync** (if configured). Push, mutate in portal, pull, diff.
9. **Tunnel relay.** Open a tunnel, fetch a local page, terminate, confirm the
   Durable Object cleans up (`wrangler tail`).
10. **Crash mid-save.** `kill -9` the server during a config save; verify the
    config file still parses on next start. (Will fail until
    [REVIEW.md §2.3](../REVIEW.md) is fixed.)

## CI (not yet wired)

Suggested GitHub Actions workflow:

```yaml
name: tests
on: [push, pull_request]
jobs:
  python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: python tests/run_tests.py -v
```

Drop this in `.github/workflows/tests.yml` when the team is ready to enable CI.
