"""
Helper to import the single-file distribution (multi_frames.py) as a module
for unit testing, with a temp config file so tests never clobber a real one.

Call ``load(tmpdir)`` before any tests reference ``multi_frames`` symbols.
"""

import importlib.util
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load(tmpdir):
    """Import multi_frames.py under an alias and point it at a scratch config."""
    # Work in the tmpdir so the relative CONFIG_FILE path lands there.
    os.chdir(tmpdir)

    src = os.path.join(_REPO_ROOT, "multi_frames.py")
    spec = importlib.util.spec_from_file_location("mf_singlefile", src)
    module = importlib.util.module_from_spec(spec)

    # The module writes a default config on import if one is missing. The
    # chdir above ensures the write happens inside the tmpdir.
    sys.modules["mf_singlefile"] = module
    spec.loader.exec_module(module)
    return module
