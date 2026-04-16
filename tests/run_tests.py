#!/usr/bin/env python3
"""
Multi-Frames test runner.

Uses only the Python standard library (matches the project's
zero-dependency constraint). Discovers every tests/test_*.py file
and runs all TestCases found inside.

Usage:
    python tests/run_tests.py              # run everything
    python tests/run_tests.py -k proxy     # only tests whose id contains 'proxy'
    python tests/run_tests.py -v           # verbose
"""

import argparse
import os
import sys
import unittest


def main():
    parser = argparse.ArgumentParser(description="Multi-Frames test runner")
    parser.add_argument("-k", dest="filter", default=None,
                        help="only run tests whose dotted id contains this substring")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, repo_root)

    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=os.path.dirname(__file__),
        pattern="test_*.py",
        top_level_dir=repo_root,
    )

    if args.filter:
        suite = _filter_suite(suite, args.filter)

    verbosity = 2 if args.verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


def _filter_suite(suite, needle):
    keep = unittest.TestSuite()
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            sub = _filter_suite(item, needle)
            if sub.countTestCases():
                keep.addTest(sub)
        else:
            if needle in item.id():
                keep.addTest(item)
    return keep


if __name__ == "__main__":
    main()
