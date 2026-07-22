#!/usr/bin/env python3
"""Compatibility launcher for running repo-guard from a source checkout."""

from pathlib import Path
import sys


SOURCE_DIR = Path(__file__).resolve().parent / "src"
if str(SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIR))

from repo_guard.cli import entrypoint  # noqa: E402


if __name__ == "__main__":
    entrypoint()
