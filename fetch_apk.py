#!/usr/bin/env python3
"""Thin entry point: ``python fetch_apk.py --help``.

The implementation lives in the :mod:`apkpure` package; this script only adds
the repository root to ``sys.path`` so the tool works without installation.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apkpure.cli import main  # noqa: E402  (import after sys.path tweak)

if __name__ == "__main__":
    sys.exit(main())
