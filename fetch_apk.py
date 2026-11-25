#!/usr/bin/env python3
"""Entry point for the APKCombo fetcher.

    python fetch_apk.py --package com.netease.newspike --mode probe --detect-abis
    python fetch_apk.py --package com.netease.newspike --mode download --require-abi arm64-v8a

Run ``python fetch_apk.py --help`` for every option.
"""

from __future__ import annotations

import sys

from apkcombo.cli import main

if __name__ == "__main__":
    sys.exit(main())
