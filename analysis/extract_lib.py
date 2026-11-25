#!/usr/bin/env python3
"""Extract a single native library from a remote APK without downloading the APK.

The archive index is read with a few ranged requests, then only the member's
compressed bytes are transferred and inflated straight to disk. For a 700 MB APK
holding an 80 MB ``libGame.so`` that is roughly 30-40 MB of traffic instead of
700 MB, which keeps CI jobs short.

    python3 analysis/extract_lib.py \
        --package com.netease.newspike --slug blood-strike-x-dj-snake \
        --abi armeabi-v7a --so-name libGame.so --out out/libGame.so

Exit codes: 0 extracted, 1 request/verification failure, 2 member not found.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apkcombo import api, pages, zipindex  # noqa: E402
from apkcombo.errors import ApkComboError, describe_exception  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract one .so from a remote APK using ranged reads.",
    )
    parser.add_argument("-p", "--package", required=True, help="application id, e.g. com.netease.newspike")
    parser.add_argument("--slug", help="APKCombo slug; guessed from the package when omitted")
    parser.add_argument("--variant", default="apk", help="apk, xapk or auto (default: apk)")
    parser.add_argument("--abi", default="armeabi-v7a", help="lib/<abi>/ to take the member from")
    parser.add_argument("--so-name", default="libGame.so", help="member file name to extract")
    parser.add_argument("--out", required=True, help="destination path for the extracted file")
    parser.add_argument("--json", dest="json_out", help="also write a small report here")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--package-sha256", help="expected package sha256; refused when it differs")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def log(message: str) -> None:
    print(message, flush=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    debug = log if args.verbose else None

    try:
        app = pages.fetch_app_info(
            args.package, slug=args.slug, timeout=args.timeout, retries=args.retries, log=debug
        )
        log(f"app: {app.title or args.package} — {app.version_name or '?'} ({app.version_code or '?'})")
        if app.package and args.package and app.package != args.package:
            log(f"warning: page reports package {app.package}, expected {args.package}")

        dl_url, variants = pages.fetch_variants(app, timeout=args.timeout, retries=args.retries, log=debug)
        variant = pages.pick_variant(variants, args.variant)
        log(f"variant: {variant.kind.upper()} — {variant.size_text}")

        remote = api.resolve_file(
            dl_url, variant, timeout=args.timeout, retries=args.retries, log=debug
        )
        log(f"file: {remote.filename} — {remote.size_text}")

        archive = zipindex.RemoteZip(
            remote.url,
            size=remote.size,
            headers=remote.extra_headers,
            timeout=args.timeout,
            retries=args.retries,
            log=debug,
        )
        wanted_name = args.so_name.lower()
        wanted_dir = f"/lib/{args.abi.strip().lower()}/"
        matches = [
            entry
            for entry in archive.entries
            if entry.name.replace("\\", "/").rsplit("/", 1)[-1].lower() == wanted_name
            and wanted_dir in "/" + entry.name.replace("\\", "/").lower().lstrip("/")
        ]
        if not matches:
            found = [
                entry.name
                for entry in archive.entries
                if entry.name.replace("\\", "/").rsplit("/", 1)[-1].lower() == wanted_name
            ]
            if found:
                log(f"error: {args.so_name} exists, but not under lib/{args.abi}/. Found: {', '.join(found)}")
            else:
                log(f"error: {args.so_name} is not in {remote.filename} ({len(archive)} members)")
            return 2
        matches.sort(key=lambda entry: entry.uncompressed_size, reverse=True)
        entry = matches[0]
        log(
            f"member: {entry.name} — {entry.uncompressed_size} bytes ({entry.compression}), "
            f"crc32 {entry.crc32:08x}"
        )

        destination = Path(args.out)
        path, size, sha256 = archive.extract(entry, destination, log=debug)
        log(f"wrote {path} — {size} bytes, sha256 {sha256}")

        report = {
            "package": args.package,
            "slug": args.slug,
            "app_version_code": app.version_code,
            "app_version_name": app.version_name,
            "variant": variant.kind,
            "archive": remote.filename,
            "archive_size": remote.size,
            "member": entry.name,
            "abi": args.abi,
            "compressed_size": entry.compressed_size,
            "uncompressed_size": entry.uncompressed_size,
            "crc32": f"{entry.crc32:08x}",
            "sha256": sha256,
            "path": str(path),
        }
        if args.package_sha256:
            expected = args.package_sha256.strip().lower()
            actual = str(app.sha256 or "").strip().lower()
            report["page_sha256"] = actual or None
            if actual and actual != expected:
                log(f"error: page sha256 {actual} does not match --package-sha256 {expected}")
                return 1
        if args.json_out:
            Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 0
    except ApkComboError as exc:
        log(f"error: {describe_exception(exc)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
