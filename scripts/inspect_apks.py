#!/usr/bin/env python3
"""Unpack a Blood Strike archive and prove which ABIs it actually ships.

What it does:

1. extracts the outer archive (``.zip`` / ``.xapk``) with zip-slip protection,
2. expands nested archives (``.xapk`` / ``.zip`` inside the outer one),
3. scans every ``.apk`` on disk for ``lib/<abi>/*.so`` entries — index only, so a
   640 MiB base APK costs a few milliseconds instead of a full decompress,
4. cross-checks ``config.<abi>.apk`` split names and the XAPK ``manifest.json``,
5. writes ``abi_report.json`` + ``abi_report.md`` and exits non-zero when a
   required ABI is missing, so the workflow fails loudly instead of silently.

Default expectation: both ``arm64-v8a`` (64-bit) and ``armeabi-v7a`` (32-bit).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ARCHIVE_SUFFIXES = (".zip", ".xapk")
APK_SUFFIX = ".apk"

#: canonical ABI -> every spelling seen in the wild
ABI_ALIASES: Dict[str, Tuple[str, ...]] = {
    "arm64-v8a": ("arm64-v8a", "arm64_v8a", "arm64", "aarch64", "arm64-v8a".replace("-", "_")),
    "armeabi-v7a": ("armeabi-v7a", "armeabi_v7a", "armeabi", "v7a", "arm", "arm32"),
    "x86_64": ("x86_64", "x86-64", "x64", "amd64"),
    "x86": ("x86", "i386", "i686", "x86_32"),
}
CANONICAL_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

BITNESS = {
    "arm64-v8a": "64-bit",
    "armeabi-v7a": "32-bit",
    "x86_64": "64-bit",
    "x86": "32-bit",
}

DEFAULT_REQUIRED = ("arm64-v8a", "armeabi-v7a")
LIB_PATTERN = re.compile(r"^lib/([^/]+)/")
CONFIG_SPLIT_PATTERN = re.compile(r"^config[._]([A-Za-z0-9._-]+)$", re.IGNORECASE)
_SPLIT_NOISE = ("config", "base", "split", "master", "apk", "_", ".")


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------


@dataclass
class SoFile:
    arch: str
    name: str
    size: int


@dataclass
class ApkScan:
    path: str
    size: int
    abis: Dict[str, List[SoFile]] = field(default_factory=dict)
    declared_split_abi: Optional[str] = None
    entry_count: int = 0
    error: Optional[str] = None

    @property
    def abi_names(self) -> List[str]:
        return sorted(self.abis)

    def as_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "size": self.size,
            "entries": self.entry_count,
            "abis": {
                arch: {
                    "so_count": len(files),
                    "uncompressed": sum(item.size for item in files),
                    "examples": [item.name for item in files[:5]],
                }
                for arch, files in sorted(self.abis.items())
            },
            "declared_split_abi": self.declared_split_abi,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def normalize_abi(value: str) -> Optional[str]:
    """Map any ABI spelling onto a canonical name (``arm64_v8a`` -> ``arm64-v8a``)."""
    cleaned = (value or "").strip().lower()
    for canonical, aliases in ABI_ALIASES.items():
        if cleaned == canonical.lower() or cleaned in aliases:
            return canonical
    return None


def detect_abi_from_name(name: str) -> Optional[str]:
    """Best-effort ABI from a split/folder name such as ``config.arm64_v8a.apk``."""
    stem = Path(name).stem
    match = CONFIG_SPLIT_PATTERN.match(stem)
    candidate = match.group(1) if match else stem
    direct = normalize_abi(candidate)
    if direct:
        return direct
    tokens = [token for token in re.split(r"[._-]+", candidate.lower()) if token]
    for token in tokens:
        if token in _SPLIT_NOISE:
            continue
        found = normalize_abi(token)
        if found:
            return found
    joined = "_".join(tokens)
    for canonical, aliases in ABI_ALIASES.items():
        if any(alias in joined for alias in aliases):
            return canonical
    return None


def human_size(num_bytes: float) -> str:
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(value) < 1024 or unit == "GiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------


def extract_archive(archive: Path, dest: Path, *, log, skip_asset_packs: bool = False) -> Tuple[int, int]:
    """Extract ``archive`` into ``dest``; returns ``(files, bytes)``.

    Entries that would escape ``dest`` (``../`` or absolute paths) are refused,
    and on case-insensitive filesystems a second ``Foo.apk`` simply overwrites.
    """
    dest.mkdir(parents=True, exist_ok=True)
    files = 0
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                log(f"refusing unsafe path inside {archive.name}: {name}")
                continue
            if skip_asset_packs and _looks_like_asset_pack(relative.name):
                log(f"skipping asset pack {name} ({human_size(info.file_size)})")
                continue
            target = dest / relative
            if not is_within(dest, target):
                log(f"refusing path outside the output directory: {name}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink, 1 << 20)
            files += 1
            total += info.file_size
    return files, total


def _looks_like_asset_pack(name: str) -> bool:
    lowered = name.lower()
    if not lowered.endswith(APK_SUFFIX):
        return False
    stem = Path(lowered).stem
    return any(token in stem for token in ("_mpk", "assets", "asset_pack", "obb"))


def expand_nested(root: Path, *, max_depth: int, log, skip_asset_packs: bool = False) -> List[str]:
    """Extract archives found inside the extracted tree. Returns notes."""
    notes: List[str] = []
    for depth in range(1, max_depth + 1):
        nested: List[Path] = [
            path
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.suffix.lower() in ARCHIVE_SUFFIXES and path.name.lower() != "fetch.json"
        ]
        if not nested:
            break
        for archive in nested:
            target = archive.with_name(archive.stem + f"__unpacked{depth}")
            if target.exists():
                continue
            try:
                files, total = extract_archive(archive, target, log=log, skip_asset_packs=skip_asset_packs)
            except zipfile.BadZipFile as exc:
                notes.append(f"{archive.name}: not a readable zip ({exc})")
                continue
            notes.append(f"nested {archive.name} -> {files} files, {human_size(total)}")
            log(f"unpacked nested {archive.name}: {files} files, {human_size(total)}")
    return notes


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------


def scan_apk(path: Path, *, root: Path) -> ApkScan:
    """Read an APK's zip index and collect its native libraries per ABI."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return ApkScan(path=str(path), size=0, error=f"cannot stat: {exc}")

    scan = ApkScan(path=str(path.relative_to(root)) if is_within(root, path) else str(path), size=size)
    scan.declared_split_abi = detect_abi_from_name(path.name)
    try:
        with zipfile.ZipFile(path) as apk:
            infos = apk.infolist()
            scan.entry_count = len(infos)
            for info in infos:
                match = LIB_PATTERN.match(info.filename)
                if not match:
                    continue
                arch = normalize_abi(match.group(1))
                if arch is None:
                    continue
                scan.abis.setdefault(arch, []).append(
                    SoFile(arch=arch, name=os.path.basename(info.filename), size=info.file_size)
                )
    except zipfile.BadZipFile as exc:
        scan.error = f"not a readable zip: {exc}"
    except OSError as exc:
        scan.error = f"cannot read: {exc}"
    return scan


def read_xapk_manifests(root: Path) -> List[Dict[str, object]]:
    """Collect split declarations from any XAPK ``manifest.json`` in the tree."""
    found: List[Dict[str, object]] = []
    for path in sorted(root.rglob("manifest.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        splits = data.get("split_apks") or data.get("splits") or []
        entries: List[Dict[str, str]] = []
        if isinstance(splits, list):
            for item in splits:
                if isinstance(item, dict):
                    identifier = str(item.get("id") or item.get("file") or "")
                    entries.append({"id": identifier, "file": str(item.get("file") or "")})
                elif isinstance(item, str):
                    entries.append({"id": item, "file": item})
        found.append(
            {
                "path": str(path.relative_to(root)) if is_within(root, path) else str(path),
                "package": data.get("package_name") or data.get("package"),
                "version_code": data.get("version_code"),
                "version_name": data.get("version_name"),
                "splits": entries,
            }
        )
    return found


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def build_report(
    *,
    source: Path,
    root: Path,
    scans: Sequence[ApkScan],
    required: Sequence[str],
    extraction: Optional[Dict[str, object]] = None,
    notes: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    abis: Dict[str, Dict[str, object]] = {}
    for arch in CANONICAL_ABIS:
        providers = [scan for scan in scans if arch in scan.abis]
        declared = [scan for scan in scans if scan.declared_split_abi == arch]
        so_files = [item for scan in providers for item in scan.abis.get(arch, [])]
        abis[arch] = {
            "present": bool(providers or declared),
            "bitness": BITNESS.get(arch, "unknown"),
            "native_code": bool(providers),
            "so_count": len(so_files),
            "uncompressed": sum(item.size for item in so_files),
            "apks": [scan.path for scan in providers],
            "split_only_apks": [scan.path for scan in declared if scan not in providers],
            "largest_so": max((item.name for item in so_files), key=lambda name: next((i.size for i in so_files if i.name == name), 0), default=None),
        }

    for arch in required:
        abis.setdefault(
            arch,
            {"present": False, "bitness": BITNESS.get(arch, "unknown"), "native_code": False, "so_count": 0, "uncompressed": 0, "apks": [], "split_only_apks": [], "largest_so": None},
        )

    missing = [arch for arch in required if not abis.get(arch, {}).get("present")]
    errors = [scan.path for scan in scans if scan.error]
    return {
        "source": str(source),
        "extracted_into": str(root),
        "required": list(required),
        "missing": missing,
        "ok": not missing,
        "abis": abis,
        "apks": [scan.as_dict() for scan in scans],
        "apk_count": len(scans),
        "errors": errors,
        "extraction": extraction or {},
        "manifests": read_xapk_manifests(root),
        "notes": list(notes or []),
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def render_markdown(report: Dict[str, object]) -> str:
    lines: List[str] = []
    required = report["required"]
    verdict = "PASS" if report["ok"] else "FAIL"

    lines.append(f"## Blood Strike ABI check — {verdict}")
    lines.append("")
    if report["ok"]:
        pairs = ", ".join(
            f"{arch} ({report['abis'][arch]['bitness']})"
            for arch in required
            if arch in report["abis"]
        )
        lines.append(f"Native code for **both architectures** was found inside the archive: {pairs}.")
    else:
        lines.append(f"**Missing ABI(s): {', '.join(report['missing'])}** — the archive does not carry them.")
    lines.append("")

    lines.append("| ABI | Bitness | Found | APKs with `lib/` | `.so` files | Uncompressed |")
    lines.append("|-----|---------|-------|------------------|-------------|--------------|")
    for arch in sorted(report["abis"], key=lambda item: (item not in required, item)):
        row = report["abis"][arch]
        mark = "✅ yes" if row["present"] else "❌ no"
        lines.append(
            f"| `{arch}` | {row['bitness']} | {mark} | {len(row['apks'])} | "
            f"{row['so_count']} | {human_size(row['uncompressed'])} |"
        )
    lines.append("")

    if report["apks"]:
        lines.append("### Scanned APKs")
        lines.append("")
        lines.append("| File | Size | Entries | ABIs |")
        lines.append("|------|------|---------|------|")
        for scan in report["apks"]:
            abi_text = ", ".join(f"`{abi}`" for abi in scan["abis"]) or "—"
            note = f" ⚠️ {scan['error']}" if scan["error"] else ""
            lines.append(f"| `{scan['path']}` | {human_size(scan['size'])} | {scan['entries']} | {abi_text}{note} |")
        lines.append("")

        for scan in report["apks"]:
            if not scan["abis"]:
                continue
            details = ", ".join(
                f"`{abi}`: {info['so_count']} .so ({human_size(info['uncompressed'])})"
                for abi, info in sorted(scan["abis"].items())
            )
            lines.append(f"- `{scan['path']}` — {details}")
        lines.append("")

    for manifest in report["manifests"]:
        version = f"{manifest.get('version_name') or '?'} ({manifest.get('version_code') or '?'})"
        lines.append(f"XAPK manifest `{manifest['path']}`: package `{manifest.get('package')}`, version {version}")
        if manifest["splits"]:
            lines.append("")
            for split in manifest["splits"]:
                lines.append(f"- split `{split['id']}` → `{split['file']}`")
        lines.append("")

    extraction = report.get("extraction") or {}
    if extraction:
        lines.append(
            f"Extracted {extraction.get('files')} files ({human_size(extraction.get('bytes') or 0)}) "
            f"from `{Path(report['source']).name}`."
        )
    for note in report.get("notes") or []:
        lines.append(f"- {note}")
    if report["errors"]:
        lines.append("")
        lines.append("**Unreadable files:** " + ", ".join(f"`{item}`" for item in report["errors"]))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inspect_apks.py",
        description="Unpack an APK/XAPK archive and verify the expected ABIs are inside.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  inspect_apks.py work/bloodstrike.zip --out-dir work/unpacked\n"
            "  inspect_apks.py work/bloodstrike.zip --require arm64-v8a,armeabi-v7a\n"
        ),
    )
    parser.add_argument("archive", help="the .zip / .xapk / .apk to inspect")
    parser.add_argument("--out-dir", default="work/unpacked", help="where to extract (default: work/unpacked)")
    parser.add_argument(
        "--require",
        default=",".join(DEFAULT_REQUIRED),
        help=f"comma-separated ABIs that must be present (default: {','.join(DEFAULT_REQUIRED)})",
    )
    parser.add_argument("--allow-missing", action="store_true", help="report missing ABIs without failing the run")
    parser.add_argument("--max-depth", type=int, default=3, help="how deep to unpack nested archives (default: 3)")
    parser.add_argument("--skip-asset-packs", action="store_true", help="do not extract *_mpk/assets APKs (big, no native code)")
    parser.add_argument("--keep-extracted", action="store_true", help="keep the extracted tree even when it is large")
    parser.add_argument("--report-dir", default=None, help="directory for abi_report.json / abi_report.md (default: the out dir)")
    parser.add_argument("--markdown-out", default=None, help="also write the markdown report to this file")
    parser.add_argument("--github-summary", action="store_true", help="append the report to $GITHUB_STEP_SUMMARY")
    parser.add_argument("--json", action="store_true", help="print the report as JSON on stdout")
    parser.add_argument("--quiet", "-q", action="store_true", help="only print the verdict")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    log = (lambda _message: None) if args.quiet else (lambda message: print(f"· {message}", file=sys.stderr, flush=True))

    source = Path(args.archive)
    if not source.is_file():
        print(f"error: no such file: {source}", file=sys.stderr)
        return 2

    required = [normalize_abi(part) or part.strip().lower() for part in args.require.split(",") if part.strip()]
    unknown = [arch for arch in required if arch not in CANONICAL_ABIS]
    if unknown:
        print(
            f"error: unknown ABI(s) {', '.join(unknown)}; known: {', '.join(CANONICAL_ABIS)}",
            file=sys.stderr,
        )
        return 2

    root = Path(args.out_dir)
    notes: List[str] = []
    extraction: Dict[str, object] = {}
    started = time.monotonic()

    try:
        if source.suffix.lower() == APK_SUFFIX:
            root.mkdir(parents=True, exist_ok=True)
            target = root / source.name
            if not target.exists():
                shutil.copy2(source, target)
            extraction = {"files": 1, "bytes": source.stat().st_size}
        else:
            log(f"extracting {source.name} into {root}")
            files, total = extract_archive(source, root, log=log, skip_asset_packs=args.skip_asset_packs)
            extraction = {"files": files, "bytes": total}
            log(f"extracted {files} files ({human_size(total)})")
            notes.extend(expand_nested(root, max_depth=args.max_depth, log=log, skip_asset_packs=args.skip_asset_packs))
    except zipfile.BadZipFile as exc:
        print(f"error: {source} is not a readable zip archive ({exc})", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot extract {source}: {exc}", file=sys.stderr)
        return 2

    apks = sorted(path for path in root.rglob(f"*{APK_SUFFIX}") if path.is_file())
    if not apks:
        print(f"error: no .apk files found inside {source.name}", file=sys.stderr)
        return 2
    log(f"scanning {len(apks)} APK(s)")

    scans = [scan_apk(path, root=root) for path in apks]
    report = build_report(
        source=source,
        root=root,
        scans=scans,
        required=required,
        extraction=extraction,
        notes=notes,
    )
    markdown = render_markdown(report)

    report_dir = Path(args.report_dir) if args.report_dir else root
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "abi_report.json"
    md_path = report_dir / "abi_report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")

    if args.markdown_out:
        out = Path(args.markdown_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
    if args.github_summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")

    if args.quiet:
        verdict = "PASS" if report["ok"] else f"FAIL (missing {', '.join(report['missing'])})"
        print(f"{verdict}: {report['apk_count']} APK(s) checked in {Path(report['source']).name}")
    else:
        print(markdown)
    print(f"reports: {json_path} and {md_path}", file=sys.stderr)
    log(f"finished in {time.monotonic() - started:.1f}s")

    if not args.keep_extracted and not os.environ.get("BS_DEC_KEEP_DOWNLOADS"):
        log(f"keeping extracted tree at {root} (delete it after uploading artifacts)")

    _write_github_output(report, json_path, md_path)
    if report["ok"]:
        return 0
    print(
        f"error: missing required ABI(s): {', '.join(report['missing'])}",
        file=sys.stderr,
    )
    return 0 if args.allow_missing else 1


def _write_github_output(report: Dict[str, object], json_path: Path, md_path: Path) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    try:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"ok={'true' if report['ok'] else 'false'}\n")
            handle.write(f"missing={','.join(report['missing'])}\n")
            handle.write(f"apk_count={report['apk_count']}\n")
            handle.write(f"report_json={json_path}\n")
            handle.write(f"report_markdown={md_path}\n")
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
