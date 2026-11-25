"""Command line interface: probe, sample, download — plus ABI inspection.

Modes exist because the archive is 650-700 MB and the interesting questions
("is the transfer URL alive?", "which ABIs are in it?") can all be answered from
a few KiB of ranged reads:

``--mode probe``    resolve everything, download nothing but a 4 KiB header
``--mode sample``   pull the first few MiB to prove the bytes really flow
``--mode download`` full resumable download, size check, SHA-256, ABI gate
``--detect-abis``   read the zip index over ranged requests and list the ABIs
``--extract-abi``   write only the base + that architecture's splits out of a bundle
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import abis, api, download, http, pages
from .errors import AbiError, ApkComboError, VerificationError, describe_exception, exit_code_for
from .zipindex import RemoteZip, local_file_reader

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_VERIFICATION = 3
DEFAULT_SAMPLE_BYTES = 4 << 20
ZIP_MAGIC = b"PK"


class Reporter:
    """Tiny stderr/stdout writer so ``--json`` and ``--quiet`` behave."""

    def __init__(self, *, quiet: bool = False, verbose: bool = False, stream=None) -> None:
        self.quiet = quiet
        self.verbose = verbose
        self.stream = stream or sys.stderr

    def out(self, message: str = "") -> None:
        if not self.quiet:
            print(message)
            sys.stdout.flush()

    def err(self, message: str) -> None:
        print(message, file=self.stream)
        self.stream.flush()

    def note(self, message: str) -> None:
        if not self.quiet:
            self.err(message)

    def debug(self, message: str) -> None:
        if self.verbose:
            self.err(f"  .. {message}")


def _hashes_available(text: str) -> bool:
    return bool(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fetch_apk.py",
        description=(
            "Resolve and download an APK/XAPK from APKCombo's public download flow, "
            "and check which CPU architectures the archive really contains."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python fetch_apk.py -p com.netease.newspike --mode probe --detect-abis\n"
            "  python fetch_apk.py -p com.netease.newspike --mode sample\n"
            "  python fetch_apk.py -p com.netease.newspike --mode download --require-abi arm64-v8a,armeabi-v7a\n"
            "  python fetch_apk.py -p com.netease.newspike --variant auto --extract-abi arm64-v8a --mode download\n"
        ),
    )
    parser.add_argument("-p", "--package", required=True, help="application id, e.g. com.netease.newspike")
    parser.add_argument("--slug", help="APKCombo page slug (skips the search step), e.g. blood-strike-x-dj-snake")
    parser.add_argument(
        "--variant",
        default="auto",
        choices=("auto", "apk", "xapk"),
        help="which offered file to use; auto prefers the XAPK bundle (default: auto)",
    )
    parser.add_argument(
        "--mode",
        default="probe",
        choices=("probe", "sample", "download"),
        help="probe resolves only, sample pulls a few MiB, download gets the whole file",
    )
    parser.add_argument("--out-dir", default="downloads", help="where files are written (default: downloads)")
    parser.add_argument("--list-variants", action="store_true", help="only print the variants the page offers")
    parser.add_argument("--detect-abis", action="store_true", help="read the zip index and report the architectures")
    parser.add_argument("--require-abi", help="comma separated ABIs the archive must contain (fails if missing)")
    parser.add_argument("--extract-abi", help="after a download, also write the base + that ABI's splits")
    parser.add_argument("--expect-sha256", help="fail unless the downloaded file has this sha256")
    parser.add_argument("--use-page-sha256", action="store_true", help="verify against the SHA-256 published on the page")
    parser.add_argument("--sample-bytes", type=int, default=DEFAULT_SAMPLE_BYTES, help="bytes to pull in sample mode")
    parser.add_argument("--timeout", type=float, default=http.DEFAULT_TIMEOUT, help="per-request timeout in seconds")
    parser.add_argument("--retries", type=int, default=http.DEFAULT_RETRIES, help="attempts per request")
    parser.add_argument("--json", action="store_true", help="print a JSON report to stdout")
    parser.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors on stderr")
    parser.add_argument("-v", "--verbose", action="store_true", help="extra progress detail on stderr")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    reporter = Reporter(quiet=args.quiet, verbose=args.verbose)
    if args.json and (args.quiet or args.verbose):
        args.quiet = True
    try:
        return run(args, reporter)
    except ApkComboError as exc:
        reporter.err(f"error: {describe_exception(exc)}")
        return exit_code_for(exc)
    except KeyboardInterrupt:
        reporter.err("interrupted")
        return EXIT_FAILURE
    except BrokenPipeError:
        return EXIT_FAILURE


def run(args, reporter: Reporter) -> int:
    started = time.monotonic()
    infos: Dict[str, object] = {}

    reporter.note(f"package {args.package}" + (f" (slug {args.slug})" if args.slug else ""))
    app = pages.fetch_app_info(
        args.package,
        slug=args.slug,
        timeout=args.timeout,
        retries=args.retries,
        log=reporter.debug,
    )
    infos["app"] = app.as_dict()
    reporter.note(
        f"app page: {app.name or app.package} v{app.version or '?'} "
        f"{app.size_text or 'unknown size'}"
        + (f", architectures: {', '.join(app.archs)}" if app.archs else "")
    )

    download_url, variants = pages.fetch_variants(
        app, timeout=args.timeout, retries=args.retries, log=reporter.debug
    )
    infos["variants"] = [variant.as_dict() for variant in variants]
    reporter.out("variants offered by APKCombo:")
    for index, variant in enumerate(variants, 1):
        marker = "*" if variant.primary else " "
        details = " · ".join(
            bit for bit in (variant.size_text, variant.android, ", ".join(variant.archs)) if bit
        )
        reporter.out(f"  {marker} {index}. {variant.kind:<4} {details}")

    if args.list_variants:
        return _finish(infos, args, reporter, started)

    variant = pages.pick_variant(variants, args.variant)
    reporter.note(f"chosen variant: {variant.kind} ({variant.size_text or 'size unknown'})")

    remote = api.resolve_file(
        download_url, variant, timeout=args.timeout, retries=args.retries, log=reporter.debug
    )
    infos["file"] = remote.as_dict()
    reporter.out(
        f"file: {remote.filename} — {remote.size_text} "
        f"({'resumable' if remote.accept_ranges else 'no range support'})"
    )

    if args.mode == "probe":
        if args.detect_abis or args.require_abi:
            report = abis.probe_abis(
                remote.url,
                size=remote.size,
                headers=remote.extra_headers,
                timeout=args.timeout,
                retries=args.retries,
                log=reporter.debug,
            )
            _report_abis(report, args, reporter, infos, app)
        return _finish(infos, args, reporter, started)

    if args.mode == "sample":
        sample_path = _sample(remote, args, reporter)
        infos["sample"] = {"path": str(sample_path), "bytes": args.sample_bytes}
        if args.detect_abis or args.require_abi:
            report = abis.probe_abis(
                remote.url,
                size=remote.size,
                headers=remote.extra_headers,
                timeout=args.timeout,
                retries=args.retries,
                log=reporter.debug,
            )
            _report_abis(report, args, reporter, infos, app)
        return _finish(infos, args, reporter, started)

    # --mode download
    out_dir = Path(args.out_dir).expanduser()
    destination = out_dir / http.sanitize_filename(remote.filename)
    expected_sha = args.expect_sha256
    if not expected_sha and args.use_page_sha256 and app.sha256:
        expected_sha = app.sha256
        reporter.note(f"verifying against the SHA-256 published on the page: {expected_sha[:16]}…")
    if expected_sha and variant.kind.lower() == "xapk" and not args.expect_sha256:
        reporter.err(
            "warning: the page's SHA-256 describes the page's main file; "
            "the XAPK may differ, so a mismatch is possible"
        )

    progress = download.Progress(total=remote.size, prefix="", stream=sys.stderr)
    result = download.download(
        remote.url,
        destination,
        expected_size=remote.size,
        expected_sha256=expected_sha,
        headers=remote.extra_headers,
        timeout=max(args.timeout, 60.0),
        retries=max(args.retries, 3),
        progress=progress,
        log=reporter.note,
    )
    progress.finish()
    infos["download"] = result.as_dict()
    reporter.out(
        f"downloaded {result.path.name} — {http.human_size(result.size)} "
        f"in {result.elapsed:.1f}s ({http.human_size(result.speed)}/s)"
    )
    reporter.out(f"sha256 {result.sha256}")

    report = _inspect_local(result.path, reporter)
    infos["abis"] = report.as_dict()
    _report_abis(report, args, reporter, infos, app)

    if args.extract_abi:
        _extract_abi(result.path, args, reporter, infos)

    return _finish(infos, args, reporter, started)


def _sample(remote: api.RemoteFile, args, reporter: Reporter) -> Path:
    """Pull the first few MiB so a broken transfer URL is caught cheaply."""
    wanted = min(args.sample_bytes, remote.size or args.sample_bytes)
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / (http.sanitize_filename(remote.filename) + ".sample")
    reporter.note(f"sampling the first {http.human_size(wanted)}")
    started = time.monotonic()
    payload = http.read_range(
        remote.url,
        0,
        wanted - 1,
        headers=remote.extra_headers,
        timeout=args.timeout,
        retries=args.retries,
        log=reporter.debug,
    )
    elapsed = max(time.monotonic() - started, 1e-6)
    target.write_bytes(payload)
    if not payload.startswith(ZIP_MAGIC):
        raise VerificationError(
            f"the sample does not start with 'PK' — it is not an archive (first bytes: {payload[:16]!r})"
        )
    reporter.out(
        f"sample ok: {http.human_size(len(payload))} in {elapsed:.1f}s "
        f"({http.human_size(len(payload) / elapsed)}/s) -> {target}"
    )
    return target


def _inspect_local(path: Path, reporter: Reporter) -> abis.BundleAbiReport:
    """Read the ABI table straight out of the downloaded file."""
    reader = local_file_reader(path)
    try:
        archive = RemoteZip(str(path), size=path.stat().st_size, reader=reader, log=reporter.debug)
        report = abis.analyse_names(str(path), archive.size, archive.names())
    finally:
        close = getattr(reader, "close", None)
        if close is not None:
            close()
    reporter.note(f"index of {path.name}: {report.entry_count} entries read from disk")
    return report


def _report_abis(report: abis.BundleAbiReport, args, reporter: Reporter, infos: Dict, app) -> None:
    reporter.out("architectures in this file (from the zip index):")
    reporter.out(report.describe())
    reporter.out(f"verdict: {report.verdict}")
    if app is not None and app.archs:
        declared = ", ".join(app.archs)
        if report.abis and not all(report.has(abi) for abi in app.archs):
            reporter.out(
                f"note: the app page advertises {declared}, but this file does not contain "
                f"all of them — the page lists what the app supports, not what one file ships"
            )
        else:
            reporter.out(f"the app page advertises: {declared}")
    for note in report.notes:
        reporter.note(f"note: {note}")

    required = abis.parse_abi_list(args.require_abi or "")
    if not required:
        return
    missing = report.missing(required)
    infos["required_abis"] = [abi for abi in required]
    if missing:
        raise AbiError(
            "the archive is missing the required architecture(s): "
            + ", ".join(missing)
            + f" (it contains: {', '.join(report.abi_names) or 'none'})"
        )
    reporter.out(f"required architectures present: {', '.join(required)}")


def _extract_abi(path: Path, args, reporter: Reporter, infos: Dict) -> None:
    """Write the base + the matching splits of one architecture."""
    wanted = abis.normalize_abi(args.extract_abi)
    out_dir = Path(args.out_dir).expanduser() / f"{path.stem}-{wanted}"
    reader = local_file_reader(path)
    try:
        archive = RemoteZip(str(path), size=path.stat().st_size, reader=reader, log=reporter.debug)
        plan = abis.plan_for_abi(archive.entries, wanted)
        reporter.out(f"extracting {plan.describe()}")
        written: List[Dict[str, object]] = []
        for entry in plan.entries:
            target, size, digest = archive.extract(entry, out_dir / entry.name, log=reporter.note)
            written.append({"path": str(target), "size": size, "sha256": digest})
            reporter.out(f"  {target.name} — {http.human_size(size)}")
        infos["extracted"] = {"abi": wanted, "dir": str(out_dir), "files": written}
    finally:
        close = getattr(reader, "close", None)
        if close is not None:
            close()


def _finish(infos: Dict, args, reporter: Reporter, started: float) -> int:
    if args.json:
        infos["elapsed_seconds"] = round(time.monotonic() - started, 3)
        print(json.dumps(infos, indent=2))
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - module entry
    raise SystemExit(main())
