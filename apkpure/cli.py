"""Command line interface for the APKPure fetcher.

Three modes share one resolution path:

``probe``     read headers / the remote zip index only — no payload written
``sample``    pull the first N bytes of every planned file to prove the pipeline
``download``  perform the real transfer (this is what CI runs)

``--json`` keeps stdout machine-readable (human output moves to stderr), which is
what the GitHub Actions workflow consumes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__, abidetect, api, transport, variants
from .downloader import Progress, download
from .errors import (
    ApkPureError,
    DownloadError,
    HttpError,
    MetadataError,
    NetworkError,
    VariantError,
    VerificationError,
    VersionNotFound,
    ZipIndexError,
    describe_exception,
)
from .variants import ALL, ARCH_CHOICES, UNIVERSAL, Plan, PlannedFile

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_VERIFICATION = 3

DEFAULT_PACKAGE = "com.netease.newspike"
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ZIP_MAGIC_WITH_HEADER = (b"PK\x03\x04", b"PK\x05\x06")

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"


class Reporter:
    """Human-readable output plus optional structured output on stdout."""

    def __init__(self, *, quiet: bool = False, verbose: bool = False, json_mode: bool = False) -> None:
        self.quiet = quiet
        self.verbose_enabled = verbose
        self.json_mode = json_mode
        self.human = sys.stderr if json_mode else sys.stdout
        self._color = _supports_color(self.human) and not json_mode

    def out(self, text: str = "") -> None:
        self._write(self.human, text)

    def log(self, message: str) -> None:
        if not self.quiet:
            self._write(sys.stderr, f"{self._paint(DIM, '·')} {message}")

    def debug(self, message: str) -> None:
        if self.verbose_enabled and not self.quiet:
            self._write(sys.stderr, f"{self._paint(DIM, 'debug:')} {message}")

    def warn(self, message: str) -> None:
        self._write(sys.stderr, f"{self._paint(YELLOW, 'warning:')} {message}")

    def error(self, message: str) -> None:
        self._write(sys.stderr, f"{self._paint(RED, 'error:')} {message}")

    def section(self, title: str) -> None:
        if self.quiet or self.json_mode:
            return
        self.out("")
        self.out(self._paint(BOLD, title))
        self.out(self._paint(DIM, "-" * min(len(title) + 8, 78)))

    def field(self, label: str, value: object, width: int = 16) -> None:
        if self.quiet or self.json_mode:
            return
        self.out(f"  {label.ljust(width)} {value}")

    def ok(self, message: str) -> None:
        if self.quiet:
            return
        mark = self._paint(GREEN, "ok")
        self._write(self.human, f"{mark} {message}")

    def _paint(self, color: str, text: str) -> str:
        if not self._color:
            return text
        return f"{color}{text}{RESET}"

    @staticmethod
    def _write(stream, text: str) -> None:
        try:
            print(text, file=stream, flush=True)
        except (OSError, ValueError):
            pass


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fetch_apk.py",
        description="Resolve and download APKs / per-architecture split APKs from APKPure.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  # what would be downloaded (no payload transferred)\n"
            "  python fetch_apk.py --version-code 169\n"
            "  # 64-bit / 32-bit split APKs out of the XAPK bundle\n"
            "  python fetch_apk.py --version-code 169 --arch arm64-v8a --with-base --mode sample\n"
            "  python fetch_apk.py --version-code 169 --arch armeabi-v7a --variant splits\n"
            "  # real transfers (what CI runs)\n"
            "  python fetch_apk.py --version-code 169 --arch universal --mode download --verify\n"
            "  python fetch_apk.py --version-code 169 --arch all --variant xapk --mode download\n"
        ),
    )
    parser.add_argument("--package", "-p", default=DEFAULT_PACKAGE, help="Android package name")
    parser.add_argument("--version-code", type=int, default=None, help="versionCode to fetch (default: newest)")
    parser.add_argument("--version-name", default=None, help="versionName to fetch, e.g. 1.003.650026")
    parser.add_argument(
        "--arch",
        "-a",
        default=UNIVERSAL,
        help=f"architecture: {', '.join(ARCH_CHOICES)} (aliases: arm64, 32, 64, x64 ...)",
    )
    parser.add_argument(
        "--variant",
        choices=("auto", "apk", "xapk", "splits"),
        default="auto",
        help=(
            "auto (apk for --arch universal, splits otherwise), apk = standalone universal APK, "
            "xapk = the complete bundle as one file, splits = pull selected parts of the bundle"
        ),
    )
    parser.add_argument(
        "--with-base",
        action="store_true",
        help="also fetch the base APK when pulling splits (automatic with --arch all)",
    )
    parser.add_argument(
        "--with-assets",
        action="store_true",
        help="also fetch bulk asset packs (e.g. base_mpk.apk, often hundreds of MB)",
    )
    parser.add_argument(
        "--mode",
        choices=("probe", "sample", "download"),
        default="probe",
        help="probe = headers only, sample = first --sample-bytes of each file, download = full transfer",
    )
    parser.add_argument("--sample-bytes", type=int, default=262144, help="bytes to pull in --mode sample")
    parser.add_argument("--out-dir", default=None, help="output directory (default: downloads/<pkg>/<version>/<arch>)")
    parser.add_argument("--filename", default=None, help="override the output file name (single-file plans only)")
    parser.add_argument("--resume", action="store_true", help="resume from an existing .part file")
    parser.add_argument("--verify", action="store_true", help="enforce the metadata size and sha1")
    parser.add_argument("--no-crc", action="store_true", help="skip crc32 verification of extracted splits")
    parser.add_argument("--timeout", type=float, default=transport.DEFAULT_TIMEOUT, help="per-request timeout (s)")
    parser.add_argument("--retries", type=int, default=4, help="retries per request")
    parser.add_argument("--lang", default="en-US", help="metadata language")
    parser.add_argument("--country", default="US", help="metadata country")
    parser.add_argument("--api-abi", default="arm64-v8a", help="ABI advertised to the metadata API")
    parser.add_argument("--no-api", action="store_true", help="skip the metadata API and use --version-code as given")
    parser.add_argument("--list-versions", action="store_true", help="list available versions and exit")
    parser.add_argument("--list-variants", action="store_true", help="list architectures/splits of the version and exit")
    parser.add_argument(
        "--detect-abis",
        action="store_true",
        help="report which ABIs the archive contains (zip index only, no payload download)",
    )
    parser.add_argument(
        "--build",
        type=int,
        default=1,
        help="which build of the version to use, 1-based: APKPure lists several builds per versionCode (see --list-versions)",
    )
    parser.add_argument(
        "--require-abi",
        default=None,
        help="comma-separated ABIs the archive must contain, e.g. arm64-v8a,armeabi-v7a (fails with exit 3)",
    )
    parser.add_argument(
        "--abi-scan",
        action="store_true",
        help="probe every build of the version name (or versionCode) and report which ABIs each carries",
    )
    parser.add_argument(
        "--scan-limit",
        type=int,
        default=12,
        help="how many builds --abi-scan probes at most (default: 12)",
    )
    parser.add_argument("--server-filename", action="store_true", help="keep the file name the CDN suggests")
    parser.add_argument("--manifest", default=None, help="path of the JSON manifest to write")
    parser.add_argument("--no-manifest", action="store_true", help="do not write a JSON manifest")
    parser.add_argument("--json", action="store_true", help="print the machine-readable result on stdout")
    parser.add_argument("--quiet", "-q", action="store_true", help="suppress progress and logs")
    parser.add_argument("--verbose", "-v", action="store_true", help="extra diagnostics")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    reporter = Reporter(quiet=args.quiet, verbose=args.verbose, json_mode=args.json)
    started = time.monotonic()
    try:
        return run(args, reporter, started)
    except KeyboardInterrupt:
        reporter.error("interrupted")
        return 130
    except VerificationError as exc:
        reporter.error(str(exc))
        return EXIT_VERIFICATION
    except (VersionNotFound, VariantError, MetadataError, ZipIndexError) as exc:
        reporter.error(str(exc))
        return EXIT_FAILURE
    except (HttpError, NetworkError, DownloadError) as exc:
        reporter.error(str(exc))
        return EXIT_FAILURE
    except ApkPureError as exc:
        reporter.error(str(exc))
        return EXIT_FAILURE


def run(args, reporter: Reporter, started: float) -> int:
    package = args.package
    mode = args.mode

    reporter.section(f"APKPure fetcher — {package}")

    version = None
    if not args.no_api:
        reporter.log(f"querying metadata API ({args.lang})")
        versions = api.fetch_versions(
            package,
            lang=args.lang,
            country=args.country,
            abi=args.api_abi,
            timeout=args.timeout,
            retries=args.retries,
        )
        reporter.debug(f"metadata contains {len(versions)} build entries")
        if args.list_versions:
            return show_versions(versions, args, reporter)
        version = api.select_version(
            versions, version_code=args.version_code, version_name=args.version_name
        )
        version = pick_build(versions, version, args)
    else:
        if args.version_code is None:
            raise MetadataError("--no-api needs an explicit --version-code")
        reporter.log("metadata API disabled, using the given version code verbatim")

    if getattr(args, "abi_scan", False):
        if args.no_api:
            raise MetadataError("--abi-scan reads the metadata API, so it cannot be used with --no-api")
        return scan_version_abis(package, versions, args, reporter)

    if version is not None:
        report_version(version, reporter)
    else:
        reporter.field("version code", args.version_code)

    arch = variants.normalize_arch(args.arch)
    plan = build_plan(package, version, arch, args, reporter)
    report_plan(plan, args, reporter)

    if args.require_abi:
        enforce_required_abis(plan, package, version, args, reporter)

    if args.list_variants or args.detect_abis:
        if args.detect_abis:
            detected = show_bundle_abis(package, version, args, reporter)
            if args.json:
                print(json.dumps(detected, indent=2))
        if args.list_variants:
            show_variants(package, version, args, reporter)
        return EXIT_OK

    if args.filename:
        if len(plan.files) != 1:
            raise ApkPureError("--filename only works when the plan contains exactly one file")
        single = plan.files[0]
        plan.files[0] = PlannedFile(
            role=single.role,
            filename=args.filename,
            url=single.url,
            size=single.size,
            sha1=single.sha1,
            entry=single.entry,
            source=single.source,
        )

    out_dir = Path(args.out_dir) if args.out_dir else default_out_dir(package, version, plan)
    out_dir.mkdir(parents=True, exist_ok=True)

    if mode == "probe":
        manifest = {"mode": "probe", "files": [], "transferred_bytes": 0}
        reporter.ok(
            f"plan resolved: {len(plan.files)} file(s), {transport.human_size(plan.total_size)}"
        )
        reporter.log("mode=probe transferred no payload (headers and zip index only)")
    elif mode == "sample":
        manifest = run_sample(plan, out_dir, args, reporter)
    else:
        manifest = run_download(plan, out_dir, args, reporter)

    result = build_manifest(package, version, plan, mode, out_dir, manifest, started)
    write_manifest(result, args, reporter, out_dir)
    if args.json:
        print(json.dumps(result, indent=2))

    return EXIT_OK


# --------------------------------------------------------------------------
# resolution
# --------------------------------------------------------------------------


def pick_build(versions, version, args):
    """Honor ``--build``: one versionCode usually has two or more builds.

    The metadata keeps every build of a versionCode (see
    :func:`apkpure.api.parse_versions`), so the caller can ask for the 64-bit
    bundle even when it is not the first entry in the payload.
    """
    index = getattr(args, "build", 1) or 1
    builds = api.builds_for(versions, version.version_code)
    if len(builds) <= 1 and index == 1:
        return version
    if index < 1 or index > len(builds):
        raise VersionNotFound(
            f"build {index} does not exist for versionCode {version.version_code} "
            f"({len(builds)} build(s); run --list-versions to see them)"
        )
    return builds[index - 1]


def bundle_target(package: str, version, args) -> Tuple[str, Optional[int]]:
    """The archive worth inspecting: the signed bundle URL when there is one."""
    descriptor = getattr(version, "descriptor", None)
    if descriptor is not None:
        return descriptor.url, descriptor.size
    code = version.version_code if version is not None else args.version_code
    return api.cdn_url(package, "XAPK", code), None


def show_bundle_abis(
    package: str,
    version,
    args,
    reporter: Reporter,
    url: Optional[str] = None,
    size: Optional[int] = None,
) -> Dict[str, object]:
    """Report the ABIs inside the archive by reading its index only."""
    if url is None:
        url, size = bundle_target(package, version, args)
    report = abidetect.probe_bundle_abis(
        url,
        size=size,
        headers=transport.request_headers(),
        timeout=args.timeout,
        retries=args.retries,
        log=reporter.debug,
    )
    reporter.section("Bundle ABIs (zip index only, no payload downloaded)")
    reporter.field("archive", _shorten_url(url))
    if report.size:
        reporter.field("archive size", transport.human_size(report.size))
    reporter.field("index entries", report.entry_count)
    reporter.field("abis", ", ".join(report.abi_names) or "none detected")
    reporter.out("")
    reporter.out(report.describe())
    for note in report.notes:
        reporter.log(note)
    return report.as_dict()


def enforce_required_abis(plan: Plan, package: str, version, args, reporter: Reporter) -> None:
    """Fail with the verification exit code when a required ABI is missing."""
    wanted = [item.strip() for item in args.require_abi.split(",") if item.strip()]
    url = plan.bundle_url or bundle_target(package, version, args)[0]
    report = abidetect.probe_bundle_abis(
        url,
        headers=transport.request_headers(),
        timeout=args.timeout,
        retries=args.retries,
        log=reporter.debug,
    )
    missing = report.missing(wanted)
    reporter.field("required abis", ", ".join(wanted))
    reporter.field("abis in archive", ", ".join(report.abi_names) or "none detected")
    if missing:
        raise VerificationError(
            f"{', '.join(missing)} missing from {_shorten_url(url)} "
            f"(found: {', '.join(report.abi_names) or 'no native libraries'})"
        )
    reporter.ok(f"required abis present: {', '.join(wanted)}")


def scan_version_abis(package: str, versions: List, args, reporter: Reporter, probe=None) -> int:
    """Probe every build of one version name and say what each one contains.

    A version *number* is published under several versionCodes (1.003.650026 is
    codes 169, 168 and 166), and the architecture is not visible in the metadata,
    so the only honest answer to "does this version have a 64-bit build?" is to
    read each build's zip index — a few KiB each, no payload download.
    """
    probe = probe or abidetect.probe_bundle_abis

    if args.version_name:
        label = args.version_name
        targets = api.versions_by_name(versions, args.version_name)
    elif args.version_code is not None:
        label = f"versionCode {args.version_code}"
        targets = api.builds_for(versions, args.version_code)
    else:
        label = versions[0].version_name
        targets = api.versions_by_name(versions, label)
    if not targets:
        raise VersionNotFound(f"no build on APKPure matches {label}")
    targets = targets[: max(1, args.scan_limit)]

    reporter.section(f"ABI scan — {label} ({len(targets)} build(s))")
    rows: List[Dict[str, object]] = []
    for version in targets:
        url, size = bundle_target(package, version, args)
        try:
            report = probe(
                url,
                size=size,
                headers=transport.request_headers(),
                timeout=args.timeout,
                retries=args.retries,
                log=reporter.debug,
            )
            abis = report.abi_names
            detail = ", ".join(abis) if abis else "none detected"
        except ApkPureError as exc:
            abis, detail = [], f"probe failed: {describe_exception(exc)}"
        rows.append(
            {
                "version_code": version.version_code,
                "build_size": version.build_size,
                "md5": version.apk_md5,
                "abis": abis,
                "detail": detail,
            }
        )
        size_text = transport.human_size(version.build_size) if version.build_size > 0 else "size n/a"
        reporter.out(f" {str(version.version_code).rjust(8)}  {size_text:>11}  {detail}")

    abis_by_code: Dict[str, List[int]] = {}
    for row in rows:
        for abi in row["abis"]:
            abis_by_code.setdefault(abi, []).append(int(row["version_code"]))

    reporter.section("Which builds carry which ABI")
    if not abis_by_code:
        reporter.warn("no ABI-labelled split was found in any probed build")
    for abi in sorted(abis_by_code, key=_abi_sort_key):
        codes = ", ".join(str(code) for code in sorted(set(abis_by_code[abi]), reverse=True))
        reporter.field(abi, f"versionCode(s) {codes}")

    if args.require_abi:
        required = _abis_from_arg(args.require_abi)
        missing = [abi for abi in required if abi not in abis_by_code]
        if missing:
            raise VerificationError(
                f"no build of {label} contains {', '.join(missing)} "
                f"(abis found across all builds: {', '.join(sorted(abis_by_code)) or 'none'})"
            )
        reporter.ok(f"required abis present in {label}: {', '.join(required)}")

    if args.json:
        print(
            json.dumps(
                {
                    "version_name": label,
                    "builds": rows,
                    "abis_by_version_code": {abi: sorted({*codes}) for abi, codes in abis_by_code.items()},
                },
                indent=2,
            )
        )
    return EXIT_OK


def _abis_from_arg(value: str) -> List[str]:
    out: List[str] = []
    for item in value.split(","):
        item = item.strip()
        if item:
            out.append(variants.normalize_arch(item))
    return out


def _abi_sort_key(abi: str) -> Tuple[int, str]:
    order = list(abidetect.ABI_ORDER)
    return (order.index(abi) if abi in order else len(order), abi)


def build_plan(package: str, version, arch: str, args, reporter: Reporter) -> Plan:
    """Turn the requested arch/variant into a concrete list of files."""
    variant = args.variant
    if variant == "auto":
        # "all" means every architecture split, not the whole bundle: --variant xapk
        # is the explicit way to ask for the (much larger) complete archive.
        variant = "apk" if arch == UNIVERSAL else "splits"

    if variant == "apk":
        if arch not in (UNIVERSAL, ALL):
            reporter.warn(
                f"--variant apk ships every ABI in one file, so --arch {arch} cannot be honored; "
                f"use --variant splits for a per-architecture build"
            )
        return variants.plan_universal(
            package,
            version,
            headers=transport.request_headers(),
            timeout=args.timeout,
            server_filename=args.server_filename,
        )

    if variant == "xapk":
        if arch not in (UNIVERSAL, ALL):
            raise VariantError(
                f"--variant xapk downloads the whole bundle; use --variant splits to extract "
                f"just {arch} from it"
            )
        return variants.plan_bundle(
            package,
            version,
            headers=transport.request_headers(),
            timeout=args.timeout,
        )

    return variants.plan_splits(
        package,
        version,
        arch,
        headers=transport.request_headers(),
        timeout=args.timeout,
        with_base=args.with_base,
        with_assets=args.with_assets,
        log=reporter.log,
    )


def default_out_dir(package: str, version, plan: Plan) -> Path:
    label = version.version_name if version is not None else "unknown-version"
    return Path("downloads") / package / label / plan.arch


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def report_version(version, reporter: Reporter) -> None:
    reporter.section("Version")
    reporter.field("app", version.app_name)
    reporter.field("version name", version.version_name)
    reporter.field("version code", version.version_code)
    if version.developer:
        reporter.field("developer", version.developer)
    if version.updated:
        reporter.field("updated", version.updated)
    if version.apk_sha1:
        reporter.field("apk sha1", version.apk_sha1)
    if version.descriptor is not None:
        reporter.field(
            "bundle",
            f"{version.descriptor.kind} "
            f"{transport.human_size(version.descriptor.size)} "
            f"(signature valid until {version.descriptor.generated or 'n/a'})",
        )


def report_plan(plan: Plan, args, reporter: Reporter) -> None:
    reporter.section("Plan")
    reporter.field("arch", plan.arch)
    reporter.field("variant", plan.variant)
    if plan.bundle_url:
        reporter.field("bundle", _shorten_url(plan.bundle_url))
    if plan.available_arches:
        reporter.field("bundle abis", ", ".join(plan.available_arches))
    reporter.field("files", len(plan.files))
    reporter.field("total size", transport.human_size(plan.total_size))
    for note in plan.notes:
        reporter.debug(note)
    reporter.out("")
    for planned in plan.files:
        reporter.out(f"  {planned.describe()}")
    if args.mode == "sample":
        reporter.out("")
        reporter.log(
            f"mode=sample transfers only {transport.human_size(args.sample_bytes)} per file "
            f"(no full download on this machine)"
        )


def show_versions(versions, args, reporter: Reporter) -> int:
    """List every build: one versionCode normally has a 32-bit and a 64-bit one."""
    grouped: Dict[int, List[object]] = {}
    for version in versions:
        grouped.setdefault(version.version_code, []).append(version)

    reporter.section(f"Builds on APKPure ({len(versions)} builds, {len(grouped)} versionCodes)")
    for code in sorted(grouped, reverse=True):
        builds = grouped[code]
        head = builds[0]
        updated = (head.updated or "")[:10]
        default = " *" if args.version_code is None and code == max(grouped) else "  "
        reporter.out(
            f" {default} {str(code).rjust(9)}  {head.version_name:<18} {updated}  "
            f"{len(builds)} build(s)"
        )
        for index, build in enumerate(builds, start=1):
            descriptor = build.descriptor
            size = transport.human_size(descriptor.size) if descriptor and descriptor.size else "size n/a"
            kind = descriptor.kind if descriptor else "APK"
            reporter.out(
                f"          build {index}: {size:>11}  {kind:<4} "
                f"md5 {(build.apk_md5 or 'n/a')[:10]}"
            )
    reporter.log("* marks the default version; --build N picks a build, --detect-abis names its ABIs")
    if args.json:
        print(json.dumps([version.as_dict() for version in versions], indent=2))
    return EXIT_OK


def show_variants(package: str, version, args, reporter: Reporter) -> None:
    """Inspect the bundle index and list what can be pulled from it."""
    reporter.section("Available variants")
    try:
        local = variants.plan_splits(
            package,
            version,
            ALL,
            headers=transport.request_headers(),
            timeout=args.timeout,
            with_base=True,
            with_assets=True,
            log=reporter.debug,
        )
    except (VariantError, ZipIndexError) as exc:
        reporter.warn(f"no split bundle available ({describe_exception(exc)})")
        return

    reporter.field("bundle abis", ", ".join(local.available_arches) or "none")
    reporter.out("")
    for entry in local.bundle_entries:
        reporter.out(f"  {variants.describe_entry(entry)}")
    reporter.out("")
    reporter.field("universal apk", "always available with --arch universal")
    reporter.log("use --arch <abi> --variant splits to fetch a single architecture")


def _shorten_url(url: str, limit: int = 96) -> str:
    if len(url) <= limit:
        return url
    head = url[: limit // 2 - 2]
    tail = url[-limit // 2 + 1 :]
    return f"{head}...{tail}"


# --------------------------------------------------------------------------
# actions
# --------------------------------------------------------------------------


def run_sample(plan: Plan, out_dir: Path, args, reporter: Reporter) -> Dict[str, object]:
    """Fetch only the first ``--sample-bytes`` of every planned file."""
    reporter.section("Sample")
    results: List[Dict[str, object]] = []
    transferred = 0
    headers = transport.request_headers()

    for planned in plan.files:
        span = sample_range(planned, args.sample_bytes)
        reporter.log(f"reading bytes {span[0]}-{span[1]} of {planned.filename}")
        data = transport.retry_call(
            lambda p=planned, s=span: transport.read_range(
                p.url, s[0], s[1], headers=headers, timeout=args.timeout
            ),
            attempts=max(args.retries, 1),
            on_error=lambda attempt, exc: reporter.log(
                f"sample read failed ({describe_exception(exc)}), retry #{attempt}"
            ),
        )
        target = out_dir / f"{planned.filename}.sample"
        target.write_bytes(data)
        transferred += len(data)
        looks_like_zip = data[:4] in ZIP_MAGIC
        entry: Dict[str, object] = {
            "role": planned.role,
            "filename": planned.filename,
            "sample_path": str(target),
            "sample_bytes": len(data),
            "remote_offset": span[0],
            "zip_magic": looks_like_zip,
            "expected_size": planned.size,
        }
        results.append(entry)
        verdict = f"{len(data)} bytes -> {target}"
        if looks_like_zip:
            reporter.ok(f"{planned.filename}: {verdict} (valid zip header)")
        else:
            reporter.warn(f"{planned.filename}: {verdict} (no PK zip header — inspect)")
        if planned.size:
            reporter.debug(
                f"full file would be {transport.human_size(planned.size)}; "
                f"sampled {len(data)} bytes of it"
            )

    reporter.section("Sample summary")
    reporter.field("files sampled", len(results))
    reporter.field("bytes received", transport.human_size(transferred))
    reporter.log("nothing was fully downloaded; run --mode download for the complete files")
    return {"mode": "sample", "files": results, "transferred_bytes": transferred}


def sample_range(planned: PlannedFile, sample_bytes: int) -> Tuple[int, int]:
    """Inclusive remote byte range to sample for ``planned``."""
    size = max(int(sample_bytes), 1)
    if planned.entry is not None and planned.source is not None:
        start = planned.source.data_offset(planned.entry)
        last = start + min(size, planned.entry.compressed_size) - 1
        return start, last
    return 0, size - 1


def run_download(plan: Plan, out_dir: Path, args, reporter: Reporter) -> Dict[str, object]:
    """Perform the full transfer for every planned file."""
    reporter.section("Download")
    results: List[Dict[str, object]] = []
    transferred = 0
    headers = transport.request_headers()

    for planned in plan.files:
        destination = out_dir / planned.filename
        progress = Progress(
            planned.filename,
            total=planned.size,
            enabled=not args.quiet,
        )
        progress.start()
        entry: Dict[str, object] = {
            "role": planned.role,
            "filename": planned.filename,
            "path": str(destination),
            "url": planned.url,
            "expected_size": planned.size,
        }
        if planned.entry is not None and planned.source is not None:
            result = planned.source.extract(
                planned.entry,
                destination,
                resume=args.resume,
                verify_crc=not args.no_crc,
                progress=progress,
                timeout=args.timeout,
                retries=args.retries,
                log=reporter.log,
            )
            entry["from_xapk_entry"] = planned.entry.name
            entry["expected_crc32"] = f"{planned.entry.crc32:08x}"
        else:
            result = download(
                planned.url,
                destination,
                headers=headers,
                expected_size=planned.size,
                expected_sha1=planned.sha1 if args.verify else None,
                resume=args.resume,
                timeout=args.timeout,
                retries=args.retries,
                progress=progress,
                log=reporter.log,
            )

        hashes = result.hashes
        entry["attempts"] = result.attempts
        entry["resumed_from"] = result.resumed_from
        entry["elapsed_seconds"] = round(result.elapsed, 3)
        entry.update(hashes.as_dict())
        entry["sha1_matches_metadata"] = bool(
            planned.sha1 and planned.sha1.lower() == hashes.sha1.lower()
        )
        results.append(entry)
        transferred += hashes.size
        reporter.ok(f"{planned.filename} — {transport.human_size(hashes.size)}, sha1 {hashes.sha1[:16]}…")
        reporter.debug(f"sha256 {hashes.sha256}")

    reporter.section("Download summary")
    reporter.field("files written", len(results))
    reporter.field("total bytes", transport.human_size(transferred))
    reporter.field("directory", str(out_dir))
    return {"mode": "download", "files": results, "transferred_bytes": transferred}


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------


def build_manifest(
    package: str,
    version,
    plan: Plan,
    mode: str,
    out_dir: Path,
    payload: Dict[str, object],
    started: float,
) -> Dict[str, object]:
    manifest: Dict[str, object] = {
        "tool": "apkpure-fetch",
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_seconds": round(time.monotonic() - started, 3),
        "package": package,
        "mode": mode,
        "arch": plan.arch,
        "variant": plan.variant,
        "out_dir": str(out_dir),
        "plan": plan.as_dict(),
        "result": payload,
    }
    if version is not None:
        manifest["app"] = version.as_dict()
    return manifest


def write_manifest(manifest: Dict[str, object], args, reporter: Reporter, out_dir: Path) -> None:
    if args.no_manifest:
        return
    target = Path(args.manifest) if args.manifest else out_dir / "manifest.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    reporter.log(f"manifest written to {target}")


if __name__ == "__main__":  # pragma: no cover - convenience for direct runs
    sys.exit(main())
