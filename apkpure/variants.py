"""Architecture and variant planning.

APKPure hosts two shapes of release per version:

* a **universal APK** served from ``d.apkpure.com/b/APK/<pkg>`` — one file that
  runs anywhere, with native libraries for every ABI inside it;
* an **XAPK bundle** served from ``d.apkpure.com/b/XAPK/<pkg>`` — a zip holding
  the base APK plus per-architecture ``config.<abi>.apk`` splits, the way Google
  Play delivers a game.

The CDN quietly ignores ``arch=``/``abi=`` query parameters (the same bytes come
back for every value), so the only honest way to get a 32-bit or 64-bit build is
to read the bundle's zip index and pull the matching split out of it. That is
what this module plans; :mod:`apkpure.cli` executes the plan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import transport
from .api import AppVersion, cdn_url
from .errors import ApkPureError, VariantError
from .zipindex import RemoteZip, ZipEntry

UNIVERSAL = "universal"
ALL = "all"
CANONICAL_ARCHES: Tuple[str, ...] = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
ARCH_CHOICES: Tuple[str, ...] = (UNIVERSAL,) + CANONICAL_ARCHES + (ALL,)

#: Accepted spellings for every architecture, normalized to APKPure/Android ABI names.
ARCH_ALIASES: Dict[str, str] = {
    "universal": UNIVERSAL,
    "all": ALL,
    "*": UNIVERSAL,
    "any": UNIVERSAL,
    "arm64": "arm64-v8a",
    "arm64-v8a": "arm64-v8a",
    "arm64_v8a": "arm64-v8a",
    "arm64v8a": "arm64-v8a",
    "aarch64": "arm64-v8a",
    "v8a": "arm64-v8a",
    "arm": "armeabi-v7a",
    "arm32": "armeabi-v7a",
    "armv7": "armeabi-v7a",
    "armv7a": "armeabi-v7a",
    "armeabi": "armeabi-v7a",
    "armeabi-v7a": "armeabi-v7a",
    "armeabi_v7a": "armeabi-v7a",
    "v7a": "armeabi-v7a",
    "32": "armeabi-v7a",
    "64": "arm64-v8a",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "x86_32": "x86",
    "x86_64": "x86_64",
    "x86-64": "x86_64",
    "x64": "x86_64",
    "amd64": "x86_64",
}

#: Substrings used to recognize an architecture inside split filenames.
ABI_TOKENS: Dict[str, Tuple[str, ...]] = {
    "arm64-v8a": ("arm64_v8a", "arm64-v8a", "arm64"),
    "armeabi-v7a": ("armeabi_v7a", "armeabi-v7a", "armeabi"),
    "x86_64": ("x86_64", "x86-64"),
    "x86": ("x86",),
}

CONFIG_PATTERN = re.compile(r"^config\.([A-Za-z0-9_.\-]+?)(?:\.apk)?$")


def normalize_arch(value: str) -> str:
    """Map any accepted spelling to a canonical architecture name."""
    key = (value or "").strip().lower()
    if key in ARCH_ALIASES:
        return ARCH_ALIASES[key]
    raise VariantError(
        f"unknown architecture {value!r}; use one of: {', '.join(ARCH_CHOICES)} "
        f"(aliases such as 'arm64', '32', 'x64' work too)"
    )


def detect_abi(name: str) -> Optional[str]:
    """Return the architecture encoded in a split filename, if any."""
    lowered = name.lower()
    if not lowered.endswith(".apk"):
        return None
    stem = lowered[: -len(".apk")]
    # Longest tokens first: "x86_64" must win over "x86", "armeabi_v7a" over "arm".
    candidates: List[Tuple[str, str]] = []
    for arch, tokens in ABI_TOKENS.items():
        for token in tokens:
            candidates.append((token, arch))
    for token, arch in sorted(candidates, key=lambda item: len(item[0]), reverse=True):
        if stem.endswith("." + token) or stem == token:
            return arch
    match = CONFIG_PATTERN.match(lowered)
    if match:
        tail = match.group(1)
        for token, arch in sorted(candidates, key=lambda item: len(item[0]), reverse=True):
            if tail.endswith(token):
                return arch
    return None


def is_config_split(name: str) -> bool:
    """True for split APKs named ``config.<something>.apk``."""
    return name.lower().startswith("config.") and name.lower().endswith(".apk")


def is_asset_split(name: str) -> bool:
    """True for bulk asset packs (``base_mpk.apk`` and friends)."""
    lowered = name.lower()
    return lowered.endswith(".apk") and "_mpk" in lowered


@dataclass(frozen=True)
class PlannedFile:
    """One file the CLI should end up with on disk."""

    role: str
    filename: str
    url: str
    size: Optional[int] = None
    sha1: Optional[str] = None
    entry: Optional[ZipEntry] = None
    source: Optional[RemoteZip] = None

    @property
    def is_split(self) -> bool:
        return self.entry is not None

    def describe(self) -> str:
        origin = "xapk-entry" if self.entry is not None else "http"
        return (
            f"{self.filename}  [{self.role}, {origin}, "
            f"{transport.human_size(self.size)}]"
        )

    def as_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "role": self.role,
            "filename": self.filename,
            "url": self.url,
            "size": self.size,
            "sha1": self.sha1,
            "from_xapk_entry": self.entry.name if self.entry else None,
        }
        if self.entry is not None:
            data["entry"] = {
                "name": self.entry.name,
                "crc32": f"{self.entry.crc32:08x}",
                "compressed_size": self.entry.compressed_size,
                "uncompressed_size": self.entry.uncompressed_size,
                "offset": self.entry.local_header_offset,
            }
        return data


@dataclass
class Plan:
    """A resolved list of files plus the context needed to explain it."""

    package: str
    arch: str
    variant: str
    files: List[PlannedFile] = field(default_factory=list)
    version: Optional[AppVersion] = None
    bundle_url: Optional[str] = None
    available_arches: List[str] = field(default_factory=list)
    bundle_entries: List[ZipEntry] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def total_size(self) -> Optional[int]:
        if any(item.size is None for item in self.files):
            return None
        return sum(item.size or 0 for item in self.files)

    def as_dict(self) -> Dict[str, object]:
        return {
            "package": self.package,
            "arch": self.arch,
            "variant": self.variant,
            "bundle_url": self.bundle_url,
            "available_arches": self.available_arches,
            "total_size": self.total_size,
            "files": [item.as_dict() for item in self.files],
            "notes": self.notes,
        }


def default_universal_name(package: str, version: Optional[AppVersion]) -> str:
    """Deterministic file name for a universal APK."""
    if version is not None:
        return f"{package}_{version.version_name}_universal.apk"
    return f"{package}_universal.apk"


def default_bundle_name(package: str, version: Optional[AppVersion]) -> str:
    """Deterministic file name for a whole XAPK bundle."""
    if version is not None:
        return f"{package}_{version.version_name}.xapk"
    return f"{package}.xapk"


def plan_universal(
    package: str,
    version: Optional[AppVersion],
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = transport.DEFAULT_TIMEOUT,
    server_filename: bool = False,
) -> Plan:
    """Plan the single universal APK download."""
    url = cdn_url(package, "APK", version.version_code if version else None)
    info = transport.probe(url, headers=headers, timeout=timeout)
    if not info.is_zip_based:
        raise VariantError(
            _missing_variant_message(
                package,
                version,
                "standalone APK",
                info,
                headers=headers,
                timeout=timeout,
            )
        )
    filename = default_universal_name(package, version)
    if server_filename and info.filename:
        filename = info.filename
    notes = [
        "universal APK: one file, all ABIs inside (no per-architecture choice)",
    ]
    if info.supports_ranges:
        notes.append("CDN supports range requests, so --resume and sampling work")
    return Plan(
        package=package,
        arch=UNIVERSAL,
        variant="apk",
        files=[
            PlannedFile(
                role="apk",
                filename=filename,
                url=url,
                size=info.size,
                sha1=version.apk_sha1 if version else None,
            )
        ],
        version=version,
        notes=notes,
    )


def plan_bundle(
    package: str,
    version: Optional[AppVersion],
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = transport.DEFAULT_TIMEOUT,
    log: Optional[Callable[[str], None]] = None,
) -> Plan:
    """Plan the whole XAPK bundle as one file."""
    url = _bundle_url(package, version)
    info = transport.probe(url, headers=headers, timeout=timeout)
    if not info.is_zip_based:
        raise VariantError(
            _missing_variant_message(
                package,
                version,
                "XAPK bundle",
                info,
                headers=headers,
                timeout=timeout,
            )
        )
    sha1 = version.descriptor.sha1 if version and version.descriptor else None
    declared = version.descriptor.size if version and version.descriptor else None
    notes = ["XAPK bundle: base APK plus every per-ABI split in one file"]
    if declared and info.size and declared != info.size:
        notes.append(
            f"metadata declares {transport.human_size(declared)}, CDN reports "
            f"{transport.human_size(info.size)}"
        )
    return Plan(
        package=package,
        arch=ALL,
        variant="xapk",
        files=[
            PlannedFile(
                role="xapk",
                filename=default_bundle_name(package, version),
                url=url,
                size=info.size or declared,
                sha1=sha1,
            )
        ],
        version=version,
        bundle_url=url,
        notes=notes,
    )


def plan_splits(
    package: str,
    version: Optional[AppVersion],
    arch: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = transport.DEFAULT_TIMEOUT,
    with_base: bool = False,
    with_assets: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> Plan:
    """Plan a targeted pull of split APKs from the remote XAPK bundle.

    ``arch`` selects ``config.<abi>.apk``; :data:`ALL` plans base + every split.
    """
    url = _bundle_url(package, version)
    sink = log or (lambda _message: None)
    bundle = RemoteZip(url, headers=headers, timeout=timeout, log=sink)
    entries = bundle.entries
    sink(f"bundle index: {len(entries)} entries")

    base_entry = _find_base(package, entries)
    asset_entries = [entry for entry in entries if is_asset_split(entry.name)]
    configs: Dict[str, ZipEntry] = {}
    for entry in entries:
        if not is_config_split(entry.name):
            continue
        abi = detect_abi(entry.name)
        if abi:
            configs[abi] = entry

    available = [item for item in CANONICAL_ARCHES if item in configs]
    notes: List[str] = [
        f"bundle: {transport.human_size(bundle.size)} contains "
        f"{len(configs)} architecture split(s)"
    ]
    if not configs:
        notes.append("this bundle has no config.<abi>.apk splits; use --arch universal")
    others = [
        entry.name
        for entry in entries
        if is_config_split(entry.name) and detect_abi(entry.name) is None
    ]
    if others:
        preview = ", ".join(others[:3]) + ("..." if len(others) > 3 else "")
        notes.append(
            f"locale/density splits also exist ({preview}); a complete installable set needs "
            f"them, so use --variant xapk if you want everything"
        )

    selected: List[ZipEntry] = []
    if arch == ALL:
        selected = [entry for _, entry in sorted(configs.items())]
    else:
        entry = configs.get(arch)
        if entry is None:
            raise VariantError(
                f"architecture {arch} is not in this bundle; available: "
                f"{', '.join(available) if available else 'none'}"
            )
        selected = [entry]

    files: List[PlannedFile] = []
    wants_base = with_base or arch == ALL
    if wants_base and base_entry is not None:
        files.append(_planned(package, version, base_entry, url, bundle, "base"))
    if with_assets:
        for entry in asset_entries:
            files.append(_planned(package, version, entry, url, bundle, "assets"))
    for entry in selected:
        files.append(_planned(package, version, entry, url, bundle, "split"))

    if not files:
        raise VariantError("nothing was selected; check --arch / --with-base")

    return Plan(
        package=package,
        arch=arch,
        variant="xapk",
        files=files,
        version=version,
        bundle_url=url,
        available_arches=available,
        bundle_entries=entries,
        notes=notes,
    )


def _planned(
    package: str,
    version: Optional[AppVersion],
    entry: ZipEntry,
    url: str,
    bundle: RemoteZip,
    role: str,
) -> PlannedFile:
    return PlannedFile(
        role=role,
        filename=entry.name,
        url=url,
        size=entry.uncompressed_size,
        entry=entry,
        source=bundle,
    )


def _bundle_url(package: str, version: Optional[AppVersion]) -> str:
    """Prefer the signed descriptor URL, fall back to the stable CDN URL."""
    if version is not None and version.descriptor is not None:
        if (version.descriptor.kind or "").upper() == "XAPK" and version.descriptor.url:
            return version.descriptor.url
    return cdn_url(package, "XAPK", version.version_code if version else None)


def bundle_abis(
    package: str,
    version: Optional[AppVersion],
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = transport.DEFAULT_TIMEOUT,
) -> List[str]:
    """Architectures offered by a version's XAPK bundle (best effort).

    Used for diagnostics: when a release has no standalone APK, naming the ABIs
    that *are* available turns a dead end into a one-line fix.
    """
    try:
        bundle = RemoteZip(_bundle_url(package, version), headers=headers, timeout=timeout)
        found = {
            detect_abi(entry.name)
            for entry in bundle.entries
            if is_config_split(entry.name)
        }
    except ApkPureError:
        return []
    return [arch for arch in CANONICAL_ARCHES if arch in found]


def _missing_variant_message(
    package: str,
    version: Optional[AppVersion],
    wanted: str,
    info: transport.RemoteFile,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = transport.DEFAULT_TIMEOUT,
) -> str:
    """Explain a missing file and suggest what to try instead."""
    label = f"{package} {version.label}" if version is not None else package
    served = info.content_type or "an unknown content type"
    parts = [f"no {wanted} for {label} (APKPure served {served}"]
    if "apkpure.com" in info.url and not info.url.endswith((".apk", ".xapk")):
        parts.append(f", redirecting to its web page {info.url}")
    parts.append(")")

    abis = bundle_abis(package, version, headers=headers, timeout=timeout)
    if abis:
        preferred = "arm64-v8a" if "arm64-v8a" in abis else abis[0]
        parts.append(
            f". This release is split-only and ships these ABIs: {', '.join(abis)} — "
            f"try --arch {preferred} --variant splits, or --arch all"
        )
    else:
        parts.append(". No downloadable variant was found for this version")
    return "".join(parts)



def _find_base(package: str, entries: Sequence[ZipEntry]) -> Optional[ZipEntry]:
    by_name = {entry.name: entry for entry in entries}
    expected = f"{package}.apk"
    if expected in by_name:
        return by_name[expected]
    for entry in entries:
        lowered = entry.name.lower()
        if lowered.endswith(".apk") and "config." not in lowered and "_mpk" not in lowered:
            return entry
    return None


def describe_entry(entry: ZipEntry) -> str:
    """One-line description of a bundle entry for ``--list-variants``."""
    abi = detect_abi(entry.name)
    tag = f"abi={abi}" if abi else ("assets" if is_asset_split(entry.name) else "other")
    return f"{entry.name:44} {transport.human_size(entry.uncompressed_size):>10}  {tag}"
