"""Which CPU architectures does this archive contain?

APKCombo's app page lists the architectures an app *supports* ("arm64-v8a,
armeabi-v7a, x86_64, x86"), but that is an app-level claim, not a property of one
downloaded file. Two builds of the same version can differ: one is the 32-bit
package, another the 64-bit one, and the page shows the same list for both.

The architecture that actually ships in a file is visible in its zip index:

* ``lib/<abi>/<library>.so`` members — a single or universal APK;
* ``config.<abi>.apk`` / ``split_config.<abi>.apk`` members — an App Bundle
  packaged as ``.xapk``.

Both names are in the central directory, so :func:`probe_abis` needs a few KiB of
ranged reads instead of the whole 600-700 MB file. The name analysis itself
(:func:`analyse_names`) is a pure function and is unit-tested offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import http
from .errors import AbiError
from .zipindex import RemoteZip, ZipEntry

LIB_DIR = "lib"
SO_SUFFIX = ".so"
APK_SUFFIX = ".apk"
CONFIG_PREFIXES = ("config.", "split_config.")
MAX_SAMPLES = 3

#: Reporting order: 64-bit entries first.
ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86", "mips64", "mips")

#: Accepted spellings, mapped onto their canonical name.
ABI_ALIASES = {
    "arm64-v8a": "arm64-v8a",
    "arm64_v8a": "arm64-v8a",
    "arm64": "arm64-v8a",
    "aarch64": "arm64-v8a",
    "armeabi-v7a": "armeabi-v7a",
    "armeabi_v7a": "armeabi-v7a",
    "armv7": "armeabi-v7a",
    "armv7a": "armeabi-v7a",
    "v7a": "armeabi-v7a",
    "armeabi": "armeabi",
    "arm": "armeabi",
    "x86_64": "x86_64",
    "x86-64": "x86_64",
    "x64": "x86_64",
    "amd64": "x86_64",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "mips64": "mips64",
    "mips": "mips",
}

#: Longest first, so "arm64-v8a" wins over "arm64" and "x86_64" over "x86".
_SEARCH_TOKENS = (
    "arm64-v8a",
    "armeabi-v7a",
    "mips64",
    "x86_64",
    "x86-64",
    "armeabi",
    "arm64",
    "mips",
    "x86",
    "aarch64",
    "v7a",
)


def normalize_abi(value: str) -> str:
    """Canonical ABI name for a user-supplied or archive-supplied spelling."""
    key = (value or "").strip().lower()
    if key in ABI_ALIASES:
        return ABI_ALIASES[key]
    raise AbiError(
        f"unknown architecture '{value}' (known: {', '.join(ABI_ORDER)})"
    )


def bitness_of(abi: str) -> int:
    """64, 32, or 0 when the width is unknown."""
    if abi in ("arm64-v8a", "x86_64", "mips64"):
        return 64
    if abi in ("armeabi-v7a", "armeabi", "x86", "mips"):
        return 32
    return 0


def detect_abi_from_name(name: str) -> Optional[str]:
    """Find an ABI inside a file name such as ``config.arm64_v8a.apk``."""
    lowered = (name or "").strip().lower()
    for token in _SEARCH_TOKENS:
        if token in lowered:
            try:
                return normalize_abi(token)
            except AbiError:
                continue
    return None


def is_config_split(name: str) -> bool:
    """True for bundle split members (``config.<x>.apk``)."""
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base.endswith(APK_SUFFIX) and base.startswith(CONFIG_PREFIXES)


def parse_abi_list(value: str) -> List[str]:
    """``"arm64-v8a,armeabi"`` -> canonical names, duplicates removed."""
    if not value:
        return []
    found: List[str] = []
    for chunk in value.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        abi = normalize_abi(chunk)
        if abi not in found:
            found.append(abi)
    return found


@dataclass(frozen=True)
class AbiInfo:
    """What the index says about one architecture."""

    abi: str
    so_files: int = 0
    splits: Tuple[str, ...] = ()
    samples: Tuple[str, ...] = ()

    @property
    def bitness(self) -> int:
        return bitness_of(self.abi)

    def describe(self) -> str:
        bits = f"{self.bitness}-bit" if self.bitness else "unknown width"
        parts = [f"{self.abi} ({bits})"]
        if self.so_files:
            parts.append(f"{self.so_files} native librar{'y' if self.so_files == 1 else 'ies'}")
        if self.splits:
            parts.append(f"{len(self.splits)} split apk(s)")
        return ", ".join(parts)

    def as_dict(self) -> Dict[str, object]:
        return {
            "abi": self.abi,
            "bitness": self.bitness,
            "so_files": self.so_files,
            "splits": list(self.splits),
            "samples": list(self.samples),
        }


@dataclass(frozen=True)
class BundleAbiReport:
    """The architectures found in one archive."""

    url: str
    size: Optional[int]
    entry_count: int
    abis: Dict[str, AbiInfo]
    unlabelled_apks: Tuple[str, ...] = ()
    unknown_arches: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()

    @property
    def abi_names(self) -> List[str]:
        return list(self.abis)

    def has(self, abi: str) -> bool:
        try:
            return normalize_abi(abi) in self.abis
        except AbiError:
            return False

    def missing(self, required: Iterable[str]) -> List[str]:
        wanted = [normalize_abi(item) for item in required]
        return [abi for abi in wanted if abi not in self.abis]

    @property
    def verdict(self) -> str:
        if not self.abis:
            return "no ABI-labelled members"
        return ", ".join(f"{abi} ({self.abis[abi].bitness}-bit)" for abi in self.abi_names)

    def describe(self) -> str:
        lines: List[str] = []
        if self.abis:
            lines.extend(f"  {self.abis[abi].describe()}" for abi in self.abi_names)
        else:
            lines.append("  no native libraries or ABI-labelled splits found")
        if self.unknown_arches:
            lines.append(f"  unrecognised lib directories: {', '.join(self.unknown_arches)}")
        if self.unlabelled_apks:
            lines.append(
                f"  {len(self.unlabelled_apks)} apk(s) without an ABI marker "
                f"(e.g. {', '.join(self.unlabelled_apks[:2])})"
            )
        return "\n".join(lines)

    def as_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "size": self.size,
            "entry_count": self.entry_count,
            "abis": {abi: info.as_dict() for abi, info in self.abis.items()},
            "unlabelled_apks": list(self.unlabelled_apks),
            "unknown_arches": list(self.unknown_arches),
            "notes": list(self.notes),
        }


def _order(abi: str) -> Tuple[int, str]:
    try:
        return (ABI_ORDER.index(abi), abi)
    except ValueError:
        return (len(ABI_ORDER), abi)


def analyse_names(url: str, size: Optional[int], names: Iterable[str]) -> BundleAbiReport:
    """Pure function: work out the ABIs from the archive's member names."""
    so_counts: Dict[str, int] = {}
    samples: Dict[str, List[str]] = {}
    splits: Dict[str, List[str]] = {}
    unlabelled: List[str] = []
    unknown: List[str] = []
    count = 0

    for raw in names:
        count += 1
        name = str(raw).replace("\\", "/")
        parts = [part for part in name.split("/") if part not in ("", ".")]
        if not parts:
            continue
        lowered = [part.lower() for part in parts]

        if len(parts) >= 3 and lowered[0] == LIB_DIR:
            abi = detect_abi_from_name(lowered[1])
            if abi is None:
                if lowered[1] not in unknown:
                    unknown.append(lowered[1])
            elif lowered[-1].endswith(SO_SUFFIX):
                so_counts[abi] = so_counts.get(abi, 0) + 1
                bucket = samples.setdefault(abi, [])
                if len(bucket) < MAX_SAMPLES:
                    bucket.append(parts[-1])
            continue

        if not lowered[-1].endswith(APK_SUFFIX):
            continue
        abi = detect_abi_from_name(lowered[-1])
        if abi is not None:
            splits.setdefault(abi, []).append(name)
        elif not is_config_split(name):
            unlabelled.append(name)

    abis: Dict[str, AbiInfo] = {}
    for abi in sorted(set(so_counts) | set(splits), key=_order):
        abis[abi] = AbiInfo(
            abi=abi,
            so_files=so_counts.get(abi, 0),
            splits=tuple(splits.get(abi, ())),
            samples=tuple(samples.get(abi, ())),
        )

    notes: List[str] = []
    if not abis and unlabelled:
        notes.append(
            "the archive looks like a single apk: its ABIs live inside that apk, "
            "so the index cannot show them"
        )

    return BundleAbiReport(
        url=url,
        size=size,
        entry_count=count,
        abis=abis,
        unlabelled_apks=tuple(unlabelled),
        unknown_arches=tuple(unknown),
        notes=tuple(notes),
    )


def probe_abis(
    url: str,
    *,
    size: Optional[int] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = http.DEFAULT_TIMEOUT,
    retries: int = http.DEFAULT_RETRIES,
    reader: Optional[Callable[[int, int], bytes]] = None,
    log: Optional[http.Log] = None,
) -> BundleAbiReport:
    """Read the archive's index over ranged requests and report its ABIs."""
    archive = RemoteZip(
        url,
        size=size,
        headers=headers,
        timeout=timeout,
        retries=retries,
        reader=reader,
        log=log,
    )
    report = analyse_names(url, archive.size, archive.names())
    if log is not None:
        log(
            f"read {len(archive)} index entries of a "
            f"{http.human_size(archive.size)} archive for ABI detection "
            f"({len(report.abis)} architecture(s) found)"
        )
    return report


@dataclass(frozen=True)
class SplitPlan:
    """The members needed to install one architecture out of a bundle."""

    abi: str
    entries: Tuple[ZipEntry, ...]

    @property
    def total_bytes(self) -> int:
        return sum(entry.uncompressed_size for entry in self.entries)

    @property
    def total_compressed_bytes(self) -> int:
        return sum(entry.compressed_size for entry in self.entries)

    def describe(self) -> str:
        joined = ", ".join(entry.name for entry in self.entries)
        return (
            f"{self.abi}: {len(self.entries)} member(s), "
            f"{http.human_size(self.total_bytes)} uncompressed — {joined}"
        )


def plan_for_abi(entries: Sequence[ZipEntry], abi: str) -> SplitPlan:
    """Pick the base plus the matching splits for one architecture.

    Everything tagged for a *different* ABI is left out, so extracting the 64-bit
    build of a bundle pulls roughly a third of the bytes.
    """
    wanted = normalize_abi(abi)
    chosen: List[ZipEntry] = []
    for entry in entries:
        base = entry.name.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if not base.endswith(APK_SUFFIX):
            continue
        tagged = detect_abi_from_name(base)
        if tagged is not None and tagged != wanted:
            continue  # a split (or an APK) built for another architecture
        chosen.append(entry)
    if not any(detect_abi_from_name(entry.name) == wanted for entry in chosen):
        raise AbiError(
            f"the archive has no members for {wanted}; "
            "run with --detect-abis to list the architectures it does contain"
        )
    return SplitPlan(abi=wanted, entries=tuple(chosen))
