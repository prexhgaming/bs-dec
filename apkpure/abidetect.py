"""Identify the CPU architectures inside a remote APK/XAPK bundle.

The metadata API is no help here: a 1.1 MB payload for Blood Strike contains the
strings ``arm64``, ``armeabi``, ``v7a`` and ``v8a`` exactly zero times, and the
transformations in field 24 only carry size/md5/kind — so two builds of the same
versionCode look identical in the metadata even though one is the 32-bit and the
other the 64-bit package.

The architecture only exists *inside* the archive: either as ``lib/<abi>/*.so``
members (a single or universal APK) or as ``config.<abi>.apk`` /
``split_config.<abi>.apk`` split names (a bundle). Both are visible in the zip
central directory, so a few ranged reads — typically a few hundred KiB instead of
the whole 600 MB+ file — are enough to answer "does this build contain
arm64-v8a and armeabi-v7a?".

The name analysis is a pure function (:func:`analyse_names`) so it can be tested
without any network access; :func:`probe_bundle_abis` only adds the ranged reads.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from . import transport, variants
from .errors import VariantError
from .zipindex import RemoteZip

LIB_DIR = "lib"
SO_SUFFIX = ".so"
APK_SUFFIX = ".apk"
MAX_SAMPLES = 3

#: Order used when reporting, so arm64 always comes before the 32-bit entries.
ABI_ORDER = ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86")


def bitness_of(abi: str) -> int:
    """64, 32, or 0 when the architecture is unknown."""
    if abi in ("arm64-v8a", "x86_64"):
        return 64
    if abi in ("armeabi-v7a", "armeabi", "x86"):
        return 32
    return 0


def _canonical(segment: str) -> Optional[str]:
    """Canonical ABI name for a path segment such as ``arm64-v8a``/``arm64_v8a``."""
    try:
        return variants.normalize_arch(segment)
    except VariantError:
        return None


@dataclass(frozen=True)
class AbiInfo:
    """What the archive index says about one architecture."""

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
            return variants.normalize_arch(abi) in self.abis
        except VariantError:
            return False

    def missing(self, required: Iterable[str]) -> List[str]:
        wanted: List[str] = []
        for raw in required:
            try:
                wanted.append(variants.normalize_arch(raw))
            except VariantError as exc:
                raise VariantError(str(exc)) from exc
        return [abi for abi in wanted if abi not in self.abis]

    def describe(self) -> str:
        lines: List[str] = []
        if self.abis:
            for abi in self.abi_names:
                lines.append(f"  {self.abis[abi].describe()}")
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


def analyse_names(url: str, size: Optional[int], names: Iterable[str]) -> BundleAbiReport:
    """Work out which ABIs an archive contains from its entry names alone."""
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

        # lib/<abi>/<library>.so — a single (possibly universal) APK.
        if len(parts) >= 3 and lowered[0] == LIB_DIR:
            abi = _canonical(lowered[1])
            if abi is None:
                # e.g. lib/arm64-v8a is fine, but lib/<something else> is not.
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

        abi = variants.detect_abi(parts[-1])
        if abi is not None:
            splits.setdefault(abi, []).append(name)
        elif not variants.is_config_split(name):
            # A base/universal apk carries its ABIs inside itself, not in its name.
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
            "the archive looks like a single apk; its ABIs live inside that apk "
            "(the bundle index cannot show them)"
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


def _order(abi: str) -> Tuple[int, str]:
    try:
        return (ABI_ORDER.index(abi), abi)
    except ValueError:
        return (len(ABI_ORDER), abi)


def probe_bundle_abis(
    url: str,
    *,
    size: Optional[int] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = transport.DEFAULT_TIMEOUT,
    retries: int = 4,
    reader: Optional[Callable[[int, int], bytes]] = None,
    log: Optional[Callable[[str], None]] = None,
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
    names = archive.names()
    report = analyse_names(url, archive.size, names)
    if log is not None:
        log(
            f"read {len(names)} index entries "
            f"({transport.human_size(archive.size)} archive) for ABI detection"
        )
    return report
