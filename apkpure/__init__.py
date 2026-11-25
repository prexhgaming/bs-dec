"""Package entry point: public helpers for scripting against APKPure."""

from __future__ import annotations

from .api import (
    AppVersion,
    DownloadDescriptor,
    cdn_url,
    fetch_metadata,
    fetch_versions,
    metadata_url,
    parse_versions,
    select_version,
)
from .downloader import DownloadResult, FileHashes, Progress, download, hash_file
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
)
from .variants import (
    ALL,
    ARCH_CHOICES,
    CANONICAL_ARCHES,
    UNIVERSAL,
    Plan,
    PlannedFile,
    normalize_arch,
    plan_bundle,
    plan_splits,
    plan_universal,
)
from .zipindex import RemoteZip, ZipEntry

__all__ = [
    "ALL",
    "ARCH_CHOICES",
    "AppVersion",
    "ApkPureError",
    "CANONICAL_ARCHES",
    "DownloadDescriptor",
    "DownloadError",
    "DownloadResult",
    "FileHashes",
    "HttpError",
    "MetadataError",
    "NetworkError",
    "Plan",
    "PlannedFile",
    "Progress",
    "RemoteZip",
    "UNIVERSAL",
    "VariantError",
    "VerificationError",
    "VersionNotFound",
    "ZipEntry",
    "ZipIndexError",
    "cdn_url",
    "download",
    "fetch_metadata",
    "fetch_versions",
    "hash_file",
    "metadata_url",
    "normalize_arch",
    "parse_versions",
    "plan_bundle",
    "plan_splits",
    "plan_universal",
    "select_version",
]

__version__ = "1.0.0"
