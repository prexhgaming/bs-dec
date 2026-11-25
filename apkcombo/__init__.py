"""APKCombo fetcher: resolve, inspect and download APK/XAPK files without an account.

The package is deliberately dependency-free (Python 3.9+, stdlib only) so it can
run unchanged in GitHub Actions:

``pages``      parse the app and download pages (variants + POST tokens)
``api``        exchange a token for the signed transfer URL of the real file
``http``       urllib plumbing: retries, ranged reads, probing, small parsers
``download``   resumable download with incremental SHA-256 and size checks
``zipindex``   read a remote archive's central directory over ranged requests
``abis``       work out which CPU architectures an archive contains
``cli``        probe / sample / download, ABI gating and split extraction
"""

from __future__ import annotations

from .abis import (
    AbiInfo,
    BundleAbiReport,
    SplitPlan,
    analyse_names,
    normalize_abi,
    parse_abi_list,
    plan_for_abi,
    probe_abis,
)
from .api import RemoteFile, exchange_token, resolve_file, resolve_variant_file
from .download import DownloadResult, Progress, download, hash_file
from .errors import (
    AbiError,
    ApkComboError,
    AppNotFound,
    DownloadError,
    HttpError,
    NetworkError,
    ScrapeError,
    TransferError,
    VariantNotFound,
    VerificationError,
    ZipIndexError,
    describe_exception,
    exit_code_for,
)
from .pages import AppInfo, Variant, fetch_app_info, fetch_variants, pick_variant

__version__ = "1.0.0"

__all__ = [
    "AbiError",
    "AbiInfo",
    "AppInfo",
    "AppNotFound",
    "ApkComboError",
    "BundleAbiReport",
    "DownloadError",
    "DownloadResult",
    "HttpError",
    "NetworkError",
    "Progress",
    "RemoteFile",
    "ScrapeError",
    "SplitPlan",
    "TransferError",
    "Variant",
    "VariantNotFound",
    "VerificationError",
    "ZipIndexError",
    "__version__",
    "analyse_names",
    "describe_exception",
    "download",
    "exchange_token",
    "exit_code_for",
    "fetch_app_info",
    "fetch_variants",
    "hash_file",
    "normalize_abi",
    "parse_abi_list",
    "pick_variant",
    "plan_for_abi",
    "probe_abis",
    "resolve_file",
    "resolve_variant_file",
]
