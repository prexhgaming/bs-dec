"""Exception hierarchy for the APKPure tooling.

Every failure raised by this package derives from :class:`ApkPureError`, so a
caller (the CLI, a GitHub Actions step, a test) can catch one type and still
tell the classes of failure apart through the dedicated subclasses.
"""

from __future__ import annotations

from typing import Optional


class ApkPureError(Exception):
    """Base class for every error raised by this package."""


class MetadataError(ApkPureError):
    """The APKPure metadata API answered with something unusable."""


class VersionNotFound(MetadataError):
    """The requested package/version is not offered by APKPure."""


class HttpError(ApkPureError):
    """A request came back with an unexpected HTTP status."""

    def __init__(self, status: int, url: str, detail: str = "") -> None:
        self.status = status
        self.url = url
        self.detail = detail
        message = f"HTTP {status} for {url}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


class NetworkError(ApkPureError):
    """A transport-level failure (DNS, TLS, timeout, reset connection)."""


class DownloadError(ApkPureError):
    """A transfer started but could not be completed correctly."""


class VerificationError(ApkPureError):
    """The downloaded bytes do not match the expected size or hash."""


class VariantError(ApkPureError):
    """The requested architecture/variant does not exist for this version."""


class ZipIndexError(ApkPureError):
    """The remote zip index could not be read or parsed."""


def describe_exception(exc: BaseException) -> Optional[str]:
    """Return a short human-readable reason for an exception, if it has one."""
    detail = getattr(exc, "detail", None)
    if isinstance(detail, str) and detail:
        return detail
    reason = getattr(exc, "reason", None)
    if reason is not None:
        return str(reason)
    text = str(exc).strip()
    return text or None
