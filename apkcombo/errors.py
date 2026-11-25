"""Exception types shared by the APKCombo package.

Every failure the tool can hit maps to one of these, so the CLI can turn any of
them into a message plus a stable exit code instead of a traceback.
"""

from __future__ import annotations

from typing import Optional


class ApkComboError(Exception):
    """Base class for every error this package raises."""


class NetworkError(ApkComboError):
    """The connection failed, timed out, or was cut short."""


class HttpError(ApkComboError):
    """The server answered with an unexpected status."""

    def __init__(self, status: int, url: str, detail: str = "") -> None:
        self.status = status
        self.url = url
        self.detail = detail
        message = f"HTTP {status} for {url}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


class ScrapeError(ApkComboError):
    """A page did not contain what the tool needs (it changed, or it is not an app page)."""


class AppNotFound(ApkComboError):
    """No APKCombo page was found for the requested package or slug."""


class VariantNotFound(ApkComboError):
    """The download page offers no variant matching the request."""


class TransferError(ApkComboError):
    """The download token could not be exchanged for a file URL."""


class DownloadError(ApkComboError):
    """The transfer failed after every retry."""


class VerificationError(ApkComboError):
    """A downloaded file does not match its expected size or checksum."""


class ZipIndexError(ApkComboError):
    """The remote zip index could not be read."""


class AbiError(ApkComboError):
    """An architecture name is unknown, or a required ABI is missing."""


def describe_exception(exc: BaseException) -> str:
    """One short line for logs, keeping the subtype visible."""
    if isinstance(exc, HttpError):
        return str(exc)
    name = type(exc).__name__
    text = str(exc).strip()
    if not text:
        return name
    return f"{name}: {text}"


def exit_code_for(exc: BaseException) -> int:
    """Stable exit codes: 1 general, 2 usage/not found, 3 verification."""
    if isinstance(exc, VerificationError):
        return 3
    if isinstance(exc, (AbiError, VariantNotFound, AppNotFound)):
        return 2
    return 1


def _summary(exc: Optional[BaseException]) -> str:
    return "" if exc is None else describe_exception(exc)
