"""The APKCombo download flow: exchange a page token for a real file URL.

The public flow, with no account and no captcha, is short:

1. ``GET /<slug>/<package>/download/apk`` renders one form per variant, each with
   a hidden field ``soqplay_download_file=<token>`` (:mod:`apkcombo.pages`).
2. ``POST`` that token back to the same URL. The answer is a ``303`` whose
   ``Location`` is a Cloudflare-Worker URL, ``apkcombo-transfer…workers.dev/file/<opaque>``.
3. ``GET`` that worker URL: it is the file itself (``Content-Disposition`` carries
   the name, ``Accept-Ranges: bytes`` lets us range-read its zip index).

Two things to remember: the token is single-use-ish and the worker URL is signed
for a short window (the cookie APKCombo sets lives 30 minutes), so both must be
re-resolved for every run instead of being cached.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional
from urllib.parse import urlsplit

from . import http
from .errors import TransferError
from .pages import Variant

TRANSFER_HOST_HINTS = ("apkcombo", "workers.dev", "download")
REDIRECT_STATUSES = (301, 302, 303, 307, 308)
ZIP_MAGIC = b"PK"


@dataclass(frozen=True)
class RemoteFile:
    """A file on APKCombo's transfer host, ready to be downloaded or ranged."""

    url: str
    variant: Variant
    filename: str
    size: Optional[int] = None
    content_type: str = ""
    accept_ranges: bool = False
    head: bytes = b""
    source_token: str = ""
    extra_headers: Dict[str, str] = field(default_factory=dict)

    @property
    def size_text(self) -> str:
        return http.human_size(self.size)

    def as_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "filename": self.filename,
            "size": self.size,
            "content_type": self.content_type,
            "accept_ranges": self.accept_ranges,
            "variant": self.variant.kind,
        }


def exchange_token(
    download_url: str,
    token: str,
    *,
    timeout: float = http.DEFAULT_TIMEOUT,
    retries: int = http.DEFAULT_RETRIES,
    log: Optional[http.Log] = None,
) -> str:
    """POST a page token and return the file URL from the redirect."""
    logger = log or (lambda _message: None)
    status, headers, body = http.post_form(
        download_url, {"soqplay_download_file": token}, timeout=timeout, retries=retries, log=log
    )
    location = headers.get("location") or ""
    if status in REDIRECT_STATUSES and location:
        logger(f"token accepted: {urlsplit(location).netloc or location[:60]}")
        return location
    if status in REDIRECT_STATUSES and not location:
        raise TransferError("the download endpoint redirected without a Location header")
    snippet = re.sub(rb"\s+", b" ", body[:200]).decode("utf-8", "replace")
    if status == 200:
        raise TransferError(
            "the token was rejected (HTTP 200 instead of a redirect) — "
            "the download page must be fetched again for a fresh token"
            + (f": {snippet}" if snippet else "")
        )
    raise TransferError(f"unexpected answer from the download endpoint: HTTP {status} {snippet[:120]}")


def resolve_file(
    download_url: str,
    variant: Variant,
    *,
    probe_bytes: int = 4096,
    timeout: float = http.DEFAULT_TIMEOUT,
    retries: int = http.DEFAULT_RETRIES,
    log: Optional[http.Log] = None,
) -> RemoteFile:
    """Token -> worker URL -> a :class:`RemoteFile` with name, size and ranges."""
    logger = log or (lambda _message: None)
    url = exchange_token(download_url, variant.token, timeout=timeout, retries=retries, log=log)

    host = urlsplit(url).netloc
    if not any(hint in host for hint in TRANSFER_HOST_HINTS):
        logger(f"note: the transfer host is unusual ({host}), continuing anyway")

    info, head = http.probe(
        url,
        sample=probe_bytes,
        headers={"Referer": f"https://{urlsplit(download_url).netloc}/"},
        timeout=timeout,
        retries=retries,
        log=log,
    )
    if head and not head.startswith(ZIP_MAGIC):
        raise TransferError(
            f"the transfer URL returned {info.content_type or 'unknown content'} instead of an "
            f"archive (first bytes: {head[:16]!r})"
        )
    filename = info.filename or f"{variant.kind.lower()}.apk"
    logger(
        f"{variant.kind} variant {variant.size_text or info.size_text}: "
        f"{filename} ({info.size_text}, ranges {'on' if info.accept_ranges else 'off'})"
    )
    return RemoteFile(
        url=url,
        variant=variant,
        filename=filename,
        size=info.size,
        content_type=info.content_type,
        accept_ranges=info.accept_ranges,
        head=head,
        source_token=variant.token,
        extra_headers={"Referer": "https://apkcombo.com/"},
    )


def resolve_variant_file(
    app,
    variant_kind: str = "auto",
    *,
    timeout: float = http.DEFAULT_TIMEOUT,
    retries: int = http.DEFAULT_RETRIES,
    log: Optional[http.Log] = None,
):
    """Convenience: app info -> variants -> the chosen :class:`RemoteFile`."""
    from . import pages  # local import keeps the module import graph flat

    download_url, variants = pages.fetch_variants(
        app, timeout=timeout, retries=retries, log=log
    )
    variant = pages.pick_variant(variants, variant_kind)
    return resolve_file(
        download_url, variant, timeout=timeout, retries=retries, log=log
    )
