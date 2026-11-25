"""HTTP plumbing: redirect handling, ranged reads, probing and header parsing.

Only the standard library is used, which is what makes the whole tool trivially
installable in CI (``python fetch_apk.py`` and nothing else).
"""

from __future__ import annotations

import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple, TypeVar

from .errors import ApkPureError, HttpError, NetworkError, describe_exception

# The mobile UA is what makes d.apkpure.com hand out a direct CDN link instead
# of an HTML interstitial page.
BROWSER_UA = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)
API_UA = "APKPure/3.19.35 (Aegon)"

DEFAULT_TIMEOUT = 60.0
MAX_REDIRECTS = 8
MAX_FILENAME_LENGTH = 180

T = TypeVar("T")

_REDIRECT_CODES = (301, 302, 303, 307, 308)


class _RedirectSeen(Exception):
    """Internal control-flow signal: a redirect was returned, stop there.

    urllib follows redirects transparently, which hides the signed CDN URL we
    want to log (and reuse). Intercepting the first hop keeps the chain visible.
    """

    def __init__(self, status: int, location: str) -> None:
        super().__init__(location)
        self.status = status
        self.location = location


class _StopAtFirstRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise _RedirectSeen(code, newurl)


_OPENER = urllib.request.build_opener(_StopAtFirstRedirect)


@dataclass(frozen=True)
class Response:
    """Metadata of an established response (headers only, body not consumed)."""

    url: str
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    redirects: Tuple[str, ...] = ()

    def header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.headers.get(name.lower(), default)

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip()

    @property
    def content_length(self) -> Optional[int]:
        return _as_int(self.header("content-length"))

    @property
    def content_range(self) -> Optional[Tuple[int, int, int]]:
        return parse_content_range(self.header("content-range"))

    @property
    def total_size(self) -> Optional[int]:
        """Full size of the resource, taken from Content-Range or Content-Length."""
        span = self.content_range
        if span is not None:
            return span[2]
        return self.content_length

    @property
    def filename(self) -> Optional[str]:
        return parse_content_disposition(self.header("content-disposition"))

    @property
    def supports_ranges(self) -> bool:
        accept = (self.header("accept-ranges") or "").lower()
        if accept == "bytes":
            return True
        if accept == "none":
            return False
        return self.content_range is not None


@dataclass(frozen=True)
class RemoteFile:
    """What a lightweight probe learned about a remote file."""

    url: str
    status: int
    size: Optional[int]
    content_type: str
    filename: Optional[str]
    supports_ranges: bool
    magic: bytes
    redirects: Tuple[str, ...] = ()

    @property
    def is_zip_based(self) -> bool:
        return self.magic[:4] in (b"PK\x03\x04", b"PK\x05\x06")


def request_headers(
    extra: Optional[Dict[str, str]] = None,
    user_agent: str = BROWSER_UA,
) -> Dict[str, str]:
    """Build a default header set (browser-like UA, no compression games)."""
    headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    if extra:
        for key, value in extra.items():
            if value is None:
                headers.pop(key, None)
            else:
                headers[key] = value
    return headers


def open_stream(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
    method: str = "GET",
) -> Tuple[Response, BinaryIO]:
    """Open ``url`` for streaming, following redirects manually.

    Returns the response metadata together with the open body stream; the caller
    owns the stream and must close it. Redirect hops end up in
    :attr:`Response.redirects` so they can be logged or cached.
    """
    current = url
    chain: List[str] = []
    for _ in range(max_redirects + 1):
        request = urllib.request.Request(current, headers=headers or request_headers(), method=method)
        try:
            resp = _OPENER.open(request, timeout=timeout)
        except _RedirectSeen as seen:
            target = urllib.parse.urljoin(current, seen.location)
            chain.append(target)
            current = target
            continue
        except urllib.error.HTTPError as exc:
            snippet = _safe_body(exc)
            raise HttpError(exc.code, current, snippet) from exc
        except urllib.error.URLError as exc:
            raise NetworkError(f"cannot reach {current}: {describe_exception(exc)}") from exc
        except OSError as exc:
            raise NetworkError(f"connection to {current} failed: {exc}") from exc

        meta = Response(
            url=resp.geturl() or current,
            status=getattr(resp, "status", 200) or 200,
            headers={k.lower(): v for k, v in resp.headers.items()},
            redirects=tuple(chain),
        )
        return meta, resp
    raise NetworkError(f"too many redirects while resolving {url}")


def fetch_bytes(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    limit: Optional[int] = None,
) -> Tuple[Response, bytes]:
    """Download ``url`` (optionally truncated to ``limit`` bytes) into memory."""
    merged = request_headers(headers)
    if limit is not None:
        merged["Range"] = f"bytes=0-{max(limit - 1, 0)}"
    meta, stream = open_stream(url, headers=merged, timeout=timeout)
    try:
        body = stream.read() if limit is None else stream.read(limit)
    except (OSError, urllib.error.URLError) as exc:
        raise NetworkError(f"truncated response from {url}: {exc}") from exc
    finally:
        stream.close()
    return meta, body


def read_range(
    url: str,
    start: int,
    end: int,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> bytes:
    """Read ``bytes=start-end`` (inclusive) via a single ranged request."""
    if start < 0 or end < start:
        raise ValueError(f"invalid byte range {start}-{end}")
    merged = request_headers(headers)
    merged["Range"] = f"bytes={start}-{end}"
    meta, stream = open_stream(url, headers=merged, timeout=timeout)
    try:
        body = stream.read()
    except (OSError, urllib.error.URLError) as exc:
        raise NetworkError(f"truncated range response from {url}: {exc}") from exc
    finally:
        stream.close()

    if meta.status == 206:
        span = meta.content_range
        if span is not None and span[0] != start:
            raise ApkPureError(
                f"server answered with offset {span[0]} instead of {start} for {url}"
            )
    return body


def probe(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    sample: int = 4096,
) -> RemoteFile:
    """Ask for the first ``sample`` bytes only and report what the server says.

    This is the cheapest possible "is this file really there and how big is it"
    check: one request, a few KiB transferred, no commitment to the full body.
    """
    merged = request_headers(headers)
    merged["Range"] = f"bytes=0-{max(sample - 1, 0)}"
    meta, stream = open_stream(url, headers=merged, timeout=timeout)
    try:
        body = stream.read(sample)
    except (OSError, urllib.error.URLError) as exc:
        raise NetworkError(f"truncated probe response from {url}: {exc}") from exc
    finally:
        stream.close()

    size = meta.total_size
    if size is None and meta.status == 200 and len(body) == sample:
        # Server ignored the range and we stopped reading early: size unknown.
        size = None
    return RemoteFile(
        url=meta.url,
        status=meta.status,
        size=size,
        content_type=meta.content_type,
        filename=meta.filename,
        supports_ranges=meta.supports_ranges,
        magic=body[:8],
        redirects=meta.redirects,
    )


def retry_call(
    operation: Callable[[], T],
    *,
    attempts: int = 4,
    base_delay: float = 0.8,
    max_delay: float = 10.0,
    on_error: Callable[[int, BaseException], None] = lambda attempt, exc: None,
    retry_on: Tuple[type, ...] = (NetworkError, HttpError),
) -> T:
    """Run ``operation`` retrying transient transport errors with backoff."""
    last: Optional[BaseException] = None
    for attempt in range(1, max(attempts, 1) + 1):
        try:
            return operation()
        except retry_on as exc:
            last = exc
            if isinstance(exc, HttpError) and exc.status < 500 and exc.status != 429:
                raise
            if attempt >= attempts:
                break
            on_error(attempt, exc)
            _sleep_backoff(attempt, base_delay, max_delay)
    assert last is not None
    raise last


def _sleep_backoff(attempt: int, base_delay: float, max_delay: float) -> None:
    delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
    time.sleep(delay * (0.7 + random.random() * 0.6))


def _safe_body(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read(512)
    except Exception:  # noqa: BLE001 - best effort only
        return ""
    text = raw.decode("utf-8", "replace").strip()
    return " ".join(text.split())


def _as_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return None


def parse_content_range(value: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Parse ``bytes 0-1023/52770316`` into ``(0, 1023, 52770316)``."""
    if not value:
        return None
    match = re.search(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", value.strip(), re.I)
    if not match:
        return None
    start, end, total = match.groups()
    total_size = -1 if total == "*" else int(total)
    return int(start), int(end), total_size


def parse_content_disposition(value: Optional[str]) -> Optional[str]:
    """Extract a usable filename from a Content-Disposition header.

    Handles both the plain ``filename="..."`` form (where ``+`` means a space)
    and the RFC 5987 ``filename*=UTF-8''...`` form.
    """
    if not value:
        return None
    extended = re.search(r"filename\*\s*=\s*([\w-]+)'([\w-]*)'([^;]+)", value, re.I)
    if extended:
        charset = extended.group(1) or "utf-8"
        try:
            decoded = urllib.parse.unquote(extended.group(3).strip().strip('"'), encoding=charset)
        except (LookupError, UnicodeDecodeError):
            decoded = urllib.parse.unquote(extended.group(3).strip().strip('"'))
        return sanitize_filename(decoded)

    quoted = re.search(r'filename\s*=\s*"([^"]*)"', value, re.I)
    if quoted:
        return sanitize_filename(urllib.parse.unquote_plus(quoted.group(1)))

    bare = re.search(r"filename\s*=\s*([^;]+)", value, re.I)
    if bare:
        return sanitize_filename(urllib.parse.unquote_plus(bare.group(1).strip()))
    return None


def sanitize_filename(name: Optional[str]) -> Optional[str]:
    """Reduce a server-supplied name to a safe, single path component."""
    if not name:
        return None
    cleaned = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch for ch in cleaned if ch.isprintable() and ch not in '\x00"<>|:*?')
    cleaned = cleaned.strip().strip(".")
    if not cleaned:
        return None
    if len(cleaned) > MAX_FILENAME_LENGTH:
        stem, dot, suffix = cleaned.rpartition(".")
        if dot and len(suffix) <= 10:
            cleaned = stem[: MAX_FILENAME_LENGTH - len(suffix) - 1] + dot + suffix
        else:
            cleaned = cleaned[:MAX_FILENAME_LENGTH]
    return cleaned


def human_size(num_bytes: Optional[float]) -> str:
    """Format a byte count as e.g. ``52.7 MB``."""
    if num_bytes is None:
        return "unknown"
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def human_duration(seconds: Optional[float]) -> str:
    """Format a duration as ``1m 04s`` / ``3.2s``."""
    if seconds is None:
        return "n/a"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(round(seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {rest:02d}s"
    return f"{minutes}m {rest:02d}s"


def ensure_dir(path: str) -> str:
    """Create ``path`` (and parents) if needed and return it."""
    os.makedirs(path, exist_ok=True)
    return path
