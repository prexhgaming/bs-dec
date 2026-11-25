"""HTTP plumbing: one place for the user agent, timeouts, retries and range reads.

Everything here uses only :mod:`urllib`, so the tool stays dependency-free. Two
details matter for APKCombo's transfer hosts:

* redirects must sometimes *not* be followed (the download endpoint answers with
  a 303 whose ``Location`` is the file URL we want), hence :func:`request` with
  ``follow_redirects=False``;
* ranged reads are how the tool inspects a 700 MB archive without downloading it,
  so :func:`read_range` and :func:`probe` keep the arithmetic honest and verify
  that the server really sent the bytes we asked for.
"""

from __future__ import annotations

import email.message
import http.client
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .errors import BlockedError, HttpError, NetworkError, describe_exception

#: APKCombo serves the same markup to any client, but the mobile agent is what the
#: site itself uses for its download buttons, so keep it identical in one place.
BROWSER_UA = (
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)

#: Cloudflare fingerprints the header set, so send what a real Chrome sends.
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Ch-Ua": '"Chromium";v="120", "Not:A-Brand";v="99", "Google Chrome";v="120"',
    "Sec-Ch-Ua-Mobile": "?1",
    "Sec-Ch-Ua-Platform": '"Android"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

#: Bodies served instead of the page when the client is considered a bot.
CHALLENGE_MARKERS = (
    b"just a moment",
    b"__cf_chl",
    b"cf-challenge",
    b"cf-chl-",
    b"attention required",
    b"enable javascript and cookies",
    b"ddos protection by",
)

_ua_override: Optional[str] = None


def set_user_agent(value: Optional[str]) -> None:
    """Override the browser agent for every later request (``--user-agent``)."""
    global _ua_override
    _ua_override = value or None


def current_user_agent() -> str:
    return _ua_override or BROWSER_UA


def looks_like_challenge(body: bytes) -> bool:
    """True when a response body is a bot wall rather than real content."""
    probe = (body or b"")[:16384].lower()
    return any(marker in probe for marker in CHALLENGE_MARKERS)


DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 4
MAX_ERROR_BODY = 4096
READ_CHUNK = 1 << 20

Log = Callable[[str], None]


def _noop(_message: str) -> None:
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn off automatic redirects so the caller can read the Location header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def build_opener(*, follow_redirects: bool = True) -> urllib.request.OpenerDirector:
    if follow_redirects:
        return urllib.request.build_opener()
    return urllib.request.build_opener(_NoRedirect)


def request_headers(**extra: str) -> Dict[str, str]:
    headers = dict(BROWSER_HEADERS)
    headers["User-Agent"] = current_user_agent()
    # Keep Content-Length truthful for ranged requests.
    headers["Accept-Encoding"] = "identity"
    for key, value in extra.items():
        if value is None:
            continue
        headers[key.replace("_", "-")] = value
    return headers


def retry_call(
    func: Callable[[], object],
    *,
    what: str,
    attempts: int = DEFAULT_RETRIES,
    log: Optional[Log] = None,
    delay: float = 1.0,
) -> object:
    """Run ``func`` until it succeeds, or give up with the last error attached."""
    logger = log or _noop
    total = max(int(attempts), 1)
    last: Optional[BaseException] = None
    for attempt in range(1, total + 1):
        try:
            return func()
        except HttpError as exc:
            # 4xx (except 408/429) will not fix themselves.
            if 400 <= exc.status < 500 and exc.status not in (408, 425, 429):
                raise
            last = exc
        except (NetworkError, OSError) as exc:
            last = exc
        if attempt < total:
            wait = delay * attempt
            logger(f"{what} failed ({describe_exception(last)}), retrying in {wait:.0f}s")
            time.sleep(wait)
    assert last is not None
    raise last


def request(
    url: str,
    *,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    retries: int = DEFAULT_RETRIES,
    log: Optional[Log] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    """Perform a request and return ``(status, headers, body)``."""
    logger = log or _noop

    def attempt() -> Tuple[int, Dict[str, str], bytes]:
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in (headers or request_headers()).items():
            req.add_header(key, value)
        opener = build_opener(follow_redirects=follow_redirects)
        try:
            with opener.open(req, timeout=timeout) as response:
                return response.status, _lower_headers(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            if not follow_redirects and 300 <= exc.code < 400:
                # A redirect the caller asked to inspect (the download endpoint
                # answers 303 with the file URL in Location).
                return exc.code, _lower_headers(exc.headers), b""
            detail = ""
            try:
                raw = exc.read(MAX_ERROR_BODY)
            except Exception:  # noqa: BLE001 - the body is only for the message
                raw = b""
            if exc.code in (403, 429, 503) and looks_like_challenge(raw):
                raise BlockedError(
                    f"APKCombo answered HTTP {exc.code} with a Cloudflare bot challenge for {url}; "
                    "the IP is blocked (GitHub's hosted runners are frequently flagged). "
                    "Point the workflow at a cached archive (--apk-file) or a direct link "
                    "(--apk-url) instead of re-scraping the site."
                ) from exc
            detail = re.sub(r"\s+", " ", raw.decode("utf-8", "replace")).strip()[:200]
            raise HttpError(exc.code, url, detail) from exc
        except urllib.error.URLError as exc:
            raise NetworkError(f"cannot reach {url}: {exc.reason}") from exc
        except (http.client.HTTPException, TimeoutError, socket.timeout, OSError) as exc:
            raise NetworkError(f"cannot reach {url}: {describe_exception(exc)}") from exc

    logger(f"{method} {url[:110]}")
    return retry_call(attempt, what=f"{method} {url[:60]}", attempts=retries, log=logger)  # type: ignore[return-value]


def _lower_headers(headers: "email.message.Message | Dict[str, str]") -> Dict[str, str]:
    return {str(key).lower(): str(value) for key, value in dict(headers).items()}


def fetch_text(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    log: Optional[Log] = None,
) -> Tuple[str, Dict[str, str]]:
    """GET a page and decode it (APKCombo is UTF-8)."""
    _status, headers, body = request(url, timeout=timeout, retries=retries, log=log)
    charset = "utf-8"
    content_type = headers.get("content-type", "")
    match = re.search(r"charset=([\w-]+)", content_type)
    if match:
        charset = match.group(1)
    try:
        return body.decode(charset, "replace"), headers
    except LookupError:
        return body.decode("utf-8", "replace"), headers


def post_form(
    url: str,
    fields: Dict[str, str],
    *,
    referer: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    log: Optional[Log] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    """POST a form and return the raw response, *without* following redirects."""
    headers = request_headers(
        Content_Type="application/x-www-form-urlencoded",
        Referer=referer or url,
        Origin=_origin(url),
    )
    body = urllib.parse.urlencode(fields).encode()
    return request(
        url,
        method="POST",
        data=body,
        headers=headers,
        timeout=timeout,
        follow_redirects=False,
        retries=retries,
        log=log,
    )


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


@dataclass(frozen=True)
class ProbeInfo:
    """What the server says about a file before we download it."""

    url: str
    status: int
    size: Optional[int] = None
    content_type: str = ""
    filename: str = ""
    accept_ranges: bool = False
    headers: Dict[str, str] = field(default_factory=dict)

    def describe(self) -> str:
        bits = [f"HTTP {self.status}", self.content_type or "unknown type"]
        if self.size is not None:
            bits.append(human_size(self.size))
        if self.filename:
            bits.append(f'"{self.filename}"')
        bits.append("ranges: yes" if self.accept_ranges else "ranges: no")
        return ", ".join(bits)

    @property
    def size_text(self) -> str:
        return human_size(self.size)


def probe(
    url: str,
    *,
    sample: int = 1024,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    log: Optional[Log] = None,
) -> Tuple[ProbeInfo, bytes]:
    """Ask for the first ``sample`` bytes and report the file's metadata."""
    status, response_headers, body = request(
        url,
        headers=request_headers(Range=f"bytes=0-{max(sample, 1) - 1}", **(headers or {})),
        timeout=timeout,
        retries=retries,
        log=log,
    )
    total = None
    content_range = response_headers.get("content-range")
    if content_range:
        parsed = parse_content_range(content_range)
        if parsed is not None:
            total = parsed[2]
    if total is None and status == 200:
        length = response_headers.get("content-length")
        if length and length.isdigit():
            total = int(length)
    info = ProbeInfo(
        url=url,
        status=status,
        size=total,
        content_type=response_headers.get("content-type", ""),
        filename=parse_content_disposition(response_headers.get("content-disposition", "")),
        accept_ranges=response_headers.get("accept-ranges", "").lower() == "bytes"
        or status == 206,
        headers=response_headers,
    )
    return info, body


def read_range(
    url: str,
    start: int,
    end: int,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    log: Optional[Log] = None,
) -> bytes:
    """Fetch ``bytes=start-end`` (inclusive) and check the server honoured it."""
    if end < start:
        return b""
    wanted = end - start + 1
    status, response_headers, body = request(
        url,
        headers=request_headers(Range=f"bytes={start}-{end}", **(headers or {})),
        timeout=timeout,
        retries=retries,
        log=log,
    )
    if status == 206:
        content_range = response_headers.get("content-range", "")
        parsed = parse_content_range(content_range)
        if parsed is not None and parsed[0] != start:
            raise HttpError(status, url, f"server returned {content_range} instead of offset {start}")
        if len(body) != wanted:
            raise NetworkError(
                f"short ranged read: wanted {wanted} bytes at {start}, received {len(body)}"
            )
        return body
    # No range support: the whole file came back, so slice it.
    if len(body) < wanted:
        raise NetworkError(f"file ends before offset {start} ({len(body)} bytes received)")
    return body[start:end + 1] if len(body) > wanted else body


def open_response(
    url: str,
    *,
    byte_range: Optional[Tuple[int, int]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
):
    """Open a streaming response for the downloader. Caller must close it."""
    extra = dict(headers or {})
    if byte_range is not None:
        extra["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
    req = urllib.request.Request(url)
    for key, value in request_headers(**extra).items():
        req.add_header(key, value)
    opener = build_opener(follow_redirects=True)
    try:
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code, url, exc.reason or "") from exc
    except urllib.error.URLError as exc:
        raise NetworkError(f"cannot reach {url}: {exc.reason}") from exc
    except (http.client.HTTPException, TimeoutError, socket.timeout, OSError) as exc:
        raise NetworkError(f"cannot reach {url}: {describe_exception(exc)}") from exc
    return response


def iter_chunks(response, size: int = READ_CHUNK) -> Iterator[bytes]:
    while True:
        chunk = response.read(size)
        if not chunk:
            break
        yield chunk


# -- parsing helpers --------------------------------------------------------

CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", re.I)
FILENAME_STAR_RE = re.compile(r"filename\*\s*=\s*([^;]+)", re.I)
FILENAME_RE = re.compile(r'filename\s*=\s*"([^"]*)"|filename\s*=\s*([^;]+)', re.I)


def parse_content_range(value: str) -> Optional[Tuple[int, int, Optional[int]]]:
    """``bytes 0-1023/698120404`` -> ``(0, 1023, 698120404)``."""
    match = CONTENT_RANGE_RE.search(value or "")
    if not match:
        return None
    start, end = int(match.group(1)), int(match.group(2))
    total = None if match.group(3) == "*" else int(match.group(3))
    return start, end, total


def parse_content_disposition(value: str) -> str:
    """Extract a filename from a Content-Disposition header."""
    if not value:
        return ""
    star = FILENAME_STAR_RE.search(value)
    if star:
        raw = star.group(1).strip().strip('"')
        if "''" in raw:
            raw = raw.split("''", 1)[1]
        return sanitize_filename(urllib.parse.unquote(raw))
    match = FILENAME_RE.search(value)
    if not match:
        return ""
    return sanitize_filename(match.group(1) or match.group(2) or "")


_UNSAFE_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(name: str) -> str:
    """Make a server-provided name safe for the local filesystem."""
    cleaned = _UNSAFE_RE.sub("_", (name or "").strip()).strip(". ")
    cleaned = cleaned.replace("..", "_")
    if len(cleaned) > 160:
        stem, dot, suffix = cleaned.rpartition(".")
        keep = 140 if dot else 160
        cleaned = (stem[:keep] + dot + suffix[:20]) if dot else cleaned[:160]
    return cleaned or "download.bin"


def human_size(num_bytes: Optional[float]) -> str:
    if num_bytes is None:
        return "unknown size"
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def content_length_of(headers: Dict[str, str]) -> Optional[int]:
    value = headers.get("content-length")
    if value and value.isdigit():
        return int(value)
    return None


def cache_busted(url: str) -> str:
    """Append a unique query so a cached redirect/HTML never answers twice."""
    separator = "&" if urllib.parse.urlsplit(url).query else "?"
    return f"{url}{separator}cb={int(time.time() * 1000)}"
