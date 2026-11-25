"""Shared helpers for talking to the Telegram Bot API.

Standard library only. Every call goes through :func:`call` so retries,
rate-limit handling and error reporting are consistent between scripts.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

DEFAULT_API_BASE = "https://api.telegram.org"
USER_AGENT = "bs-dec/1.0 (+https://github.com)"

#: A bot using Telegram's cloud Bot API may only fetch files up to 20 MiB.
#: A self-hosted Bot API server raises the limit to 2000 MiB.
CLOUD_FILE_LIMIT = 20 * 1024 * 1024
LOCAL_API_FILE_LIMIT = 2000 * 1024 * 1024

# t.me/c/<internal id>/<message id>  (private supergroup)
# t.me/<username>/<message id>       (public channel/group)
LINK_PATTERN = re.compile(
    r"^(?:https?://)?t\.me/(?:(?:c/(?P<internal>\d+))|(?P<username>[A-Za-z0-9_]{4,}))"
    r"(?:/(?P<message>\d+))?/?(?:\?.*)?$",
    re.IGNORECASE,
)


class TelegramError(RuntimeError):
    """Any failure while talking to Telegram."""


class TelegramApiError(TelegramError):
    """The API answered ``ok: false`` or returned an HTTP error status."""

    def __init__(self, method: str, description: str, error_code: Optional[int] = None, status: Optional[int] = None):
        self.method = method
        self.description = description
        self.error_code = error_code
        self.status = status
        detail = f"{method} failed"
        if error_code is not None:
            detail += f" ({error_code})"
        if status is not None and status != error_code:
            detail += f" [HTTP {status}]"
        super().__init__(f"{detail}: {description}")


@dataclass(frozen=True)
class RemoteFile:
    """A downloadable document attached to a Telegram message."""

    file_id: str
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    mime_type: Optional[str] = None
    file_unique_id: Optional[str] = None
    chat_id: Optional[Union[int, str]] = None
    message_id: Optional[int] = None

    @property
    def looks_like_archive(self) -> bool:
        name = (self.file_name or "").lower()
        return name.endswith((".zip", ".xapk", ".apk", ".7z", ".rar"))

    def describe(self) -> str:
        size = describe_size(self.file_size)
        return f"{self.file_name or self.file_id} ({size}, {self.mime_type or 'unknown type'})"


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


def api_base() -> str:
    """Bot API root. Point ``TELEGRAM_API_BASE`` at a self-hosted server for >20 MiB.

    Blank values are treated as unset: Actions sets the variable to an empty
    string when the local server step is skipped, and ``""`` would otherwise
    produce a URL with no scheme.
    """
    configured = (os.environ.get("TELEGRAM_API_BASE") or "").strip()
    return (configured or DEFAULT_API_BASE).rstrip("/")


def is_cloud_api(base: Optional[str] = None) -> bool:
    return "api.telegram.org" in (base or api_base())


def file_size_limit(base: Optional[str] = None) -> int:
    return CLOUD_FILE_LIMIT if is_cloud_api(base) else LOCAL_API_FILE_LIMIT


def bot_token(explicit: Optional[str] = None) -> str:
    """Read the bot token from an argument, ``TELEGRAM_BOT_TOKEN`` or ``TG_BOT_TOKEN``."""
    token = (explicit or os.environ.get("TELEGRAM_BOT_TOKEN") or os.environ.get("TG_BOT_TOKEN") or "").strip()
    if not token:
        raise TelegramError(
            "no bot token: pass --token or set the TELEGRAM_BOT_TOKEN environment variable "
            "(in GitHub Actions: Settings -> Secrets and variables -> Actions -> New repository secret)"
        )
    return token


def describe_size(num_bytes: Optional[float]) -> str:
    """Format a byte count like ``634.4 MB`` (SI units, matching Telegram's UI)."""
    if num_bytes is None:
        return "unknown size"
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1000 or unit == "TB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


def check_downloadable_size(size: Optional[int], base: Optional[str] = None) -> Optional[str]:
    """Return a warning string when the file exceeds what this Bot API can serve."""
    if size is None:
        return None
    limit = file_size_limit(base)
    if size <= limit:
        return None
    if is_cloud_api(base):
        return (
            f"file is {describe_size(size)} but Telegram's cloud Bot API only lets bots "
            f"download {describe_size(CLOUD_FILE_LIMIT)}; getFile will refuse it. Run your own "
            f"Bot API server (telegram-bot-api --local) and set TELEGRAM_API_BASE to its URL "
            f"(then bots may fetch up to {describe_size(LOCAL_API_FILE_LIMIT)}), or pass a "
            f"direct --url / split the archive into <20 MiB parts."
        )
    return f"file is {describe_size(size)}, above the {describe_size(limit)} self-hosted limit"


# ---------------------------------------------------------------------------
# chat / link parsing
# ---------------------------------------------------------------------------


def normalize_chat(value: str, *, link_message_id: Optional[int] = None) -> Tuple[Union[int, str], Optional[int]]:
    """Turn a chat id, ``@username`` or t.me link into ``(chat_id, message_id)``.

    Private supergroup links (``t.me/c/<internal>``) use the *internal* group id,
    which the Bot API addresses as ``-100<internal>`` — that prefix is added here.
    """
    raw = (value or "").strip()
    if not raw:
        raise TelegramError("empty chat value")

    match = LINK_PATTERN.match(raw)
    if match:
        message_id = int(match.group("message")) if match.group("message") else link_message_id
        if match.group("internal"):
            return int(f"-100{match.group('internal')}"), message_id
        return f"@{match.group('username')}", message_id

    if raw.startswith("@"):
        return raw, link_message_id
    if re.fullmatch(r"-?\d+", raw):
        return int(raw), link_message_id
    if raw.startswith("http"):
        raise TelegramError(f"unsupported link {raw!r}: expected https://t.me/<name>/<message> or https://t.me/c/<id>/<message>")
    return f"@{raw}", link_message_id


_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_name(name: str, *, default: str = "download.bin", max_length: int = 120) -> str:
    """Make a server-supplied file name safe to write on the runner's disk."""
    candidate = os.path.basename((name or "").replace("\\", "/")).strip()
    candidate = _UNSAFE_NAME.sub("_", candidate).strip("._-")
    if not candidate:
        return default
    if len(candidate) > max_length:
        stem, dot, suffix = candidate.rpartition(".")
        has_suffix = bool(dot) and len(suffix) <= 10
        keep = max_length - (len(suffix) + 1 if has_suffix else 0)
        candidate = (stem[:keep] + (dot + suffix if has_suffix else "")) or default
    return candidate


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------


def call(
    method: str,
    *,
    token: Optional[str] = None,
    params: Optional[Mapping[str, Any]] = None,
    timeout: float = 60.0,
    retries: int = 4,
    base: Optional[str] = None,
    log=None,
) -> Any:
    """POST a JSON request to the Bot API and return ``result``."""
    api_root = (base or api_base()).rstrip("/")
    url = f"{api_root}/bot{bot_token(token)}/{method}"
    payload = {key: value for key, value in (params or {}).items() if value is not None}
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    note = log or (lambda _message: None)

    last_error: Optional[BaseException] = None
    for attempt in range(1, max(retries, 1) + 1):
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {}
            description = parsed.get("description") or raw.strip() or exc.reason
            error_code = parsed.get("error_code")
            retry_after = int((parsed.get("parameters") or {}).get("retry_after", 0) or 0)
            if exc.code == 429 or exc.code >= 500:
                last_error = TelegramApiError(method, str(description), error_code, exc.code)
                if attempt < max(retries, 1):
                    delay = retry_after or min(2 ** (attempt - 1), 30)
                    note(f"{method}: HTTP {exc.code}, retrying in {delay}s")
                    time.sleep(delay)
                    continue
            raise TelegramApiError(method, str(description), error_code, exc.code) from exc
        except urllib.error.URLError as exc:
            last_error = TelegramError(f"{method}: cannot reach {api_root}: {exc.reason}")
            if attempt < max(retries, 1):
                delay = min(2 ** (attempt - 1), 15)
                note(f"{method}: network error ({exc.reason}), retrying in {delay}s")
                time.sleep(delay)
                continue
            raise last_error from exc

        if not data.get("ok", False):
            error_code = data.get("error_code")
            description = data.get("description", "unknown error")
            raise TelegramApiError(method, str(description), error_code)
        return data.get("result")

    raise last_error if last_error is not None else TelegramError(f"{method} failed")


def call_with_file(
    method: str,
    *,
    fields: Mapping[str, Any],
    file_field: str,
    file_name: str,
    file_bytes: bytes,
    token: Optional[str] = None,
    timeout: float = 120.0,
    retries: int = 3,
    base: Optional[str] = None,
    log=None,
) -> Any:
    """POST a multipart request (used for ``sendDocument``)."""
    api_root = (base or api_base()).rstrip("/")
    url = f"{api_root}/bot{bot_token(token)}/{method}"
    boundary = f"----bsdec{uuid.uuid4().hex}"
    body = _multipart_body(boundary, fields, file_field, file_name, file_bytes)
    note = log or (lambda _message: None)

    last_error: Optional[BaseException] = None
    for attempt in range(1, max(retries, 1) + 1):
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            retry_after = 0
            try:
                parsed = json.loads(raw)
                retry_after = int((parsed.get("parameters") or {}).get("retry_after", 0) or 0)
                description = parsed.get("description") or raw.strip()
            except json.JSONDecodeError:
                description = raw.strip() or exc.reason
            if (exc.code == 429 or exc.code >= 500) and attempt < max(retries, 1):
                delay = retry_after or min(2 ** (attempt - 1), 30)
                note(f"{method}: HTTP {exc.code}, retrying in {delay}s")
                time.sleep(delay)
                continue
            raise TelegramApiError(method, str(description), None, exc.code) from exc
        except urllib.error.URLError as exc:
            last_error = TelegramError(f"{method}: cannot reach {api_root}: {exc.reason}")
            if attempt < max(retries, 1):
                time.sleep(min(2 ** (attempt - 1), 15))
                continue
            raise last_error from exc

        if not data.get("ok", False):
            raise TelegramApiError(method, str(data.get("description", "unknown error")), data.get("error_code"))
        return data.get("result")

    raise last_error if last_error is not None else TelegramError(f"{method} failed")


def _multipart_body(
    boundary: str,
    fields: Mapping[str, Any],
    file_field: str,
    file_name: str,
    file_bytes: bytes,
) -> bytes:
    parts: List[bytes] = []
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n".encode())
        parts.append(str(value).encode("utf-8"))
        parts.append(b"\r\n")
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
        f"filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
    )
    parts.append(file_bytes)
    parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


# ---------------------------------------------------------------------------
# file resolution
# ---------------------------------------------------------------------------


def file_from_message(message: Mapping[str, Any]) -> Optional[RemoteFile]:
    """Pull the downloadable document out of a Message object."""
    if not isinstance(message, Mapping):
        return None
    document = message.get("document")
    if isinstance(document, Mapping) and document.get("file_id"):
        return RemoteFile(
            file_id=str(document["file_id"]),
            file_name=document.get("file_name"),
            file_size=_as_int(document.get("file_size")),
            mime_type=document.get("mime_type"),
            file_unique_id=document.get("file_unique_id"),
            chat_id=(message.get("chat") or {}).get("id"),
            message_id=_as_int(message.get("message_id")),
        )
    for key in ("video", "audio", "voice", "animation"):
        media = message.get(key)
        if isinstance(media, Mapping) and media.get("file_id"):
            return RemoteFile(
                file_id=str(media["file_id"]),
                file_name=media.get("file_name"),
                file_size=_as_int(media.get("file_size")),
                mime_type=media.get("mime_type"),
                file_unique_id=media.get("file_unique_id"),
                chat_id=(message.get("chat") or {}).get("id"),
                message_id=_as_int(message.get("message_id")),
            )
    photos = message.get("photo")
    if isinstance(photos, list) and photos:
        largest = photos[-1]
        if isinstance(largest, Mapping) and largest.get("file_id"):
            return RemoteFile(
                file_id=str(largest["file_id"]),
                file_name=None,
                file_size=_as_int(largest.get("file_size")),
                mime_type="image/jpeg",
                chat_id=(message.get("chat") or {}).get("id"),
                message_id=_as_int(message.get("message_id")),
            )
    return None


def get_file(file_id: str, *, token: Optional[str] = None, base: Optional[str] = None, log=None) -> Dict[str, Any]:
    """``getFile`` — returns the API result (``file_path``, ``file_size``...)."""
    return call("getFile", token=token, params={"file_id": file_id}, base=base, log=log)


def build_download_url(file_path: str, *, token: Optional[str] = None, base: Optional[str] = None) -> str:
    """URL of the file contents for a path returned by ``getFile``."""
    api_root = (base or api_base()).rstrip("/")
    quoted = "/".join(urllib.parse.quote(part) for part in file_path.split("/"))
    return f"{api_root}/file/bot{bot_token(token)}/{quoted}"


def iter_updates(
    *,
    token: Optional[str] = None,
    base: Optional[str] = None,
    limit: int = 100,
    pages: int = 5,
    offset: Optional[int] = None,
    timeout: float = 30.0,
    log=None,
) -> Iterable[Dict[str, Any]]:
    """Yield recent updates, paging backwards a bounded number of times.

    Used as a fallback when a message cannot be forwarded for a file_id lookup.
    """
    seen_offset = offset
    for _ in range(max(pages, 1)):
        params: Dict[str, Any] = {"limit": limit, "timeout": 0}
        if seen_offset is not None:
            params["offset"] = seen_offset
        updates = call("getUpdates", token=token, params=params, base=base, timeout=timeout, log=log)
        if not updates:
            return
        for update in updates:
            yield update
        # Walk to the oldest batch: getUpdates(offset=0) returns the oldest
        # pending updates, so raising the offset keeps paging forward in time.
        seen_offset = max(_as_int(item.get("update_id")) or 0 for item in updates) + 1


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
