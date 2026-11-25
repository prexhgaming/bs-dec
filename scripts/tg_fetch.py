#!/usr/bin/env python3
"""Download a file (the Blood Strike archive) straight out of a Telegram chat.

The file is located in one of four ways, in order:

1. ``--file-id``                     an explicit Telegram ``file_id``
2. ``--message`` (id or t.me link)   forwarded to obtain the ``file_id``
3. ``--url``                         a direct download URL (any host)
4. ``getUpdates`` scan               finds the newest matching archive

Everything is written to ``--out-dir`` together with a ``fetch.json`` record
(size, sha256, resolved file name) for the following steps.

Note on size: Telegram's *cloud* Bot API only lets a bot download files up to
20 MiB. A self-hosted Bot API server (``--local``) allows 2000 MiB, so point
``TELEGRAM_API_BASE`` at it for a ~640 MiB Blood Strike archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tg_common as tg  # noqa: E402

ARCHIVE_SUFFIXES = (".zip", ".xapk", ".apk", ".7z", ".rar")
DEFAULT_NAME = "bloodstrike-archive.zip"
CHUNK = 1 << 16


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tg_fetch.py",
        description="Fetch a file from Telegram (bot token + chat/message) into a local directory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  tg_fetch.py --chat -1001234567890 --message 4242 --out-dir work\n"
            "  tg_fetch.py --chat https://t.me/c/1234567890/77 --out-dir work\n"
            "  tg_fetch.py --url https://example.com/bs.zip --out-dir work\n"
        ),
    )
    parser.add_argument("--chat", help="chat id, @username or https://t.me/... link")
    parser.add_argument("--message", help="message id or full t.me message link")
    parser.add_argument("--file-id", help="Telegram file_id (skips message lookup)")
    parser.add_argument("--url", help="download directly from this URL instead of Telegram")
    parser.add_argument(
        "--forward-to",
        help="chat used to obtain a file_id (default: the source chat itself)",
    )
    parser.add_argument("--out-dir", default="work", help="directory to write into")
    parser.add_argument("--name", help=f"output file name (default: server name or {DEFAULT_NAME})")
    parser.add_argument("--token", help="bot token (default: $TELEGRAM_BOT_TOKEN)")
    parser.add_argument("--api-base", help="Bot API base URL (default: $TELEGRAM_API_BASE or the cloud API)")
    parser.add_argument("--timeout", type=float, default=120.0, help="request timeout in seconds")
    parser.add_argument("--retries", type=int, default=4, help="retries per network step")
    parser.add_argument("--scan-pages", type=int, default=5, help="getUpdates pages to scan in fallback mode")
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="scan getUpdates, print every document found (name, size, file_id) and stop without downloading",
    )
    parser.add_argument(
        "--keep-forward",
        action="store_true",
        help="keep the forwarded copy of the message used to read the file_id (default: delete it again)",
    )
    parser.add_argument("--require-suffix", default=".zip", help="preferred suffix when scanning getUpdates")
    parser.add_argument("--max-size", type=int, help="refuse files larger than this many bytes")
    parser.add_argument("--allow-huge", action="store_true", help="download even when over the API limit")
    parser.add_argument("--json", action="store_true", help="print the result record as JSON on stdout")
    parser.add_argument("--quiet", "-q", action="store_true", help="less output")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    log = (lambda _message: None) if args.quiet else (lambda message: print(f"· {message}", file=sys.stderr, flush=True))

    try:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        if args.list_only:
            chat, link_message = (tg.normalize_chat(args.chat) if args.chat else (None, None))
            candidates = list_updates(chat, args, log)
            if not candidates:
                # getUpdates only carries *pending* updates and drains on read, so fall
                # back to reading the message itself when a message id was given.
                message_id = _message_id_from(args, link_message)
                if chat is not None and message_id is not None:
                    log("getUpdates returned no documents; reading the message directly instead")
                    remote = lookup_message_file(chat, message_id, args, log)
                    if remote is not None:
                        candidates = [remote]
            payload = [
                {
                    "file_id": item.file_id,
                    "file_name": item.file_name,
                    "size": item.file_size,
                    "size_human": tg.describe_size(item.file_size),
                    "mime_type": item.mime_type,
                    "chat_id": item.chat_id,
                    "message_id": item.message_id,
                    "archive": item.looks_like_archive,
                }
                for item in candidates
            ]
            for item in payload:
                print(
                    f"{item['size_human']:>10}  {item['file_name'] or '<no name>':<48} "
                    f"chat={item['chat_id']} msg={item['message_id']} archive={item['archive']}"
                )
                print(f"            file_id={item['file_id']}")
            if args.json:
                print(json.dumps(payload, indent=2))
            if not candidates:
                print(
                    "no documents found in recent updates: check that the bot can see the chat, "
                    "and resend the file if it was older than the bot's last getUpdates poll.",
                    file=sys.stderr,
                )
                return 1
            return 0

        if args.url:
            log(f"downloading directly from {args.url}")
            target, size, sha256, source = download_url(
                args.url,
                out_dir / (args.name or _name_from_url(args.url) or DEFAULT_NAME),
                timeout=args.timeout,
                retries=args.retries,
                log=log,
                max_size=args.max_size,
            )
            record = _record(target, size, sha256, source, {"kind": "url", "url": args.url})
        else:
            remote, origin = resolve_remote_file(args, log)
            log(f"resolved {remote.describe()} via {origin}")
            warning = tg.check_downloadable_size(remote.file_size, args.api_base)
            if warning and not args.allow_huge:
                raise tg.TelegramError(warning)
            if args.max_size and remote.file_size and remote.file_size > args.max_size:
                raise tg.TelegramError(
                    f"file is {tg.describe_size(remote.file_size)}, above --max-size "
                    f"({tg.describe_size(args.max_size)})"
                )

            file_path = _resolve_file_path(remote.file_id, args)
            url = tg.build_download_url(file_path, token=args.token, base=args.api_base)
            name = args.name or remote.file_name or DEFAULT_NAME
            log(f"downloading {name} from Telegram")
            target, size, sha256, _ = download_url(
                url,
                out_dir / tg.sanitize_name(name),
                timeout=args.timeout,
                retries=args.retries,
                log=log,
                expected_size=remote.file_size,
                max_size=args.max_size,
            )
            record = _record(
                target,
                size,
                sha256,
                origin,
                {
                    "kind": "telegram",
                    "file_id": remote.file_id,
                    "file_unique_id": remote.file_unique_id,
                    "chat_id": remote.chat_id,
                    "message_id": remote.message_id,
                    "declared_size": remote.file_size,
                },
            )

        manifest = out_dir / "fetch.json"
        manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"ok {record['path']} ({tg.describe_size(record['size'])}, sha256 {record['sha256'][:16]}…)", file=sys.stderr)
        print(f"· record written to {manifest}", file=sys.stderr)
        if args.json:
            print(json.dumps(record, indent=2))
        _write_github_output(record)
        return 0
    except tg.TelegramError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


# ---------------------------------------------------------------------------
# locating the file
# ---------------------------------------------------------------------------


def _message_id_from(args, fallback=None):
    """Read the message id out of ``--message`` (a bare id or a t.me link)."""
    value = (args.message or "").strip()
    if not value:
        return fallback
    if re.match(r"^(https?://)?t\.me/", value, re.I):
        return tg.normalize_chat(value)[1]
    return int(value) if re.fullmatch(r"-?\d+", value) else None


def lookup_message_file(chat, message_id, args, log):
    """Resolve the document of an existing message.

    The file_id is read through ``forwardMessage`` because it works on chat
    history, unlike ``getUpdates`` which consumes the updates it returns. The
    forwarded copy is deleted again so the chat is left as it was.
    """
    target = args.forward_to or chat
    log(f"forwarding message {message_id} from chat {chat} to read its file_id")
    forwarded = tg.call(
        "forwardMessage",
        token=args.token,
        base=args.api_base,
        log=log,
        params={
            "chat_id": target,
            "from_chat_id": chat,
            "message_id": message_id,
            "disable_notification": True,
        },
    )
    copy_id = forwarded.get("message_id")
    if copy_id and not args.keep_forward:
        try:
            tg.call(
                "deleteMessage",
                token=args.token,
                base=args.api_base,
                params={"chat_id": target, "message_id": copy_id},
            )
            log(f"deleted the forwarded copy (message {copy_id})")
        except tg.TelegramApiError as exc:
            log(f"note: could not delete the forwarded copy {copy_id}: {exc}")
    return tg.file_from_message(forwarded)


def resolve_remote_file(args, log) -> Tuple[tg.RemoteFile, str]:
    """Find the file to download, trying the cheap routes before scanning."""
    if args.file_id:
        return tg.RemoteFile(file_id=args.file_id), "explicit file_id"

    chat_value = args.chat or ""
    message_value = args.message or ""

    # A t.me link may carry the chat *and* the message id in one string.
    chat, link_message = tg.normalize_chat(chat_value) if chat_value else (None, None)
    if message_value and re.match(r"^(https?://)?t\.me/", message_value.strip(), re.I):
        linked_chat, linked_message = tg.normalize_chat(message_value)
        chat = chat or linked_chat
        message_id = linked_message
    elif message_value:
        if not re.fullmatch(r"-?\d+", message_value.strip()):
            raise tg.TelegramError(f"--message must be a numeric message id or a t.me link, got {message_value!r}")
        message_id = int(message_value.strip())
    else:
        message_id = link_message

    if chat is not None and message_id is not None:
        remote = lookup_message_file(chat, message_id, args, log)
        if remote is not None:
            return remote, f"forwarded message {message_id}"
        raise tg.TelegramError(
            f"message {message_id} in chat {chat} carries no downloadable document "
            f"(is it the archive, and can the bot see that chat?)"
        )

    if chat is None:
        raise tg.TelegramError("nothing to download: pass --chat with --message, --file-id, or --url")

    log(f"scanning getUpdates for an archive in chat {chat}")
    remote = scan_updates(chat, args, log)
    if remote is None:
        raise tg.TelegramError(
            f"no archive found in recent updates for chat {chat}. Either give --message, or send the "
            f"file to the bot again (updates only reach a bot for messages it can already see), or use --url."
        )
    return remote, "getUpdates scan"


def list_updates(chat, args, log) -> list:
    """Collect every document seen in recent updates (newest first, de-duplicated)."""
    wanted_suffixes = tuple(
        part.strip().lower() for part in (args.require_suffix or "").split(",") if part.strip()
    ) or ARCHIVE_SUFFIXES
    collected = []
    seen = set()
    for update in tg.iter_updates(
        token=args.token,
        base=args.api_base,
        pages=args.scan_pages,
        log=log,
    ):
        message = update.get("message") or update.get("channel_post") or {}
        remote = tg.file_from_message(message)
        if remote is None:
            continue
        if chat is not None and str(chat).lstrip("@") != str(remote.chat_id):
            if not isinstance(chat, str) or not chat.startswith("@"):
                continue
        name = (remote.file_name or "").lower()
        if not (name.endswith(wanted_suffixes) or remote.looks_like_archive):
            continue
        if remote.file_unique_id and remote.file_unique_id in seen:
            continue
        if remote.file_unique_id:
            seen.add(remote.file_unique_id)
        collected.append(remote)
    return collected


def scan_updates(chat, args, log):
    """Look through recent updates for a document that looks like the archive."""
    for remote in list_updates(chat, args, log):
        log(f"found {remote.describe()}")
        return remote
    return None


def _resolve_file_path(file_id: str, args) -> str:
    result = tg.get_file(file_id, token=args.token, base=args.api_base, log=lambda m: None)
    if not result or not result.get("file_path"):
        raise tg.TelegramError(f"getFile returned no file_path for file_id {file_id!r}")
    return str(result["file_path"])


# ---------------------------------------------------------------------------
# downloading
# ---------------------------------------------------------------------------


def download_url(
    url: str,
    dest: Path,
    *,
    timeout: float = 120.0,
    retries: int = 4,
    log=None,
    expected_size: Optional[int] = None,
    max_size: Optional[int] = None,
) -> Tuple[Path, int, str, str]:
    """Stream ``url`` to ``dest`` and return ``(path, size, sha256, final_url)``."""
    note = log or (lambda _message: None)
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    last_error: Optional[BaseException] = None

    for attempt in range(1, max(retries, 1) + 1):
        digest = hashlib.sha256()
        size = 0
        started = time.monotonic()
        try:
            request = urllib.request.Request(url, headers={"User-Agent": tg.USER_AGENT, "Accept": "*/*"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                total = expected_size or _content_length(response.headers.get("Content-Length"))
                if max_size and total and total > max_size:
                    raise tg.TelegramError(
                        f"remote file is {tg.describe_size(total)}, above the {tg.describe_size(max_size)} limit"
                    )
                with open(part, "wb") as handle:
                    while True:
                        chunk = response.read(CHUNK)
                        if not chunk:
                            break
                        handle.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                        _progress(dest.name, size, total, started, note)
            if expected_size is not None and size != expected_size:
                raise tg.TelegramError(f"size mismatch: got {size} bytes, expected {expected_size}")
            os.replace(part, dest)
            note(f"received {dest.name}: {tg.describe_size(size)} in {time.monotonic() - started:.1f}s")
            return dest, size, digest.hexdigest(), url
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, tg.TelegramError) as exc:
            last_error = exc
            _cleanup(part)
            if attempt >= max(retries, 1):
                break
            delay = min(2 ** (attempt - 1), 20)
            note(f"download attempt {attempt} failed ({exc}); retrying in {delay}s")
            time.sleep(delay)

    assert last_error is not None
    if isinstance(last_error, tg.TelegramError):
        raise last_error
    raise tg.TelegramError(f"download failed after {retries} attempts: {last_error}")


def _progress(label: str, done: int, total: Optional[int], started: float, note) -> None:
    elapsed = max(time.monotonic() - started, 1e-6)
    if total:
        mark = int(done / total * 10) * 10
        if mark and mark != getattr(_progress, "last", -1):
            _progress.last = mark  # type: ignore[attr-defined]
            note(f"{label}: {mark}% ({tg.describe_size(done)}/{tg.describe_size(total)})")
    else:
        now = time.monotonic()
        if now - getattr(_progress, "last_time", 0.0) > 10:
            _progress.last_time = now  # type: ignore[attr-defined]
            note(f"{label}: {tg.describe_size(done)} at {tg.describe_size(done / elapsed)}/s")


def _cleanup(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _content_length(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value else None
    except ValueError:
        return None


def _name_from_url(url: str) -> Optional[str]:
    path = urllib.parse.urlparse(url).path
    name = os.path.basename(path)
    return name or None


def _record(path: Path, size: int, sha256: str, origin: str, source: Dict[str, object]) -> Dict[str, object]:
    return {
        "path": str(path),
        "name": path.name,
        "size": size,
        "sha256": sha256,
        "origin": origin,
        "source": source,
        "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _write_github_output(record: Dict[str, object]) -> None:
    """Expose the result to later workflow steps when running in Actions."""
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    try:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"archive_path={record['path']}\n")
            handle.write(f"archive_name={record['name']}\n")
            handle.write(f"archive_size={record['size']}\n")
            handle.write(f"sha256={record['sha256']}\n")
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
