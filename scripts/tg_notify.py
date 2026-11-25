#!/usr/bin/env python3
"""Send the ABI report (and optionally files) back to the Telegram chat.

Best effort by design: notification problems must never fail the build, so the
workflow calls this with ``continue-on-error`` and every failure becomes a
warning on stderr instead of a non-zero exit code.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tg_common as tg  # noqa: E402

MESSAGE_LIMIT = 4000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tg_notify.py",
        description="Post a status message / report file back to a Telegram chat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  tg_notify.py --chat -1001234567890 --text 'build ok'\n"
            "  tg_notify.py --chat -1001234567890 --from-report work/report/abi_report.json \\\n"
            "      --document work/report/abi_report.md --caption 'ABI report'\n"
        ),
    )
    parser.add_argument("--chat", required=True, help="chat id, @username or t.me link")
    parser.add_argument("--text", help="message text")
    parser.add_argument("--text-file", help="read the message text from this file")
    parser.add_argument("--from-report", help="build the message from an abi_report.json")
    parser.add_argument("--document", help="send this file as a document")
    parser.add_argument("--caption", help="caption for the document")
    parser.add_argument("--link", help="extra URL appended to the message (defaults to $GITHUB_RUN_URL)")
    parser.add_argument("--token", help="bot token (default: $TELEGRAM_BOT_TOKEN)")
    parser.add_argument("--api-base", help="Bot API base URL")
    parser.add_argument("--thread-id", help="message thread id for forum topics")
    parser.add_argument("--silent", action="store_true", help="send without a notification sound")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        chat, _ = tg.normalize_chat(args.chat)
        text = _text(args)
        if not text and not args.document:
            print("nothing to send: pass --text/--text-file/--from-report or --document", file=sys.stderr)
            return 0

        if args.document:
            document = Path(args.document)
            if not document.is_file():
                print(f"warning: document not found: {document}", file=sys.stderr)
            else:
                tg.call_with_file(
                    "sendDocument",
                    fields={
                        "chat_id": chat,
                        "caption": (args.caption or "")[:1000] or None,
                        "disable_notification": args.silent or None,
                        "message_thread_id": args.thread_id,
                    },
                    file_field="document",
                    file_name=document.name,
                    file_bytes=document.read_bytes(),
                    token=args.token,
                    base=args.api_base,
                )
                print(f"sent {document.name} to {chat}", file=sys.stderr)

        if text:
            tg.call(
                "sendMessage",
                params={
                    "chat_id": chat,
                    "text": text[:MESSAGE_LIMIT],
                    "disable_web_page_preview": True,
                    "disable_notification": args.silent or None,
                    "message_thread_id": args.thread_id,
                },
                token=args.token,
                base=args.api_base,
            )
            print(f"sent message to {chat}", file=sys.stderr)
        return 0
    except (tg.TelegramError, OSError) as exc:
        # Never break the workflow over a notification.
        print(f"warning: could not notify Telegram: {exc}", file=sys.stderr)
        return 0


def _text(args) -> str:
    """Assemble the message body from the explicit or report-derived text."""
    if args.text:
        body = args.text
    elif args.text_file:
        body = _read(Path(args.text_file))
    elif args.from_report:
        body = summarize_report(Path(args.from_report))
    else:
        body = ""
    link = args.link or os.environ.get("GITHUB_RUN_URL") or os.environ.get("RUN_URL")
    if link and link not in body:
        body = f"{body.rstrip()}\n\n{link}" if body else link
    return body.strip()


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError as exc:
        print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
        return ""


def summarize_report(path: Path) -> str:
    """Render a Telegram-friendly summary (no markdown tables) from abi_report.json."""
    try:
        report = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: cannot read report {path}: {exc}", file=sys.stderr)
        return ""
    if not isinstance(report, dict):
        return ""

    ok = bool(report.get("ok"))
    lines = [f"{'✅' if ok else '❌'} Blood Strike ABI check — {'PASS' if ok else 'FAIL'}"]
    if not ok:
        lines.append(f"missing ABI(s): {', '.join(report.get('missing') or [])}")

    for arch, row in sorted((report.get("abis") or {}).items()):
        if arch not in (report.get("required") or []) and not row.get("present"):
            continue
        mark = "✅" if row.get("present") else "❌"
        size = tg.describe_size_iec(row.get("uncompressed") or 0)
        lines.append(f"{mark} {arch} ({row.get('bitness', '?')}): {row.get('so_count', 0)} .so, {size}")

    source = Path(str(report.get("source") or "archive")).name
    lines.append(f"📦 {source}: {report.get('apk_count', 0)} APK(s) scanned")
    if report.get("errors"):
        lines.append(f"⚠️ unreadable: {', '.join(report['errors'][:3])}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
