"""Offline tests for the bs-dec scripts (no network, no Telegram).

Run with ``python -m unittest discover -s tests -v`` from the repository root.
"""

from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest import mock
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import inspect_apks  # noqa: E402
import tg_common as tg  # noqa: E402
import tg_fetch  # noqa: E402


# ---------------------------------------------------------------------------
# tg_common
# ---------------------------------------------------------------------------


class ChatParsingTests(unittest.TestCase):
    def test_numeric_id(self):
        self.assertEqual(tg.normalize_chat("9117250551"), (9117250551, None))
        self.assertEqual(tg.normalize_chat("-1001234567890"), (-1001234567890, None))

    def test_username(self):
        self.assertEqual(tg.normalize_chat("@builddebugbot"), ("@builddebugbot", None))
        self.assertEqual(tg.normalize_chat("builddebugbot"), ("@builddebugbot", None))

    def test_public_link(self):
        chat, message = tg.normalize_chat("https://t.me/somechannel/235")
        self.assertEqual(chat, "@somechannel")
        self.assertEqual(message, 235)

    def test_private_link_gets_the_minus_100_prefix(self):
        chat, message = tg.normalize_chat("https://t.me/c/1234567890/77")
        self.assertEqual(chat, -1001234567890)
        self.assertEqual(message, 77)

    def test_desktop_link_is_rejected(self):
        with self.assertRaises(tg.TelegramError):
            tg.normalize_chat("https://web.telegram.org/a/#123")

    def test_empty(self):
        with self.assertRaises(tg.TelegramError):
            tg.normalize_chat("   ")


class NameAndSizeTests(unittest.TestCase):
    def test_sanitize_keeps_a_normal_name(self):
        self.assertEqual(
            tg.sanitize_name("com.netease.newspike_1.003.650026.xapk"),
            "com.netease.newspike_1.003.650026.xapk",
        )

    def test_sanitize_strips_directories_and_odd_characters(self):
        self.assertEqual(tg.sanitize_name("../../etc/passwd"), "passwd")
        self.assertEqual(tg.sanitize_name("a b/c\\d.zip"), "d.zip")
        self.assertEqual(tg.sanitize_name(""), "download.bin")

    def test_sanitize_truncates_but_keeps_the_suffix(self):
        name = tg.sanitize_name("x" * 300 + ".xapk", max_length=40)
        self.assertLessEqual(len(name), 40)
        self.assertTrue(name.endswith(".xapk"))

    def test_describe_size_is_si(self):
        self.assertEqual(tg.describe_size(666668430), "666.7 MB")
        self.assertEqual(tg.describe_size(None), "unknown size")

    def test_cloud_limit_is_flagged(self):
        warning = tg.check_downloadable_size(666668430, "https://api.telegram.org")
        self.assertIsNotNone(warning)
        self.assertIn("cloud Bot API", warning)

    def test_local_server_accepts_the_archive(self):
        self.assertIsNone(tg.check_downloadable_size(666668430, "http://127.0.0.1:8081"))

    def test_local_server_still_has_a_ceiling(self):
        warning = tg.check_downloadable_size(5_000_000_000, "http://127.0.0.1:8081")
        self.assertIsNotNone(warning)
        self.assertIn("self-hosted", warning)

    def test_small_file_is_fine_on_the_cloud_api(self):
        self.assertIsNone(tg.check_downloadable_size(1_048_576, "https://api.telegram.org"))

    def test_blank_api_base_env_falls_back_to_the_cloud_api(self):
        # Actions exports TELEGRAM_API_BASE="" when the local server is skipped.
        old = os.environ.get("TELEGRAM_API_BASE")
        os.environ["TELEGRAM_API_BASE"] = "   "
        try:
            self.assertEqual(tg.api_base(), tg.DEFAULT_API_BASE.rstrip("/"))
            self.assertTrue(tg.is_cloud_api())
        finally:
            self._restore(old)

    def test_local_api_base_env_is_used_and_trailing_slash_stripped(self):
        old = os.environ.get("TELEGRAM_API_BASE")
        os.environ["TELEGRAM_API_BASE"] = "http://127.0.0.1:8081/"
        try:
            self.assertEqual(tg.api_base(), "http://127.0.0.1:8081")
            self.assertFalse(tg.is_cloud_api())
            self.assertEqual(tg.file_size_limit(), tg.LOCAL_API_FILE_LIMIT)
        finally:
            self._restore(old)

    @staticmethod
    def _restore(old):
        if old is None:
            os.environ.pop("TELEGRAM_API_BASE", None)
        else:
            os.environ["TELEGRAM_API_BASE"] = old


class MessageParsingTests(unittest.TestCase):
    def test_document(self):
        message = {
            "message_id": 236,
            "chat": {"id": 9117250551},
            "document": {
                "file_id": "BQACAgUAAxkBAA",
                "file_unique_id": "AgADpCAAAm29QVQ",
                "file_name": "com.netease.newspike_1.003.650026.xapk",
                "file_size": 666668430,
                "mime_type": "application/octet-stream",
            },
        }
        remote = tg.file_from_message(message)
        self.assertIsNotNone(remote)
        self.assertEqual(remote.file_name, "com.netease.newspike_1.003.650026.xapk")
        self.assertEqual(remote.file_size, 666668430)
        self.assertEqual(remote.message_id, 236)
        self.assertTrue(remote.looks_like_archive)
        self.assertIn("666.7 MB", remote.describe())

    def test_text_only_message(self):
        self.assertIsNone(tg.file_from_message({"message_id": 1, "chat": {"id": 5}, "text": "hi"}))

    def test_largest_photo_wins(self):
        message = {
            "message_id": 7,
            "chat": {"id": 1},
            "photo": [{"file_id": "small", "file_size": 10}, {"file_id": "big", "file_size": 99}],
        }
        remote = tg.file_from_message(message)
        self.assertEqual(remote.file_id, "big")

    def test_download_url_shape(self):
        url = tg.build_download_url("documents/file_3.xapk", token="123:abc", base="http://127.0.0.1:8081")
        self.assertEqual(url, "http://127.0.0.1:8081/file/bot123:abc/documents/file_3.xapk")


class MessageLookupTests(unittest.TestCase):
    """forwardMessage is used instead of getUpdates, and cleaned up afterwards."""

    forwarded = {
        "message_id": 999,
        "chat": {"id": 9117250551},
        "document": {
            "file_id": "BQACAgUAAxkBAA",
            "file_unique_id": "AgADpCAAAm29QVQ",
            "file_name": "com.netease.newspike_1.003.650026.xapk",
            "file_size": 666668430,
        },
    }

    def _args(self, *extra):
        return tg_fetch.build_parser().parse_args(["--chat", "9117250551", *extra])

    def test_forwarded_copy_is_deleted(self):
        calls = []

        def fake_call(method, **kwargs):
            calls.append((method, kwargs.get("params")))
            return dict(self.forwarded) if method == "forwardMessage" else True

        with mock.patch.object(tg, "call", side_effect=fake_call):
            remote = tg_fetch.lookup_message_file(9117250551, 236, self._args("--message", "236"), lambda _m: None)

        self.assertEqual(remote.file_id, "BQACAgUAAxkBAA")
        self.assertEqual([name for name, _ in calls], ["forwardMessage", "deleteMessage"])
        self.assertEqual(calls[0][1]["message_id"], 236)
        self.assertEqual(calls[1][1], {"chat_id": 9117250551, "message_id": 999})

    def test_keep_forward_leaves_the_copy_alone(self):
        calls = []

        def fake_call(method, **kwargs):
            calls.append(method)
            return dict(self.forwarded) if method == "forwardMessage" else True

        with mock.patch.object(tg, "call", side_effect=fake_call):
            tg_fetch.lookup_message_file(9117250551, 236, self._args("--keep-forward"), lambda _m: None)
        self.assertEqual(calls, ["forwardMessage"])

    def test_a_failed_delete_is_not_fatal(self):
        def fake_call(method, **kwargs):
            if method == "forwardMessage":
                return dict(self.forwarded)
            raise tg.TelegramApiError("deleteMessage", "message can't be deleted")

        with mock.patch.object(tg, "call", side_effect=fake_call):
            remote = tg_fetch.lookup_message_file(9117250551, 236, self._args(), lambda _m: None)
        self.assertEqual(remote.file_name, "com.netease.newspike_1.003.650026.xapk")

    def test_forward_to_another_chat_is_honoured(self):
        calls = []

        def fake_call(method, **kwargs):
            calls.append(kwargs.get("params"))
            return dict(self.forwarded) if method == "forwardMessage" else True

        with mock.patch.object(tg, "call", side_effect=fake_call):
            tg_fetch.lookup_message_file(
                9117250551, 236, self._args("--forward-to", "-100123"), lambda _m: None
            )
        self.assertEqual(calls[0]["chat_id"], "-100123")
        self.assertEqual(calls[0]["from_chat_id"], 9117250551)

    def test_message_id_parsing(self):
        self.assertEqual(tg_fetch._message_id_from(self._args("--message", "236")), 236)
        self.assertEqual(
            tg_fetch._message_id_from(self._args("--message", "https://t.me/c/1234567890/77")), 77
        )
        self.assertIsNone(tg_fetch._message_id_from(self._args()))
        self.assertEqual(tg_fetch._message_id_from(self._args(), fallback=5), 5)
        self.assertIsNone(tg_fetch._message_id_from(self._args("--message", "not-a-number")))


# ---------------------------------------------------------------------------
# tg_fetch (download machinery, against a local HTTP server)
# ---------------------------------------------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    payload = b""
    truncate = False

    def do_GET(self):  # noqa: N802
        body = self.payload
        if _Handler.truncate:
            body = body[:-10]
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):  # silence the test output
        pass


class DownloadTests(unittest.TestCase):
    payload = b"blood-strike-archive" * 5000

    @classmethod
    def setUpClass(cls):
        _Handler.payload = cls.payload
        _Handler.truncate = False
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Handler.truncate = False
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)

    def test_download_writes_the_file_and_hashes_it(self):
        dest, size, sha256, _ = tg_fetch.download_url(f"{self.base}/archive.xapk", self.out / "archive.xapk")
        self.assertEqual(size, len(self.payload))
        self.assertEqual(dest.read_bytes(), self.payload)
        self.assertEqual(sha256, hashlib.sha256(self.payload).hexdigest())
        self.assertFalse((self.out / "archive.xapk.part").exists())

    def test_expected_size_mismatch_is_reported_and_no_part_is_left(self):
        with self.assertRaises(tg.TelegramError) as ctx:
            tg_fetch.download_url(
                f"{self.base}/archive.xapk",
                self.out / "archive.xapk",
                expected_size=len(self.payload) + 1,
                retries=1,
            )
        self.assertIn("size mismatch", str(ctx.exception))
        self.assertFalse((self.out / "archive.xapk.part").exists())

    def test_truncated_body_is_caught_by_the_declared_size(self):
        _Handler.truncate = True
        try:
            with self.assertRaises(tg.TelegramError):
                tg_fetch.download_url(
                    f"{self.base}/archive.xapk",
                    self.out / "archive.xapk",
                    expected_size=len(self.payload),
                    retries=1,
                )
        finally:
            _Handler.truncate = False

    def test_github_output_is_written(self):
        record = tg_fetch._record(self.out / "archive.xapk", 123, "abc", "test", {"kind": "test"})
        output = self.out / "github_output"
        old = os.environ.get("GITHUB_OUTPUT")
        os.environ["GITHUB_OUTPUT"] = str(output)
        try:
            tg_fetch._write_github_output(record)
        finally:
            if old is None:
                os.environ.pop("GITHUB_OUTPUT", None)
            else:
                os.environ["GITHUB_OUTPUT"] = old
        text = output.read_text(encoding="utf-8")
        self.assertIn("archive_path=", text)
        self.assertIn("archive_size=123", text)
        self.assertIn("sha256=abc", text)

    def test_no_github_output_is_not_an_error(self):
        old = os.environ.pop("GITHUB_OUTPUT", None)
        try:
            tg_fetch._write_github_output({"path": "x", "name": "x", "size": 1, "sha256": "y"})
        finally:
            if old is not None:
                os.environ["GITHUB_OUTPUT"] = old


# ---------------------------------------------------------------------------
# inspect_apks (synthetic XAPK: no 640 MB download involved)
# ---------------------------------------------------------------------------


def _apk_bytes(entries: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _write_synthetic_xapk(path: Path, *, arm64: bool, v7a: bool) -> Path:
    manifest = {
        "package_name": "com.netease.newspike",
        "version_code": 169,
        "version_name": "1.003.650026",
        "split_apks": [],
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("com.netease.newspike.apk", _apk_bytes({"AndroidManifest.xml": b"base"}))
        if arm64:
            manifest["split_apks"].append({"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"})
            archive.writestr(
                "config.arm64_v8a.apk",
                _apk_bytes(
                    {
                        "AndroidManifest.xml": b"arm64",
                        "lib/arm64-v8a/libGame.so": b"\x7fELF" + b"a" * 4096,
                        "lib/arm64-v8a/libmain.so": b"\x7fELF" + b"b" * 1024,
                    }
                ),
            )
        if v7a:
            manifest["split_apks"].append({"file": "config.armeabi_v7a.apk", "id": "config.armeabi_v7a"})
            archive.writestr(
                "config.armeabi_v7a.apk",
                _apk_bytes(
                    {
                        "AndroidManifest.xml": b"v7a",
                        "lib/armeabi-v7a/libGame.so": b"\x7fELF" + b"c" * 2048,
                    }
                ),
            )
        archive.writestr("base_mpk.apk", _apk_bytes({"assets/big.bin": b"x" * 2048}))
        archive.writestr("manifest.json", json.dumps(manifest))
    return path


class InspectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _run(self, archive: Path, *extra: str) -> int:
        report_dir = self.root / "report"
        return inspect_apks.main(
            [
                str(archive),
                "--out-dir",
                str(self.root / "unpacked"),
                "--report-dir",
                str(report_dir),
                "--quiet",
                *extra,
            ]
        )

    def test_both_abis_found(self):
        archive = _write_synthetic_xapk(self.root / "bs.xapk", arm64=True, v7a=True)
        code = self._run(archive, "--require", "arm64-v8a,armeabi-v7a")
        self.assertEqual(code, 0)
        report = json.loads((self.root / "report" / "abi_report.json").read_text())
        self.assertTrue(report["ok"])
        self.assertEqual(report["missing"], [])
        self.assertTrue(report["abis"]["arm64-v8a"]["present"])
        self.assertTrue(report["abis"]["armeabi-v7a"]["present"])
        self.assertEqual(report["abis"]["arm64-v8a"]["so_count"], 2)
        self.assertEqual(report["abis"]["arm64-v8a"]["bitness"], "64-bit")
        self.assertEqual(report["abis"]["armeabi-v7a"]["bitness"], "32-bit")
        self.assertIn("xapk", report["source"].lower())

    def test_missing_64_bit_fails_the_run(self):
        archive = _write_synthetic_xapk(self.root / "bs32.xapk", arm64=False, v7a=True)
        code = self._run(archive, "--require", "arm64-v8a,armeabi-v7a")
        self.assertEqual(code, 1)
        report = json.loads((self.root / "report" / "abi_report.json").read_text())
        self.assertFalse(report["ok"])
        self.assertEqual(report["missing"], ["arm64-v8a"])
        self.assertFalse(report["abis"]["arm64-v8a"]["present"])
        self.assertTrue(report["abis"]["armeabi-v7a"]["present"])

    def test_allow_missing_still_exits_zero(self):
        archive = _write_synthetic_xapk(self.root / "bs32b.xapk", arm64=False, v7a=True)
        self.assertEqual(self._run(archive, "--require", "arm64-v8a", "--allow-missing"), 0)

    def test_unknown_abi_is_a_usage_error(self):
        archive = _write_synthetic_xapk(self.root / "bs3.xapk", arm64=True, v7a=True)
        self.assertEqual(self._run(archive, "--require", "mips"), 2)

    def test_asset_packs_can_be_skipped(self):
        archive = _write_synthetic_xapk(self.root / "bs4.xapk", arm64=True, v7a=True)
        code = self._run(archive, "--require", "arm64-v8a", "--skip-asset-packs")
        self.assertEqual(code, 0)
        unpacked = self.root / "unpacked"
        self.assertFalse(list(unpacked.rglob("base_mpk.apk")))

    def test_markdown_report_mentions_the_verdict(self):
        archive = _write_synthetic_xapk(self.root / "bs5.xapk", arm64=True, v7a=True)
        markdown = self.root / "report" / "abi_report.md"
        code = self._run(archive, "--markdown-out", str(markdown))
        self.assertEqual(code, 0)
        text = markdown.read_text()
        self.assertIn("PASS", text)
        self.assertIn("arm64-v8a", text)
        self.assertIn("armeabi-v7a", text)

    def test_not_a_zip(self):
        broken = self.root / "broken.xapk"
        broken.write_bytes(b"this is not a zip file")
        self.assertEqual(self._run(broken), 2)


if __name__ == "__main__":
    unittest.main()
