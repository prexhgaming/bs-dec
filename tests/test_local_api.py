"""Tests for the self-hosted (local mode) Bot API server support.

Covers the docker command we generate, the ``getFile`` absolute-path fast route
(local mode returns a path on disk, so the archive is not transferred twice) and
the `local_api.py` CLI behaviour — all without docker and without network.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.server
import io
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import local_api  # noqa: E402
import tg_common as tg  # noqa: E402
import tg_fetch  # noqa: E402

CONTAINER_DIR = "/var/lib/telegram-bot-api"
LOCAL_BASE_HINT = "export TELEGRAM_API_BASE=http://127.0.0.1:8081"


@contextlib.contextmanager
def temp_dir(prefix="bs-dec-test-"):
    """A temporary directory whose removal is best-effort.

    Emulated filesystems (proot/overlayfs) sometimes fail to remove a hard link
    and then answer ``ENOTEMPTY`` for the directory itself, which would turn a
    passing test into an error in cleanup. Each test asserts what it needs.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# docker command generation
# ---------------------------------------------------------------------------


class DockerCommandTests(unittest.TestCase):
    def test_run_command_asks_for_local_mode(self):
        command = local_api.build_run_command(host_dir=Path("/srv/tg"))
        self.assertEqual(command[:3], ["docker", "run", "-d"])
        self.assertIn("TELEGRAM_LOCAL=1", command)
        self.assertIn("aiogram/telegram-bot-api:latest", command)
        self.assertIn("/srv/tg:/var/lib/telegram-bot-api", command)
        self.assertIn("127.0.0.1:8081:8081", command)

    def test_credentials_are_referenced_by_name_not_by_value(self):
        with mock.patch.dict(
            os.environ, {"TELEGRAM_API_ID": "1234567", "TELEGRAM_API_HASH": "deadbeef"}, clear=False
        ):
            joined = " ".join(local_api.build_run_command(host_dir=Path("/srv/tg")))
        self.assertIn("TELEGRAM_API_ID", joined)
        self.assertIn("TELEGRAM_API_HASH", joined)
        # the values must never land in argv (visible through ps / workflow logs)
        self.assertNotIn("1234567", joined)
        self.assertNotIn("deadbeef", joined)

    def test_never_binds_to_all_interfaces(self):
        self.assertNotIn("0.0.0.0", " ".join(local_api.build_run_command(host_dir=Path("/srv/tg"))))

    def test_custom_port_and_mount(self):
        command = local_api.build_run_command(host_dir=Path("/data"), port=9999)
        self.assertIn("127.0.0.1:9999:8081", command)
        self.assertIn("/data:/var/lib/telegram-bot-api", command)

    def test_stop_removes_the_container(self):
        self.assertEqual(local_api.build_stop_commands("tg-bot-api"), [["docker", "rm", "-f", "tg-bot-api"]])

    def test_base_url(self):
        self.assertEqual(local_api.local_base_url(), "http://127.0.0.1:8081")
        self.assertEqual(local_api.local_base_url(port=9000), "http://127.0.0.1:9000")


class OptionOrderTests(unittest.TestCase):
    """Shared options must work before *and* after the subcommand."""

    def _parse(self, argv):
        args = local_api.build_parser().parse_args(argv)
        for key, value in local_api.DEFAULT_OPTIONS.items():
            if not hasattr(args, key):
                setattr(args, key, value)
        return args

    def test_defaults(self):
        args = self._parse(["status"])
        self.assertEqual(args.port, 8081)
        self.assertEqual(args.host_dir, ".tg-bot-api")
        self.assertEqual(args.name, "tg-bot-api")
        self.assertFalse(args.quiet)

    def test_option_after_subcommand(self):
        self.assertEqual(self._parse(["status", "--port", "9001"]).port, 9001)

    def test_option_before_subcommand_is_not_overwritten(self):
        args = self._parse(["--port", "9002", "--host-dir", "/data", "status"])
        self.assertEqual(args.port, 9002)
        self.assertEqual(args.host_dir, "/data")

    def test_subcommand_options_still_work(self):
        self.assertTrue(self._parse(["start", "--restart"]).restart)


class _NotFoundHandler(http.server.BaseHTTPRequestHandler):
    """Answers 404, like a live Bot API server does on '/', so it counts as ready."""

    def do_GET(self):  # noqa: N802
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):  # keep test output clean
        pass


class ReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), _NotFoundHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_404_counts_as_reachable(self):
        self.assertTrue(local_api.is_local_admin_reachable(self.url, timeout=2))

    def test_wait_until_ready_returns_true_when_up(self):
        self.assertTrue(local_api.wait_until_ready(self.url, timeout=5, interval=0.1))

    def test_dead_port_is_not_reachable(self):
        self.assertFalse(local_api.is_local_admin_reachable("http://127.0.0.1:9", timeout=1))

    def test_wait_until_ready_times_out(self):
        with mock.patch.object(local_api, "is_local_admin_reachable", return_value=False):
            self.assertFalse(local_api.wait_until_ready("http://127.0.0.1:9", timeout=0.3, interval=0.1))


# ---------------------------------------------------------------------------
# CLI behaviour (docker calls mocked)
# ---------------------------------------------------------------------------


def run_main(argv, *, docker=True, ready=True):
    """Run ``local_api.main`` with docker mocked; returns ``(code, stdout, stderr, runner)``."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(local_api, "docker_available", return_value=docker), \
         mock.patch.object(local_api, "wait_until_ready", return_value=ready), \
         mock.patch.object(local_api, "_run", return_value=_completed()) as runner:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = local_api.main(argv)
    return code, out.getvalue(), err.getvalue(), runner


def without_credentials():
    """os.environ minus the two credential variables."""
    env = dict(os.environ)
    env.pop("TELEGRAM_API_ID", None)
    env.pop("TELEGRAM_API_HASH", None)
    return mock.patch.dict(os.environ, env, clear=True)


class StartCommandTests(unittest.TestCase):
    def test_missing_credentials_explains_where_to_get_them(self):
        with without_credentials():
            code, _out, err, runner = run_main(["start", "--host-dir", "/tmp/x"])
        self.assertEqual(code, 2)
        self.assertIn("my.telegram.org", err)
        self.assertIn("TELEGRAM_API_ID", err)
        runner.assert_not_called()

    def test_missing_credentials_never_starts_docker(self):
        with without_credentials():
            _code, _out, _err, runner = run_main(["start"])
        runner.assert_not_called()

    def test_dry_run_prints_the_command_instead(self):
        with without_credentials():
            code, _out, err, runner = run_main(
                ["start", "--host-dir", "/tmp/x", "--allow-missing-credentials"]
            )
        self.assertEqual(code, 0)
        self.assertIn("docker run", err)
        self.assertIn("TELEGRAM_LOCAL=1", err)
        runner.assert_not_called()

    def test_start_runs_docker_and_reports_the_mapping(self):
        with mock.patch.dict(
            os.environ, {"TELEGRAM_API_ID": "1234567", "TELEGRAM_API_HASH": "deadbeef"}, clear=False
        ), temp_dir() as tmp:
            code, out, _err, runner = run_main(["start", "--host-dir", tmp])
            command = runner.call_args_list[0][0][0]
        self.assertEqual(code, 0)
        self.assertEqual(command[0], "docker")
        self.assertIn("TELEGRAM_LOCAL=1", command)
        self.assertIn(f"{tmp}:/var/lib/telegram-bot-api", command)
        self.assertIn(LOCAL_BASE_HINT, out)
        self.assertIn("--local-data-dir", out)

    def test_start_fails_when_the_server_never_answers(self):
        with mock.patch.dict(
            os.environ, {"TELEGRAM_API_ID": "1234567", "TELEGRAM_API_HASH": "deadbeef"}, clear=False
        ), temp_dir() as tmp:
            code, _out, err, _runner = run_main(["start", "--host-dir", tmp], ready=False)
        self.assertEqual(code, 1)
        self.assertIn("did not come up", err)

    def test_docker_missing_is_a_clear_error(self):
        code, _out, err, _runner = run_main(["start"], docker=False)
        self.assertEqual(code, 2)
        self.assertIn("docker is not available", err)

    def test_docker_command_subcommand_prints_without_running(self):
        with mock.patch.dict(
            os.environ, {"TELEGRAM_API_ID": "1234567", "TELEGRAM_API_HASH": "deadbeef"}, clear=False
        ):
            code, out, _err, runner = run_main(["docker-command"])
        self.assertEqual(code, 0)
        self.assertIn("docker run", out)
        self.assertNotIn("1234567", out)
        runner.assert_not_called()


class StopStatusTests(unittest.TestCase):
    def test_stop_without_docker_reports_it(self):
        code, _out, err, _runner = run_main(["stop"], docker=False)
        self.assertEqual(code, 2)
        self.assertIn("docker is not available", err)

    def test_stop_removes_the_container(self):
        code, _out, _err, runner = run_main(["stop", "--name", "tg-bot-api"])
        self.assertEqual(code, 0)
        self.assertEqual(runner.call_args_list[0][0][0], ["docker", "rm", "-f", "tg-bot-api"])

    def test_status_ok_when_reachable(self):
        with mock.patch.object(local_api, "is_local_admin_reachable", return_value=True):
            code, out, _err, _runner = run_main(["status"], docker=False)
        self.assertEqual(code, 0)
        self.assertIn("reachable", out)

    def test_status_fails_when_down(self):
        with mock.patch.object(local_api, "is_local_admin_reachable", return_value=False):
            code, _out, _err, _runner = run_main(["status"], docker=False)
        self.assertEqual(code, 1)


class LogoutCloudTests(unittest.TestCase):
    def test_logout_calls_the_cloud_api(self):
        with mock.patch.object(tg, "call", return_value=True) as call:
            code, out, _err, _runner = run_main(["logout-cloud"])
        self.assertEqual(code, 0)
        self.assertEqual(call.call_args[0][0], "logOut")
        self.assertEqual(call.call_args[1]["base"], tg.DEFAULT_API_BASE)
        self.assertIn("logged out", out)

    def test_logout_failure_is_reported(self):
        with mock.patch.object(
            tg, "call", side_effect=tg.TelegramApiError("logOut", "Unauthorized", 401)
        ):
            code, _out, err, _runner = run_main(["logout-cloud"])
        self.assertEqual(code, 1)
        self.assertIn("Unauthorized", err)

    def test_unexpected_result_is_an_error(self):
        with mock.patch.object(tg, "call", return_value={"weird": True}):
            code, _out, err, _runner = run_main(["logout-cloud"])
        self.assertEqual(code, 1)
        self.assertIn("unexpected", err)


# ---------------------------------------------------------------------------
# getFile returning an absolute local path (the --local fast route)
# ---------------------------------------------------------------------------


class MapLocalFileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="bs-dec-test-"))
        self.addCleanup(shutil.rmtree, str(self.root), ignore_errors=True)
        self.payload = self.root / "1456253845:AAH" / "documents" / "file_42.xapk"
        self.payload.parent.mkdir(parents=True)
        self.payload.write_bytes(b"blood-strike")

    def test_container_path_is_mapped_through_the_mount(self):
        resolved = tg.map_local_file(
            f"{CONTAINER_DIR}/1456253845:AAH/documents/file_42.xapk",
            host_dir=str(self.root),
            container_dir=CONTAINER_DIR,
        )
        self.assertEqual(resolved, self.payload)

    def test_same_machine_absolute_path_is_used_directly(self):
        self.assertEqual(tg.map_local_file(str(self.payload)), self.payload)

    def test_http_style_relative_path_is_not_a_local_file(self):
        self.assertIsNone(tg.map_local_file("documents/file_42.xapk", host_dir=str(self.root)))

    def test_missing_file_returns_none(self):
        self.assertIsNone(
            tg.map_local_file(
                f"{CONTAINER_DIR}/ghost/documents/nope.xapk",
                host_dir=str(self.root),
                container_dir=CONTAINER_DIR,
            )
        )

    def test_empty_values(self):
        self.assertIsNone(tg.map_local_file(None))
        self.assertIsNone(tg.map_local_file(""))

    def test_container_path_without_host_dir_is_not_guessed(self):
        self.assertIsNone(tg.map_local_file(f"{CONTAINER_DIR}/x/documents/file_42.xapk"))


class CopyLocalFileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="bs-dec-test-"))
        self.addCleanup(shutil.rmtree, str(self.root), ignore_errors=True)
        self.src = self.root / "server-copy.xapk"
        self.src.write_bytes(b"X" * 4096 + b"tail")

    def test_copy_matches_byte_for_byte(self):
        dest = self.root / "out" / "copy.xapk"
        path, size, sha256 = tg_fetch.copy_local_file(self.src, dest)
        self.assertEqual(path, dest)
        self.assertEqual(size, self.src.stat().st_size)
        self.assertEqual(path.read_bytes(), self.src.read_bytes())
        self.assertEqual(sha256, hashlib.sha256(self.src.read_bytes()).hexdigest())

    def test_hard_link_is_tried_first(self):
        dest = self.root / "linked.xapk"
        with mock.patch.object(tg_fetch.os, "link", wraps=os.link) as linker:
            path, _size, _sha = tg_fetch.copy_local_file(self.src, dest)
        self.assertTrue(linker.called)
        self.assertEqual(path.read_bytes(), self.src.read_bytes())

    def test_falls_back_to_a_real_copy(self):
        dest = self.root / "plain.xapk"
        with mock.patch.object(tg_fetch.os, "link", side_effect=OSError("cross-device link")):
            path, _size, _sha = tg_fetch.copy_local_file(self.src, dest)
        self.assertEqual(path.read_bytes(), self.src.read_bytes())
        self.assertNotEqual(os.stat(path).st_ino, os.stat(self.src).st_ino)

    def test_no_part_file_is_left_behind(self):
        tg_fetch.copy_local_file(self.src, self.root / "done.xapk")
        self.assertEqual(sorted(item.name for item in self.root.glob("*.part")), [])


class _StoredPayloadMixin(unittest.TestCase):
    """A fake Bot API server data dir holding the 'downloaded' archive."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="bs-dec-test-"))
        self.addCleanup(shutil.rmtree, str(self.root), ignore_errors=True)
        self.data_dir = self.root / "server-data"
        self.stored = self.data_dir / "1456253845:AAH" / "documents" / "file_7.xapk"
        self.stored.parent.mkdir(parents=True)
        self.body = b"bs" * 5000
        self.stored.write_bytes(self.body)
        self.remote = tg.RemoteFile(
            file_id="FILEID",
            file_name="com.netease.newspike.xapk",
            file_size=len(self.body),
            chat_id=9117250551,
            message_id=241,
        )

    def _args(self, *extra):
        base = [
            "--chat", "9117250551",
            "--message", "241",
            "--token", "123:abc",
            "--out-dir", str(self.root / "work"),
            "--local-data-dir", str(self.data_dir),
            "--quiet",
        ]
        return tg_fetch.build_parser().parse_args(base + list(extra))


class LocalPathFetchTests(_StoredPayloadMixin):
    def test_absolute_path_is_copied_not_downloaded(self):
        args = self._args()
        dest = Path(args.out_dir) / "out.xapk"
        with mock.patch.object(tg, "get_file", return_value={"file_path": str(self.stored)}), \
             mock.patch.object(
                 tg_fetch, "download_url", side_effect=AssertionError("HTTP download must not happen")
             ):
            path, size, sha256, how, file_path = tg_fetch._fetch_remote_file(
                self.remote, dest, args, lambda _m: None
            )
        self.assertEqual(how, "local-path")
        self.assertEqual(path.read_bytes(), self.body)
        self.assertEqual(size, len(self.body))
        self.assertEqual(sha256, hashlib.sha256(self.body).hexdigest())
        self.assertEqual(file_path, str(self.stored))

    def test_size_mismatch_is_refused(self):
        args = self._args()
        wrong = tg.RemoteFile(file_id="FILEID", file_name="x.xapk", file_size=len(self.body) + 10)
        with mock.patch.object(tg, "get_file", return_value={"file_path": str(self.stored)}):
            with self.assertRaises(tg.TelegramError):
                tg_fetch._fetch_remote_file(wrong, Path(args.out_dir) / "out.xapk", args, lambda _m: None)

    def test_max_size_is_enforced_for_local_copies(self):
        args = self._args("--max-size", "10")
        with mock.patch.object(tg, "get_file", return_value={"file_path": str(self.stored)}):
            with self.assertRaises(tg.TelegramError):
                tg_fetch._fetch_remote_file(self.remote, Path(args.out_dir) / "out.xapk", args, lambda _m: None)

    def test_unreadable_local_copy_falls_back_to_http(self):
        args = self._args()
        dest = Path(args.out_dir) / "fallback.xapk"
        with mock.patch.object(tg, "get_file", return_value={"file_path": str(self.stored)}), \
             mock.patch.object(tg_fetch, "copy_local_file", side_effect=PermissionError("denied")), \
             mock.patch.object(
                 tg_fetch, "download_url", return_value=(dest, 4, "0" * 64, "http")
             ) as downloader:
            _path, _size, _sha, how, _fp = tg_fetch._fetch_remote_file(
                self.remote, dest, args, lambda _m: None
            )
        self.assertEqual(how, "http")
        self.assertTrue(downloader.called)

    def test_relative_file_path_uses_http(self):
        args = self._args()
        dest = Path(args.out_dir) / "http.xapk"
        with mock.patch.object(tg, "get_file", return_value={"file_path": "documents/file_7.xapk"}), \
             mock.patch.object(
                 tg_fetch, "download_url", return_value=(dest, 4, "0" * 64, "http")
             ) as downloader:
            _path, _size, _sha, how, _fp = tg_fetch._fetch_remote_file(
                self.remote, dest, args, lambda _m: None
            )
        self.assertEqual(how, "http")
        self.assertIn("/file/bot123:abc/documents/file_7.xapk", downloader.call_args[0][0])

    def test_main_uses_the_local_copy_end_to_end(self):
        def fake_call(method, *, params=None, **kwargs):
            params = params or {}
            if method == "forwardMessage":
                return {
                    "message_id": params["message_id"],
                    "chat": {"id": 9117250551},
                    "document": {
                        "file_id": "FILEID",
                        "file_unique_id": "U1",
                        "file_name": "com.netease.newspike.xapk",
                        "file_size": len(self.body),
                    },
                }
            if method == "getFile":
                return {"file_path": str(self.stored)}
            if method == "deleteMessage":
                return True
            raise AssertionError(f"unexpected call {method}")

        argv = [
            "--chat", "9117250551", "--message", "241", "--token", "123:abc",
            "--out-dir", str(self.root / "work"),
            "--local-data-dir", str(self.data_dir), "--quiet",
        ]
        with mock.patch.object(tg, "call", side_effect=fake_call), \
             mock.patch.object(tg_fetch, "download_url", side_effect=AssertionError("must not download")):
            code = tg_fetch.main(argv)
        self.assertEqual(code, 0)

        record = json.loads((self.root / "work" / "fetch.json").read_text())
        self.assertEqual(record["source"]["kind"], "telegram")
        self.assertEqual(record["source"]["transfer"], "local-path")
        self.assertEqual(record["size"], len(self.body))
        self.assertEqual((self.root / "work" / "com.netease.newspike.xapk").read_bytes(), self.body)


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


if __name__ == "__main__":
    unittest.main()
