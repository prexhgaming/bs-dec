#!/usr/bin/env python3
"""Run a **self-hosted Telegram Bot API server** in local mode for this project.

Why this exists
---------------
Telegram's hosted API (``https://api.telegram.org``) refuses ``getFile`` for files
larger than ~20 MB (``400: Bad Request: file is too big``). The Blood Strike
archive is ~640 MB, so it can never come through the hosted API in one piece. A
server *you* run with ``--local`` has no download limit (uploads up to 2000 MB).

Two extra wins from local mode:
* ``getFile`` returns the **absolute local path** of the file instead of an HTTP
  URL, so ``tg_fetch.py`` can read/copy the archive straight out of the server's
  directory — the ~640 MB is transferred exactly once, not twice.
* the file lands in ``--host-dir`` on this machine, where the unpack step can use
  it directly.

Official requirements this script takes care of
-----------------------------------------------
1. The server needs ``api_id``/``api_hash`` (free: https://my.telegram.org).
   They are passed **by name** (``-e TELEGRAM_API_ID``) so the values never appear
   in argv, ``ps`` output or logs.
2. A bot must be deregistered from the cloud API (``logOut``) before a local
   server is reliable — see the ``logout-cloud`` subcommand. Telegram then blocks
   logging back into the cloud API for ~10 minutes, so it is a separate step.

Usage
-----
    export TELEGRAM_BOT_TOKEN=...        # from @BotFather
    export TELEGRAM_API_ID=... TELEGRAM_API_HASH=...   # from my.telegram.org

    python scripts/local_api.py start --host-dir .tg-bot-api
    python scripts/local_api.py logout-cloud      # one-time migration step
    TELEGRAM_API_BASE=http://127.0.0.1:8081 python scripts/tg_fetch.py \
        --chat 9117250551 --message 241 --local-data-dir .tg-bot-api --out-dir work
    python scripts/local_api.py stop

``python scripts/local_api.py docker-command`` prints the exact docker invocation
without running anything, which is handy for debugging.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tg_common as tg  # noqa: E402

DEFAULT_IMAGE = "aiogram/telegram-bot-api:latest"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8081
DEFAULT_CONTAINER_NAME = "tg-bot-api"
DEFAULT_HOST_DIR = ".tg-bot-api"
#: Working directory of the server inside the image; ``getFile`` paths start here.
DEFAULT_CONTAINER_DIR = "/var/lib/telegram-bot-api"
#: Defaults for the shared options. They are declared with ``default=SUPPRESS``
#: so a subparser never overwrites an option that was written *before* it on the
#: command line (argparse copies a subparser's defaults back over the parent's).
DEFAULT_OPTIONS = {
    "name": DEFAULT_CONTAINER_NAME,
    "host_dir": DEFAULT_HOST_DIR,
    "container_dir": DEFAULT_CONTAINER_DIR,
    "port": DEFAULT_PORT,
    "host": DEFAULT_HOST,
    "image": DEFAULT_IMAGE,
    "timeout": 90.0,
    "quiet": False,
}


def build_run_command(
    *,
    host_dir: Path,
    container_dir: str = DEFAULT_CONTAINER_DIR,
    port: int = DEFAULT_PORT,
    host: str = DEFAULT_HOST,
    image: str = DEFAULT_IMAGE,
    name: str = DEFAULT_CONTAINER_NAME,
) -> List[str]:
    """The ``docker run`` argv for a local-mode server.

    Credentials are referenced by *name* (``-e TELEGRAM_API_ID``) so the secret
    values are read from the environment by docker and never land in argv.
    """
    return [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "-p",
        f"{host}:{port}:8081",
        "-e",
        "TELEGRAM_API_ID",
        "-e",
        "TELEGRAM_API_HASH",
        "-e",
        "TELEGRAM_LOCAL=1",
        "-e",
        "TELEGRAM_VERBOSITY=1",
        "-v",
        f"{host_dir}:{container_dir}",
        image,
    ]


def build_stop_commands(name: str = DEFAULT_CONTAINER_NAME) -> List[List[str]]:
    """``docker rm -f <name>``; a running container is removed without a separate stop."""
    return [["docker", "rm", "-f", name]]


def local_base_url(port: int = DEFAULT_PORT, host: str = DEFAULT_HOST) -> str:
    return f"http://{host}:{port}"


def is_local_admin_reachable(url: str, timeout: float = 2.0) -> bool:
    """True as soon as the server answers *any* HTTP response (404 is fine)."""
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/", timeout=timeout):
            return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, OSError):
        return False


def wait_until_ready(url: str, *, timeout: float = 90.0, interval: float = 2.0, log=None) -> bool:
    note = log or (lambda _message: None)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_local_admin_reachable(url):
            return True
        time.sleep(interval)
    note(f"the server did not answer on {url} within {timeout:.0f}s")
    return False


def docker_available() -> bool:
    return shutil.which("docker") is not None


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_docker_command(args) -> int:
    command = build_run_command(
        host_dir=Path(args.host_dir).absolute(),
        container_dir=args.container_dir,
        port=args.port,
        host=args.host,
        image=args.image,
        name=args.name,
    )
    print(" ".join(command))
    return 0


def cmd_start(args) -> int:
    log = _logger(args)
    if not docker_available():
        print(
            "error: docker is not available here. Install/start docker, or point "
            "TELEGRAM_API_BASE at a Bot API server running elsewhere.",
            file=sys.stderr,
        )
        return 2

    missing = [name for name in ("TELEGRAM_API_ID", "TELEGRAM_API_HASH") if not os.environ.get(name)]
    if missing and not args.allow_missing_credentials:
        print(
            "error: "
            + " and ".join(missing)
            + " must be set: the Bot API server identifies your API client application with them.\n"
            "       Get them (free) at https://my.telegram.org -> API development tools, then:\n"
            "         export TELEGRAM_API_ID=1234567 TELEGRAM_API_HASH=abcdef0123456789abcdef0123456789\n"
            "       `--allow-missing-credentials` prints the command without starting anything.",
            file=sys.stderr,
        )
        return 2
    if missing:
        print(" ".join(build_run_command(host_dir=Path(args.host_dir).absolute(), port=args.port)), file=sys.stderr)
        print("(dry run: TELEGRAM_API_ID / TELEGRAM_API_HASH are not set)", file=sys.stderr)
        return 0

    host_dir = Path(args.host_dir).absolute()
    host_dir.mkdir(parents=True, exist_ok=True)

    if args.restart:
        log(f"removing any previous container named {args.name}")
        _run(build_stop_commands(args.name)[0], check=False)

    command = build_run_command(
        host_dir=host_dir,
        container_dir=args.container_dir,
        port=args.port,
        host=args.host,
        image=args.image,
        name=args.name,
    )
    log("starting the local Bot API server: " + " ".join(command[0:3] + ["...", args.image]))
    result = _run(command, check=False)
    if result.returncode != 0:
        print("error: docker run failed — see the output above", file=sys.stderr)
        return 1

    url = local_base_url(args.port, args.host)
    if not wait_until_ready(url, timeout=args.timeout, log=log):
        _run(["docker", "logs", "--tail", "40", args.name], check=False)
        print(f"error: the local Bot API server did not come up on {url}", file=sys.stderr)
        return 1

    print(f"local Bot API server is up on {url} (local mode: no download limit)")
    print(f"  file_path from getFile will look like {args.container_dir}/<token>/documents/...")
    print(f"  that directory is {host_dir} on this machine")
    print(f"  export TELEGRAM_API_BASE={url}")
    print("  pass --local-data-dir " + str(host_dir) + " to tg_fetch.py to copy the file straight from disk")
    if not args.no_migration_note:
        print(
            "  note: if in doubt, run `python scripts/local_api.py logout-cloud` once so the cloud API\n"
            "        releases the bot (official requirement before a local server serves it)"
        )
    return 0


def cmd_stop(args) -> int:
    if not docker_available():
        print("error: docker is not available here", file=sys.stderr)
        return 2
    for command in build_stop_commands(args.name):
        result = _run(command, check=False)
        if result.returncode == 0:
            print(f"stopped and removed container {args.name}")
        else:
            print(f"nothing to stop (no container named {args.name})")
    return 0


def cmd_status(args) -> int:
    url = local_base_url(args.port, args.host)
    reachable = is_local_admin_reachable(url)
    print(f"server: {'reachable' if reachable else 'not reachable'} at {url}")
    if docker_available():
        result = _run(["docker", "ps", "--filter", f"name={args.name}", "--format", "{{.Names}}\t{{.Status}}"], check=False)
        text = (result.stdout or "").strip()
        print(f"container: {text or 'not running'}")
    used = os.environ.get("TELEGRAM_API_BASE", "")
    print(f"TELEGRAM_API_BASE: {used or '(unset -> the cloud API is used)'}")
    return 0 if reachable else 1


def cmd_logout_cloud(args) -> int:
    """``logOut`` on the *cloud* API: the official step before using a local server."""
    log = _logger(args)
    try:
        result = tg.call("logOut", base=tg.DEFAULT_API_BASE, log=log)
    except tg.TelegramError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if result is True or result is None:
        print(
            "the bot is logged out of the cloud Bot API, so it can be used on the local server.\n"
            "  Telegram now refuses to log the bot back into the cloud API for about 10 minutes."
        )
        return 0
    print(f"unexpected logOut result: {result!r}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------


def _logger(args):
    if getattr(args, "quiet", False):
        return lambda _message: None
    return lambda message: print(f"· {message}", file=sys.stderr, flush=True)


def _run(command: Sequence[str], *, check: bool = True):
    try:
        return subprocess.run(list(command), check=check, capture_output=not check, text=True)
    except subprocess.CalledProcessError as exc:  # pragma: no cover - docker failures
        sys.stderr.write(exc.stdout or "")
        sys.stderr.write(exc.stderr or "")
        raise


def build_parser() -> argparse.ArgumentParser:
    # The shared options live in a parent parser so they can be written before
    # *or* after the subcommand: `local_api.py --host-dir X start` and
    # `local_api.py start --host-dir X` both work.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--name", default=argparse.SUPPRESS, help=f"container name (default: {DEFAULT_CONTAINER_NAME})")
    common.add_argument("--host-dir", default=argparse.SUPPRESS, help=f"host data dir to mount (default: {DEFAULT_HOST_DIR})")
    common.add_argument(
        "--container-dir",
        default=argparse.SUPPRESS,
        help=f"data dir inside the container (default: {DEFAULT_CONTAINER_DIR})",
    )
    common.add_argument("--port", type=int, default=argparse.SUPPRESS, help=f"local HTTP port (default: {DEFAULT_PORT})")
    common.add_argument("--host", default=argparse.SUPPRESS, help=f"bind address (default: {DEFAULT_HOST}, never 0.0.0.0)")
    common.add_argument("--image", default=argparse.SUPPRESS, help=f"docker image (default: {DEFAULT_IMAGE})")
    common.add_argument("--timeout", type=float, default=argparse.SUPPRESS, help="seconds to wait for the server (default: 90)")
    common.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS, help="less output")

    parser = argparse.ArgumentParser(
        prog="local_api.py",
        parents=[common],
        description="Run a self-hosted Telegram Bot API server (local mode) for big downloads.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  local_api.py start --host-dir .tg-bot-api\n"
            "  local_api.py logout-cloud\n"
            "  local_api.py status\n"
            "  local_api.py stop\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command")

    start = subparsers.add_parser("start", parents=[common], help="start the server (docker run)")
    start.add_argument("--restart", action="store_true", help="remove a container of the same name first")
    start.add_argument("--allow-missing-credentials", action="store_true", help="print the command instead of failing")
    start.add_argument("--no-migration-note", action="store_true", help="do not print the logOut reminder")
    start.set_defaults(func=cmd_start)

    subparsers.add_parser("stop", parents=[common], help="stop and remove the server").set_defaults(func=cmd_stop)
    subparsers.add_parser("status", parents=[common], help="is the local server reachable?").set_defaults(func=cmd_status)
    subparsers.add_parser(
        "logout-cloud",
        parents=[common],
        help="logOut on the cloud API (official one-time step before using a local server)",
    ).set_defaults(func=cmd_logout_cloud)
    subparsers.add_parser(
        "docker-command",
        parents=[common],
        help="print the docker command that would be used, then exit",
    ).set_defaults(func=cmd_docker_command)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for key, value in DEFAULT_OPTIONS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
