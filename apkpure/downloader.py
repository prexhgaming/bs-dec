"""Resumable downloads with verification and CI-friendly progress output."""

from __future__ import annotations

import hashlib
import os
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional, TextIO, Tuple

from . import transport
from .errors import DownloadError, NetworkError, VerificationError, describe_exception

CHUNK_SIZE = 1 << 16
HASH_CHUNK_SIZE = 1 << 20
PART_SUFFIX = ".part"


@dataclass(frozen=True)
class FileHashes:
    """Digests of a file (or byte string)."""

    size: int
    sha256: str
    sha1: str
    md5: str
    crc32: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "size": self.size,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "crc32": self.crc32,
        }


def _new_digests() -> Dict[str, "hashlib._Hash"]:
    return {
        "sha256": hashlib.sha256(),
        "sha1": hashlib.sha1(),
        "md5": hashlib.md5(),
    }


def _finalize(digests: Dict[str, "hashlib._Hash"], size: int, crc: int) -> FileHashes:
    return FileHashes(
        size=size,
        sha256=digests["sha256"].hexdigest(),
        sha1=digests["sha1"].hexdigest(),
        md5=digests["md5"].hexdigest(),
        crc32=f"{crc & 0xFFFFFFFF:08x}",
    )


def hash_file(path: os.PathLike) -> FileHashes:
    """Read ``path`` once and return all digests we care about."""
    digests = _new_digests()
    crc = 0
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            crc = zlib.crc32(chunk, crc)
            for digest in digests.values():
                digest.update(chunk)
    return _finalize(digests, size, crc)


def hash_bytes(data: bytes) -> FileHashes:
    """Digests of an in-memory payload (used by tests and small files)."""
    digests = _new_digests()
    for digest in digests.values():
        digest.update(data)
    return _finalize(digests, len(data), zlib.crc32(data))


class Progress:
    """Progress reporter that stays readable in CI logs and on a TTY."""

    def __init__(
        self,
        label: str,
        total: Optional[int] = None,
        *,
        stream: Optional[TextIO] = None,
        enabled: bool = True,
        step: float = 0.1,
    ) -> None:
        self.label = label
        self.total = total
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = enabled
        self.step = step if step > 0 else 1.0
        self.started = time.monotonic()
        self.done = 0
        self._last_emit = 0.0
        self._next_mark = self.step
        self._tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._closed = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if not self.enabled:
            return
        self.started = time.monotonic()
        total = self.total
        if total:
            self._write(f"{self.label}: 0% of {transport.human_size(total)}")
        else:
            self._write(f"{self.label}: starting")

    def update(self, done: int) -> None:
        self.done = done
        if not self.enabled or self._closed:
            return
        if self.total:
            fraction = min(done / self.total, 1.0)
            if fraction + 1e-9 >= self._next_mark or fraction >= 1.0:
                self._next_mark = min(self._next_mark + self.step, 1.0 + 1e-9)
                self._emit(fraction)
        else:
            now = time.monotonic()
            if now - self._last_emit >= 2.0:
                self._last_emit = now
                self._write(f"{self.label}: {transport.human_size(done)} received")

    def finish(self, message: Optional[str] = None, level: str = "done") -> None:
        if not self.enabled or self._closed:
            return
        self._closed = True
        elapsed = max(time.monotonic() - self.started, 1e-6)
        speed = transport.human_size(self.done / elapsed) + "/s" if self.done else "n/a"
        text = message or f"{transport.human_size(self.done)} in {transport.human_duration(elapsed)} ({speed})"
        suffix = f"[{level}] " if level else ""
        if self._tty:
            self._write(f"\r{' ' * 79}\r{suffix}{self.label}: {text}")
        else:
            self._write(f"{suffix}{self.label}: {text}")

    # -- internals ---------------------------------------------------------
    def _emit(self, fraction: float) -> None:
        elapsed = max(time.monotonic() - self.started, 1e-6)
        speed = transport.human_size(self.done / elapsed)
        percent = fraction * 100
        bars = 24
        filled = int(round(percent / 100 * bars))
        bar = "#" * filled + "." * (bars - filled)
        line = (
            f"{self.label}: [{bar}] {percent:5.1f}% "
            f"{transport.human_size(self.done)}/{transport.human_size(self.total)} @ {speed}/s"
        )
        if self._tty:
            self._write("\r" + line.ljust(78))
        else:
            self._write(line)

    def _write(self, text: str) -> None:
        try:
            print(text, file=self.stream, flush=True)
        except (OSError, ValueError):
            self.enabled = False


@dataclass
class DownloadResult:
    """Outcome of a completed transfer."""

    path: Path
    hashes: FileHashes
    url: str
    resumed_from: int = 0
    elapsed: float = 0.0
    attempts: int = 1

    @property
    def size(self) -> int:
        return self.hashes.size

    @property
    def speed(self) -> float:
        return self.size / self.elapsed if self.elapsed > 0 else 0.0


RetryHook = Callable[[int, BaseException], None]


def download(
    url: str,
    dest: os.PathLike,
    *,
    headers: Optional[Dict[str, str]] = None,
    expected_size: Optional[int] = None,
    expected_sha1: Optional[str] = None,
    expected_sha256: Optional[str] = None,
    resume: bool = False,
    chunk_size: int = CHUNK_SIZE,
    timeout: float = transport.DEFAULT_TIMEOUT,
    retries: int = 4,
    progress: Optional[Progress] = None,
    byte_range: Optional[Tuple[int, Optional[int]]] = None,
    keep_partial: bool = True,
    log: Optional[Callable[[str], None]] = None,
) -> DownloadResult:
    """Stream ``url`` into ``dest``, resuming and verifying where possible.

    ``byte_range`` limits the transfer to an inclusive remote range, which is how
    a single split APK is pulled out of a remote XAPK bundle. A partial file is
    written to ``dest + '.part'`` and only renamed on success, so an interrupted
    CI job can resume on the next run.
    """
    destination = Path(dest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    part_path = destination.with_name(destination.name + PART_SUFFIX)

    remote_start = byte_range[0] if byte_range else 0
    remote_end = byte_range[1] if byte_range else None
    span_size = None if remote_end is None else remote_end - remote_start + 1
    expected_local = expected_size if expected_size is not None else span_size

    started = time.monotonic()
    offset = _initial_offset(part_path, resume=resume, expected=expected_local)
    resumed_from = offset
    attempts = 0
    last_error: Optional[BaseException] = None
    restart = False

    while True:
        attempts += 1
        if restart:
            _truncate(part_path)
            offset = 0
            restart = False
        try:
            offset = _transfer(
                url,
                part_path,
                offset=offset,
                remote_start=remote_start,
                remote_end=remote_end,
                headers=headers,
                chunk_size=chunk_size,
                timeout=timeout,
                progress=progress,
                expected_local=expected_local,
            )
            break
        except (NetworkError, DownloadError, VerificationError) as exc:
            last_error = exc
            if attempts > max(retries, 1):
                break
            if isinstance(exc, DownloadError) and "ignored our Range" in str(exc):
                restart = True
            else:
                offset = _file_size(part_path)
            if log:
                log(f"transfer interrupted ({describe_exception(exc)}); retrying #{attempts}")
            time.sleep(min(0.8 * (2 ** (attempts - 1)), 10.0) * 0.8)
        except transport.HttpError as exc:
            last_error = exc
            if exc.status == 416:
                restart = True
                if attempts > max(retries, 1):
                    break
                continue
            if exc.status >= 500 or exc.status == 429:
                if attempts > max(retries, 1):
                    break
                offset = _file_size(part_path)
                time.sleep(min(0.8 * (2 ** (attempts - 1)), 10.0) * 0.8)
                continue
            raise

    if last_error is not None and _file_size(part_path) != (expected_local or _file_size(part_path)):
        if not keep_partial:
            _unlink(part_path)
        raise last_error

    actual = _file_size(part_path)
    if expected_local is not None and actual != expected_local:
        if not keep_partial:
            _unlink(part_path)
        raise DownloadError(
            f"size mismatch for {destination.name}: got {actual} bytes, expected {expected_local}"
        )

    hashes = hash_file(part_path)
    _verify_hashes(destination.name, hashes, expected_sha1, expected_sha256)
    os.replace(part_path, destination)

    elapsed = max(time.monotonic() - started, 1e-6)
    result = DownloadResult(
        path=destination,
        hashes=hashes,
        url=url,
        resumed_from=resumed_from,
        elapsed=elapsed,
        attempts=attempts,
    )
    if progress is not None:
        progress.done = hashes.size
        progress.finish()
    return result


def _transfer(
    url: str,
    part_path: Path,
    *,
    offset: int,
    remote_start: int,
    remote_end: Optional[int],
    headers: Optional[Dict[str, str]],
    chunk_size: int,
    timeout: float,
    progress: Optional[Progress],
    expected_local: Optional[int],
) -> int:
    """One (possibly resumed) transfer attempt; returns the final local size."""
    request_headers = transport.request_headers(headers)
    if offset > 0 or remote_end is not None:
        first = remote_start + offset
        last = "" if remote_end is None else str(remote_end)
        request_headers["Range"] = f"bytes={first}-{last}"

    meta, stream = transport.open_stream(url, headers=request_headers, timeout=timeout)
    try:
        if offset > 0:
            if meta.status != 206:
                raise DownloadError(f"server ignored our Range request (HTTP {meta.status})")
            span = meta.content_range
            if span is None or span[0] != remote_start + offset:
                raise DownloadError("server resumed at an unexpected offset")
        elif meta.status not in (200, 206):
            raise DownloadError(f"unexpected HTTP {meta.status} while downloading")

        total = expected_local
        if total is None and meta.total_size is not None:
            total = meta.total_size - remote_start
        if progress is not None:
            progress.total = total
            progress.done = offset

        written = offset
        mode = "ab" if offset else "wb"
        with open(part_path, mode) as handle:
            while True:
                try:
                    chunk = stream.read(chunk_size)
                except (OSError, TimeoutError) as exc:
                    raise NetworkError(f"read failed after {written} bytes: {exc}") from exc
                if not chunk:
                    break
                handle.write(chunk)
                written += len(chunk)
                if progress is not None:
                    progress.update(written)
            handle.flush()
            os.fsync(handle.fileno())
        return written
    finally:
        stream.close()


def _verify_hashes(
    label: str,
    hashes: FileHashes,
    expected_sha1: Optional[str],
    expected_sha256: Optional[str],
) -> None:
    if expected_sha1 and expected_sha1.lower() != hashes.sha1.lower():
        raise VerificationError(
            f"sha1 mismatch for {label}: got {hashes.sha1}, expected {expected_sha1.lower()}"
        )
    if expected_sha256 and expected_sha256.lower() != hashes.sha256.lower():
        raise VerificationError(
            f"sha256 mismatch for {label}: got {hashes.sha256}, expected {expected_sha256.lower()}"
        )


def _initial_offset(part_path: Path, *, resume: bool, expected: Optional[int]) -> int:
    if not resume or not part_path.exists():
        return 0
    size = _file_size(part_path)
    if expected is not None and size > expected:
        _truncate(part_path)
        return 0
    if expected is not None and size == expected:
        # Already complete: keep it and let the size check pass without network IO.
        return size
    return size


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _truncate(path: Path) -> None:
    try:
        with open(path, "wb"):
            pass
    except OSError:
        pass


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
