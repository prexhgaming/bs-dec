"""Resumable download with incremental hashing.

The transfer host advertises ``Accept-Ranges: bytes``, so a 700 MB download that
dies at 90% only costs the user the last 10%: everything is written to
``<name>.part`` and the next attempt asks for the remaining byte range. The hash
is computed while streaming, and the part file is only renamed into place after
size and (optionally) SHA-256 check out — a corrupt transfer can never look like
a finished file.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from . import http
from .errors import DownloadError, NetworkError, VerificationError, describe_exception

HASH_CHUNK = 1 << 20


@dataclass(frozen=True)
class DownloadResult:
    """What a finished (or already present) download looks like."""

    path: Path
    size: int
    sha256: str
    url: str
    elapsed: float
    resumed_from: int = 0
    already_present: bool = False

    @property
    def speed(self) -> float:
        if self.elapsed <= 0:
            return 0.0
        return self.size / self.elapsed

    def as_dict(self) -> Dict[str, object]:
        return {
            "path": str(self.path),
            "size": self.size,
            "sha256": self.sha256,
            "url": self.url,
            "elapsed_seconds": round(self.elapsed, 3),
            "resumed_from": self.resumed_from,
            "already_present": self.already_present,
        }


def hash_file(path: os.PathLike) -> str:
    """SHA-256 of a file on disk (used to check an existing download)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class Progress:
    """Throttled progress line (percent, transferred, speed, ETA)."""

    def __init__(
        self,
        *,
        total: Optional[int],
        prefix: str = "",
        stream=None,
        interval: float = 1.0,
        log: Optional[http.Log] = None,
    ) -> None:
        self.total = total
        self.prefix = prefix
        self.interval = interval
        self.log = log
        self.stream = stream
        self.done = 0
        self.started = time.monotonic()
        self._last = 0.0

    def advance(self, count: int) -> None:
        self.done += count
        now = time.monotonic()
        if now - self._last < self.interval:
            return
        self._last = now
        self.render(final=False)

    def render(self, *, final: bool) -> None:
        elapsed = max(time.monotonic() - self.started, 1e-6)
        speed = self.done / elapsed
        if self.total:
            percent = min(100.0, self.done * 100.0 / self.total)
            eta = ""
            if speed > 0 and self.done < self.total:
                remaining = (self.total - self.done) / speed
                eta = f", {_duration(remaining + elapsed)} elapsed, {_duration(remaining)} left"
            line = (
                f"{self.prefix}{percent:5.1f}%  {http.human_size(self.done)} / "
                f"{http.human_size(self.total)}  {http.human_size(speed)}/s{eta}"
            )
        else:
            line = f"{self.prefix}{http.human_size(self.done)}  {http.human_size(speed)}/s"
        _emit(line, self.stream, final=final)

    def finish(self, note: str = "") -> None:
        self.render(final=True)
        if note:
            _emit(f"{self.prefix}{note}", self.stream, final=True)


def _emit(line: str, stream, *, final: bool) -> None:
    if stream is None:
        return
    end = "\n" if final else "\r"
    try:
        stream.write(f"{line}{end}")
        stream.flush()
    except (ValueError, OSError):
        return


def _duration(seconds: float) -> str:
    seconds = max(seconds, 0)
    minutes, rest = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{rest:02d}s"
    return f"{rest}s"


def download(
    url: str,
    dest: os.PathLike,
    *,
    expected_size: Optional[int] = None,
    expected_sha256: Optional[str] = None,
    resume: bool = True,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
    retries: int = 3,
    progress: Optional[Progress] = None,
    log: Optional[http.Log] = None,
) -> DownloadResult:
    """Download ``url`` to ``dest``, resuming and verifying as described above."""
    logger = log or (lambda _message: None)
    destination = Path(dest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_name(destination.name + ".part")

    if destination.exists() and not part.exists():
        size = destination.stat().st_size
        digest = hash_file(destination) if expected_sha256 else ""
        if (expected_size is None or size == expected_size) and (
            not expected_sha256 or digest == expected_sha256.lower()
        ):
            logger(f"already downloaded: {destination.name} ({http.human_size(size)})")
            return DownloadResult(
                path=destination,
                size=size,
                sha256=digest,
                url=url,
                elapsed=0.0,
                already_present=True,
            )
        logger(f"{destination.name} does not match the expected file, replacing it")

    started = time.monotonic()
    resumed_from = 0
    last_error: Optional[BaseException] = None

    for attempt in range(1, max(retries, 1) + 1):
        offset = part.stat().st_size if (resume and part.exists()) else 0
        if offset and expected_size is not None and offset > expected_size:
            logger(f"{part.name} is larger than expected, starting over")
            offset = 0
        if offset:
            logger(f"resuming {destination.name} at {http.human_size(offset)}")
        resumed_from = offset
        try:
            size, digest = _transfer(
                url,
                part,
                offset=offset,
                expected_size=expected_size,
                headers=headers,
                timeout=timeout,
                progress=progress,
                log=log,
            )
        except (NetworkError, DownloadError) as exc:
            last_error = exc
            if attempt >= max(retries, 1):
                break
            wait = min(2.0 * attempt, 10.0)
            logger(f"transfer interrupted ({describe_exception(exc)}), retrying in {wait:.0f}s")
            time.sleep(wait)
            continue
        except VerificationError:
            _remove(part)
            raise

        if expected_size is not None and size != expected_size:
            _remove(part)
            raise VerificationError(
                f"{destination.name} is {size} bytes, expected {expected_size} "
                "(the transfer was truncated; run again to start over)"
            )
        if expected_sha256 and digest != expected_sha256.lower():
            _remove(part)
            raise VerificationError(
                f"sha256 mismatch for {destination.name}: got {digest}, expected {expected_sha256.lower()}"
            )
        os.replace(part, destination)
        elapsed = time.monotonic() - started
        return DownloadResult(
            path=destination,
            size=size,
            sha256=digest,
            url=url,
            elapsed=elapsed,
            resumed_from=resumed_from,
        )

    assert last_error is not None
    raise DownloadError(
        f"could not download {url} after {retries} attempt(s): {describe_exception(last_error)}"
    )


def _transfer(
    url: str,
    part: Path,
    *,
    offset: int,
    expected_size: Optional[int],
    headers: Optional[Dict[str, str]],
    timeout: float,
    progress: Optional[Progress],
    log: Optional[http.Log],
) -> Tuple[int, str]:
    logger = log or (lambda _message: None)
    byte_range = None
    if offset:
        byte_range = (offset, expected_size - 1 if expected_size else 1 << 62)

    response = http.open_response(url, byte_range=byte_range, headers=headers, timeout=timeout)
    try:
        status = getattr(response, "status", 200)
        response_headers = {str(k).lower(): str(v) for k, v in dict(getattr(response, "headers", {})).items()}
        if offset and status == 200:
            # The server ignored the Range header: start from scratch.
            logger("server ignored the range request, downloading from the beginning")
            offset = 0
        digest = hashlib.sha256()
        mode = "r+b" if offset else "wb"
        with open(part, mode) as handle:
            if offset:
                handle.seek(0)
                remaining = offset
                while remaining > 0:
                    chunk = handle.read(min(HASH_CHUNK, remaining))
                    if not chunk:
                        break
                    digest.update(chunk)
                    remaining -= len(chunk)
                handle.seek(offset)
                handle.truncate(offset)
            else:
                handle.truncate(0)
            if progress is not None:
                progress.done = offset
            written = offset
            for chunk in http.iter_chunks(response):
                handle.write(chunk)
                digest.update(chunk)
                written += len(chunk)
                if progress is not None:
                    progress.advance(len(chunk))
            handle.flush()
            os.fsync(handle.fileno())
        return written, digest.hexdigest()
    finally:
        try:
            response.close()
        except Exception:  # noqa: BLE001 - closing must never mask the real error
            pass


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
