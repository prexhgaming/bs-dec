"""Streaming download with incremental hashing.

The transfer host advertises ``Accept-Ranges: bytes``, but resuming is not worth
the extra state here: a 700 MB pull on a runner finishes in well under a minute,
so every attempt simply starts over. The hash is computed while the bytes stream
in, and the file is only kept after size and (optionally) SHA-256 check out — a
corrupt or truncated transfer can never look like a finished file.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

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
    """Throttled progress line (percent, transferred, speed, elapsed/left)."""

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
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
    retries: int = 3,
    progress: Optional[Progress] = None,
    log: Optional[http.Log] = None,
) -> DownloadResult:
    """Stream ``url`` into ``dest`` and verify the result.

    An existing file that already matches is reused (handy on a CI re-run).
    Failed attempts delete their partial file, so the next attempt starts clean.
    """
    logger = log or (lambda _message: None)
    destination = Path(dest)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists():
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
    last_error: Optional[BaseException] = None
    attempts = max(retries, 1)

    for attempt in range(1, attempts + 1):
        try:
            size, digest = _transfer(
                url,
                destination,
                headers=headers,
                timeout=timeout,
                progress=progress,
                log=log,
            )
        except VerificationError:
            _remove(destination)
            raise
        except (NetworkError, DownloadError) as exc:
            last_error = exc
            _remove(destination)
            if attempt >= attempts:
                break
            wait = min(2.0 * attempt, 10.0)
            logger(f"transfer interrupted ({describe_exception(exc)}), retrying in {wait:.0f}s")
            time.sleep(wait)
            continue

        if expected_size is not None and size != expected_size:
            _remove(destination)
            raise VerificationError(
                f"{destination.name} is {size} bytes, expected {expected_size} "
                "(the transfer was truncated)"
            )
        if expected_sha256 and digest != expected_sha256.lower():
            _remove(destination)
            raise VerificationError(
                f"sha256 mismatch for {destination.name}: got {digest}, expected {expected_sha256.lower()}"
            )
        return DownloadResult(
            path=destination,
            size=size,
            sha256=digest,
            url=url,
            elapsed=time.monotonic() - started,
        )

    assert last_error is not None
    raise DownloadError(
        f"could not download {url} after {attempts} attempt(s): {describe_exception(last_error)}"
    )


def _transfer(
    url: str,
    destination: Path,
    *,
    headers: Optional[Dict[str, str]],
    timeout: float,
    progress: Optional[Progress],
    log: Optional[http.Log],
) -> Tuple[int, str]:
    logger = log or (lambda _message: None)
    response = http.open_response(url, headers=headers, timeout=timeout)
    digest = hashlib.sha256()
    written = 0
    try:
        status = getattr(response, "status", 200)
        if status not in (200, 206):
            raise DownloadError(f"unexpected HTTP {status} while downloading {url}")
        if progress is not None:
            progress.done = 0
        with open(destination, "wb") as handle:
            for chunk in http.iter_chunks(response):
                handle.write(chunk)
                digest.update(chunk)
                written += len(chunk)
                if progress is not None:
                    progress.advance(len(chunk))
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise DownloadError(f"could not write {destination}: {exc}") from exc
    finally:
        try:
            response.close()
        except Exception:  # noqa: BLE001 - closing must never mask the real error
            pass
    logger(f"received {http.human_size(written)} into {destination.name}")
    return written, digest.hexdigest()


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
