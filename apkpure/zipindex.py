"""Random-access reading of a zip archive that lives on an HTTP server.

APKPure serves split-APK bundles as ``.xapk`` files, which are ordinary zips: the
central directory sits at the end of the file and every entry is addressed by
absolute offset. Local headers and the tail index are a few KiB in total, so a
tool can enumerate the per-architecture splits and then fetch exactly one of
them with a single ranged request instead of pulling the whole (often 600 MB+)
bundle.
"""

from __future__ import annotations

import os
import struct
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import transport
from .downloader import DownloadResult, Progress, download, hash_bytes
from .errors import VerificationError, ZipIndexError, describe_exception

EOCD_SIGNATURE = b"PK\x05\x06"
CENTRAL_SIGNATURE = b"PK\x01\x02"
LOCAL_SIGNATURE = b"PK\x03\x04"
LOCAL_HEADER_SIZE = 30
EOCD_MIN_SIZE = 22
EOCD_SEARCH_SIZE = 65536 + EOCD_MIN_SIZE
ZIP64_MARKER = 0xFFFFFFFF
MAX_CENTRAL_DIRECTORY = 64 << 20
MAX_INFLATE_BUFFER = 320 << 20

Reader = Callable[[int, int], bytes]


@dataclass(frozen=True)
class ZipEntry:
    """One member of a remote zip archive."""

    name: str
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_header_offset: int

    @property
    def is_stored(self) -> bool:
        return self.method == 0

    @property
    def is_deflated(self) -> bool:
        return self.method == 8

    @property
    def ratio(self) -> float:
        if not self.uncompressed_size:
            return 0.0
        return self.compressed_size / self.uncompressed_size

    def describe(self) -> str:
        compression = {0: "store", 8: "deflate"}.get(self.method, f"method {self.method}")
        return (
            f"{self.name} ({compression}, {transport.human_size(self.uncompressed_size)}, "
            f"offset {self.local_header_offset})"
        )


class RemoteZip:
    """Zip archive reader backed by ranged HTTP reads.

    ``reader`` can be injected to make the class testable offline, or to serve
    the archive from a local file instead of the network.
    """

    def __init__(
        self,
        url: str,
        *,
        size: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = transport.DEFAULT_TIMEOUT,
        reader: Optional[Reader] = None,
        log: Optional[Callable[[str], None]] = None,
        retries: int = 4,
    ) -> None:
        self.url = url
        self.headers = headers
        self.timeout = timeout
        self.retries = retries
        self.log = log or (lambda _message: None)
        self._reader = reader
        self._size = size
        self._entries: Optional[List[ZipEntry]] = None

    # -- basic properties --------------------------------------------------
    @property
    def size(self) -> int:
        if self._size is None:
            info = transport.probe(self.url, headers=self.headers, timeout=self.timeout, sample=16)
            if info.size is None:
                raise ZipIndexError(f"cannot determine size of {self.url}")
            self._size = info.size
        return self._size

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    # -- index -------------------------------------------------------------
    @property
    def entries(self) -> List[ZipEntry]:
        if self._entries is None:
            self._entries = self._load_central_directory()
        return self._entries

    def names(self) -> List[str]:
        return [entry.name for entry in self.entries]

    def find(self, name: str) -> Optional[ZipEntry]:
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None

    def match(self, predicate: Callable[[ZipEntry], bool]) -> List[ZipEntry]:
        return [entry for entry in self.entries if predicate(entry)]

    def _load_central_directory(self) -> List[ZipEntry]:
        total = self.size
        if total < EOCD_MIN_SIZE:
            raise ZipIndexError("remote file is too small to be a zip archive")
        window_start = max(0, total - EOCD_SEARCH_SIZE)
        tail = self._read(window_start, total - 1)
        offset = tail.rfind(EOCD_SIGNATURE)
        if offset < 0:
            raise ZipIndexError("zip end-of-central-directory record not found")
        if len(tail) - offset < EOCD_MIN_SIZE:
            raise ZipIndexError("zip end-of-central-directory record is truncated")

        (
            _signature,
            _disk_number,
            _cd_disk,
            _entries_this_disk,
            entry_count,
            cd_size,
            cd_offset,
            _comment_length,
        ) = struct.unpack("<4sHHHHIIH", tail[offset:offset + EOCD_MIN_SIZE])

        if cd_offset == ZIP64_MARKER or cd_size == ZIP64_MARKER:
            raise ZipIndexError(
                "zip64 archives are not supported (offset/size marker found)"
            )
        if cd_size > MAX_CENTRAL_DIRECTORY:
            raise ZipIndexError(f"central directory is implausibly large ({cd_size} bytes)")
        if cd_offset + cd_size > total:
            raise ZipIndexError("central directory lies outside the remote file")

        self.log(f"index: {entry_count} entries, {transport.human_size(cd_size)} at offset {cd_offset}")
        blob = self._read(cd_offset, cd_offset + cd_size - 1)
        entries: List[ZipEntry] = []
        position = 0
        while position + 46 <= len(blob) and blob[position:position + 4] == CENTRAL_SIGNATURE:
            header = struct.unpack("<4sHHHHHHIIIHHHHHII", blob[position:position + 46])
            (
                _sig,
                _version_made_by,
                _version_needed,
                _flags,
                method,
                _mod_time,
                _mod_date,
                crc,
                compressed_size,
                uncompressed_size,
                name_length,
                extra_length,
                comment_length,
                _disk_start,
                _internal_attr,
                _external_attr,
                local_offset,
            ) = header
            name_start = position + 46
            name_end = name_start + name_length
            if name_end > len(blob):
                raise ZipIndexError("central directory entry runs past the end of the index")
            name = blob[name_start:name_end].decode("utf-8", "replace")
            if uncompressed_size == ZIP64_MARKER or compressed_size == ZIP64_MARKER:
                raise ZipIndexError(f"zip64 entry is not supported: {name}")
            entries.append(
                ZipEntry(
                    name=name,
                    method=method,
                    crc32=crc,
                    compressed_size=compressed_size,
                    uncompressed_size=uncompressed_size,
                    local_header_offset=local_offset,
                )
            )
            position = name_end + extra_length + comment_length

        if not entries:
            raise ZipIndexError("central directory contains no entries")
        return entries

    # -- payload -----------------------------------------------------------
    def data_offset(self, entry: ZipEntry) -> int:
        """Absolute offset of an entry's payload (after the local header)."""
        header = self._read(entry.local_header_offset, entry.local_header_offset + LOCAL_HEADER_SIZE - 1)
        if header[:4] != LOCAL_SIGNATURE:
            raise ZipIndexError(f"local header of {entry.name} is not a zip local file header")
        name_length, extra_length = struct.unpack("<HH", header[26:30])
        return entry.local_header_offset + LOCAL_HEADER_SIZE + name_length + extra_length

    def read(self, entry: ZipEntry, *, max_bytes: int = MAX_INFLATE_BUFFER) -> bytes:
        """Read and (if needed) inflate an entry fully into memory."""
        if entry.uncompressed_size > max_bytes:
            raise ZipIndexError(
                f"{entry.name} is too large to read into memory "
                f"({transport.human_size(entry.uncompressed_size)})"
            )
        start = self.data_offset(entry)
        raw = self._read(start, start + entry.compressed_size - 1)
        if entry.is_deflated:
            return zlib.decompressobj(-15).decompress(raw, entry.uncompressed_size)
        if not entry.is_stored:
            raise ZipIndexError(f"unsupported compression method {entry.method} for {entry.name}")
        return raw

    def extract(
        self,
        entry: ZipEntry,
        dest: os.PathLike,
        *,
        resume: bool = False,
        verify_crc: bool = True,
        progress: Optional[Progress] = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
        log: Optional[Callable[[str], None]] = None,
    ) -> DownloadResult:
        """Write one entry to ``dest``, pulling only that entry's byte range.

        Returns the same :class:`~apkpure.downloader.DownloadResult` a plain
        download produces, so callers get sizes, hashes and resume information
        regardless of how the file was obtained.
        """
        destination = Path(dest)
        start = self.data_offset(entry)
        end = start + entry.compressed_size - 1

        if entry.is_stored:
            result = download(
                self.url,
                destination,
                headers=self.headers,
                byte_range=(start, end),
                expected_size=entry.uncompressed_size,
                resume=resume,
                timeout=timeout or self.timeout,
                retries=retries if retries is not None else self.retries,
                progress=progress,
                log=log,
            )
        elif entry.is_deflated:
            started = time.monotonic()
            if progress is not None:
                progress.total = entry.uncompressed_size
                progress.done = 0
            payload = self.read(entry)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with open(destination, "wb") as handle:
                handle.write(payload)
            if progress is not None:
                progress.done = len(payload)
                progress.finish(f"{transport.human_size(len(payload))} inflated")
            result = DownloadResult(
                path=destination,
                hashes=hash_bytes(payload),
                url=self.url,
                elapsed=max(time.monotonic() - started, 1e-6),
            )
        else:
            raise ZipIndexError(f"unsupported compression method {entry.method} for {entry.name}")

        if verify_crc and int(result.hashes.crc32, 16) != entry.crc32:
            raise VerificationError(
                f"crc32 mismatch for {entry.name}: got {result.hashes.crc32}, "
                f"expected {entry.crc32:08x}"
            )
        return result

    # -- transport ---------------------------------------------------------
    def _read(self, start: int, end: int) -> bytes:
        if end < start:
            return b""
        if self._reader is not None:
            return self._reader(start, end)

        last: Optional[BaseException] = None
        for attempt in range(1, max(self.retries, 1) + 1):
            try:
                return transport.read_range(self.url, start, end, headers=self.headers, timeout=self.timeout)
            except Exception as exc:  # noqa: BLE001 - retried below
                last = exc
                if attempt >= max(self.retries, 1):
                    break
                self.log(f"range read {start}-{end} failed ({describe_exception(exc)}), retrying")
        assert last is not None
        raise ZipIndexError(f"cannot read bytes {start}-{end} of {self.url}: {describe_exception(last)}")


def local_file_reader(path: os.PathLike) -> Tuple[Reader, int]:
    """Build a :class:`RemoteZip` reader over a local file (used by tests)."""

    def reader(start: int, end: int) -> bytes:
        with open(path, "rb") as handle:
            handle.seek(start)
            return handle.read(end - start + 1)

    size = os.path.getsize(path)
    return reader, size
