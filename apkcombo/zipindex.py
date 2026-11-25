"""Random-access reading of a zip archive that lives behind an HTTP URL.

An ``.apk`` and an ``.xapk`` are both ordinary zips: the central directory sits
at the end of the file and every member is addressed by absolute offset. Local
headers plus the tail index are a few KiB in total, so a tool can enumerate what
is inside a 700 MB archive — and then pull exactly one member — with a handful of
ranged requests instead of the whole file.

That is how :mod:`apkcombo.abis` answers "which CPU architectures does this build
contain?" in a second or two.
"""

from __future__ import annotations

import hashlib
import os
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import http
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
EXTRACT_CHUNK = 1 << 20

#: ``reader(start, end)`` returns the inclusive byte range; injectable for tests.
Reader = Callable[[int, int], bytes]


@dataclass(frozen=True)
class ZipEntry:
    """One member of the archive."""

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
    def compression(self) -> str:
        return {0: "store", 8: "deflate"}.get(self.method, f"method {self.method}")

    def describe(self) -> str:
        return (
            f"{self.name} ({self.compression}, {http.human_size(self.uncompressed_size)}, "
            f"offset {self.local_header_offset})"
        )


def local_file_reader(path: os.PathLike) -> Reader:
    """A reader over a local file, so the same code paths can run offline."""
    handle = open(path, "rb")

    def read(start: int, end: int) -> bytes:
        handle.seek(start)
        return handle.read(end - start + 1)

    read.close = handle.close  # type: ignore[attr-defined]
    return read


class RemoteZip:
    """Zip archive reader backed by ranged reads."""

    def __init__(
        self,
        url: str,
        *,
        size: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = http.DEFAULT_TIMEOUT,
        retries: int = http.DEFAULT_RETRIES,
        reader: Optional[Reader] = None,
        log: Optional[http.Log] = None,
    ) -> None:
        self.url = url
        self.headers = headers
        self.timeout = timeout
        self.retries = retries
        self.log = log or (lambda _message: None)
        self._reader = reader
        self._size = size
        self._entries: Optional[List[ZipEntry]] = None

    # -- basics ------------------------------------------------------------
    @property
    def size(self) -> int:
        if self._size is None:
            info, _head = http.probe(
                self.url, sample=1, headers=self.headers, timeout=self.timeout, log=self.log
            )
            if info.size is None:
                raise ZipIndexError(f"cannot determine the size of {self.url}")
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
            raise ZipIndexError("the remote file is too small to be a zip archive")
        window_start = max(0, total - EOCD_SEARCH_SIZE)
        tail = self._read(window_start, total - 1)
        offset = tail.rfind(EOCD_SIGNATURE)
        if offset < 0:
            raise ZipIndexError(
                "no zip end-of-central-directory record: the file is not a zip archive"
            )
        if len(tail) - offset < EOCD_MIN_SIZE:
            raise ZipIndexError("the zip end-of-central-directory record is truncated")

        (
            _signature,
            _disk_number,
            _cd_disk,
            _entries_here,
            entry_count,
            cd_size,
            cd_offset,
            _comment_length,
        ) = struct.unpack("<4sHHHHIIH", tail[offset:offset + EOCD_MIN_SIZE])

        if cd_offset == ZIP64_MARKER or cd_size == ZIP64_MARKER:
            raise ZipIndexError("zip64 archives are not supported")
        if cd_size > MAX_CENTRAL_DIRECTORY:
            raise ZipIndexError(f"central directory is implausibly large ({cd_size} bytes)")
        if cd_offset + cd_size > total:
            raise ZipIndexError("the central directory lies outside the remote file")

        self.log(
            f"index: {entry_count} entries, {http.human_size(cd_size)} at offset {cd_offset} "
            f"of a {http.human_size(total)} archive"
        )
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
            name_end = position + 46 + name_length
            if name_end > len(blob):
                raise ZipIndexError("a central directory entry runs past the end of the index")
            name = blob[position + 46:name_end].decode("utf-8", "replace")
            if compressed_size == ZIP64_MARKER or uncompressed_size == ZIP64_MARKER:
                raise ZipIndexError(f"zip64 entries are not supported ({name})")
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
            raise ZipIndexError("the central directory contains no entries")
        return entries

    # -- payload -----------------------------------------------------------
    def data_offset(self, entry: ZipEntry) -> int:
        header = self._read(
            entry.local_header_offset, entry.local_header_offset + LOCAL_HEADER_SIZE - 1
        )
        if header[:4] != LOCAL_SIGNATURE:
            raise ZipIndexError(f"the local header of {entry.name} is not a zip local file header")
        name_length, extra_length = struct.unpack("<HH", header[26:30])
        return entry.local_header_offset + LOCAL_HEADER_SIZE + name_length + extra_length

    def read(self, entry: ZipEntry, *, max_bytes: int = MAX_INFLATE_BUFFER) -> bytes:
        """Read one member fully (bounded, so a mistake cannot eat all memory)."""
        if entry.uncompressed_size > max_bytes:
            raise ZipIndexError(
                f"{entry.name} is too large to read into memory "
                f"({http.human_size(entry.uncompressed_size)})"
            )
        start = self.data_offset(entry)
        raw = self._read(start, start + entry.compressed_size - 1)
        if entry.is_stored:
            return raw
        if entry.is_deflated:
            return zlib.decompressobj(-15).decompress(raw, entry.uncompressed_size)
        raise ZipIndexError(f"unsupported compression method {entry.method} for {entry.name}")

    def extract(
        self,
        entry: ZipEntry,
        dest: os.PathLike,
        *,
        verify_crc: bool = True,
        log: Optional[http.Log] = None,
    ) -> Tuple[Path, int, str]:
        """Write one member to ``dest``, downloading only that member's bytes.

        Returns ``(path, size, sha256)``. Also validates the CRC32 stored in the
        index, so a truncated ranged read cannot pass silently.
        """
        logger = log or (lambda _message: None)
        destination = Path(dest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        start = self.data_offset(entry)
        digest = hashlib.sha256()
        crc = 0
        written = 0

        if entry.is_stored:
            with open(destination, "wb") as handle:
                position = start
                end = start + entry.compressed_size - 1
                while position <= end:
                    stop = min(position + EXTRACT_CHUNK - 1, end)
                    chunk = self._read(position, stop)
                    handle.write(chunk)
                    digest.update(chunk)
                    crc = zlib.crc32(chunk, crc)
                    written += len(chunk)
                    position = stop + 1
        elif entry.is_deflated:
            raw = self.read(entry)
            payload = raw
            logger(f"inflating {entry.name} ({http.human_size(len(raw))} compressed)")
            with open(destination, "wb") as handle:
                handle.write(payload)
            digest.update(payload)
            crc = zlib.crc32(payload, crc)
            written = len(payload)
        else:
            raise ZipIndexError(f"unsupported compression method {entry.method} for {entry.name}")

        if verify_crc and (crc & 0xFFFFFFFF) != entry.crc32:
            try:
                destination.unlink()
            except OSError:
                pass
            raise VerificationError(
                f"crc32 mismatch for {entry.name}: got {crc & 0xFFFFFFFF:08x}, "
                f"expected {entry.crc32:08x}"
            )
        return destination, written, digest.hexdigest()

    # -- transport ---------------------------------------------------------
    def _read(self, start: int, end: int) -> bytes:
        if end < start:
            return b""
        if self._reader is not None:
            return self._reader(start, end)
        try:
            return http.read_range(
                self.url,
                start,
                end,
                headers=self.headers,
                timeout=self.timeout,
                retries=self.retries,
                log=self.log,
            )
        except Exception as exc:  # noqa: BLE001 - normalised for the caller
            raise ZipIndexError(
                f"cannot read bytes {start}-{end} of {self.url}: {describe_exception(exc)}"
            ) from exc
