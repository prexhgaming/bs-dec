"""Dependency-free protobuf wire-format reader.

APKPure's v3 API answers in protobuf but publishes no ``.proto`` schema, so
instead of generated classes we decode the wire format generically and pick the
fields we need by number. That keeps the project at zero third-party
dependencies (important for a fast, cache-friendly GitHub Actions job).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Union

VARINT = 0
FIXED64 = 1
LEN = 2
FIXED32 = 5

# Guards against pathological input (e.g. an HTML error page or an image served
# where metadata was expected): the generic scan refuses to descend forever.
MAX_DEPTH = 8
MAX_MESSAGES = 200_000


class ProtobufError(ValueError):
    """Raised when a buffer cannot be decoded as protobuf wire data."""


@dataclass(frozen=True)
class Field:
    """One decoded protobuf field."""

    number: int
    wire_type: int
    value: Union[int, bytes]

    def text(self, encoding: str = "utf-8") -> Optional[str]:
        """Return the value as text, or ``None`` when it is not valid UTF-8."""
        if self.wire_type != LEN or not isinstance(self.value, bytes):
            return None
        try:
            return self.value.decode(encoding)
        except UnicodeDecodeError:
            return None

    def integer(self) -> Optional[int]:
        if self.wire_type != VARINT or not isinstance(self.value, int):
            return None
        return self.value

    def double(self) -> Optional[float]:
        if self.wire_type != FIXED64 or not isinstance(self.value, bytes):
            return None
        return struct.unpack("<d", self.value)[0]


def read_varint(buf: bytes, pos: int) -> "tuple[int, int]":
    """Read a base-128 varint, returning ``(value, next_pos)``."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ProtobufError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise ProtobufError("varint is too long")


def parse(buf: bytes) -> List[Field]:
    """Decode one protobuf message into a flat list of :class:`Field`."""
    fields: List[Field] = []
    pos = 0
    end = len(buf)
    while pos < end:
        key, pos = read_varint(buf, pos)
        number, wire = key >> 3, key & 0x7
        if number <= 0:
            raise ProtobufError("invalid field number 0")
        if wire == VARINT:
            value, pos = read_varint(buf, pos)
            fields.append(Field(number, wire, value))
        elif wire == LEN:
            length, pos = read_varint(buf, pos)
            if pos + length > end:
                raise ProtobufError("truncated length-delimited field")
            fields.append(Field(number, wire, buf[pos:pos + length]))
            pos += length
        elif wire == FIXED64:
            if pos + 8 > end:
                raise ProtobufError("truncated 64-bit field")
            fields.append(Field(number, wire, buf[pos:pos + 8]))
            pos += 8
        elif wire == FIXED32:
            if pos + 4 > end:
                raise ProtobufError("truncated 32-bit field")
            fields.append(Field(number, wire, buf[pos:pos + 4]))
            pos += 4
        else:
            raise ProtobufError(f"unsupported wire type {wire}")
    return fields


def first(buf: bytes, number: int) -> Optional[Field]:
    """Return the first field with ``number``, or ``None``."""
    for field in parse(buf):
        if field.number == number:
            return field
    return None


def all_with(buf: bytes, number: int) -> List[Field]:
    """Return every field with ``number``."""
    return [field for field in parse(buf) if field.number == number]


def get_text(buf: bytes, number: int, default: Optional[str] = None) -> Optional[str]:
    """Return field ``number`` as text (``default`` when absent/not text)."""
    field = first(buf, number)
    if field is None:
        return default
    text = field.text()
    return default if text is None else text


def get_int(buf: bytes, number: int, default: Optional[int] = None) -> Optional[int]:
    """Return field ``number`` as an integer (``default`` when absent)."""
    field = first(buf, number)
    if field is None:
        return default
    value = field.integer()
    return default if value is None else value


def messages(buf: bytes) -> Iterator[bytes]:
    """Yield every nested length-delimited sub-message, depth-first.

    Used as a schema-independent fallback: when the API grows a new wrapper
    level, a search over all nested messages still finds the payload.
    """
    produced = 0
    frontier: List[bytes] = [buf]
    for _depth in range(MAX_DEPTH):
        following: List[bytes] = []
        for chunk in frontier:
            try:
                fields = parse(chunk)
            except ProtobufError:
                continue
            for field in fields:
                if field.wire_type != LEN:
                    continue
                value = field.value
                if not isinstance(value, bytes) or not value:
                    continue
                produced += 1
                if produced > MAX_MESSAGES:
                    return
                yield value
                following.append(value)
        if not following:
            return
        frontier = following
