#!/usr/bin/env python3
"""Locate CPython's PyRun_StringFlags / _PyRun_String in a stripped, symbol-hidden
ELF shared object -- without using symbol names.

Why this rewrite exists
-----------------------
The previous version scored call sites by looking up PLT / relocation *symbol names*
("PyRun_StringFlags", "Py_CompileString", ...).  That is useless against a binary
whose symbol table is stripped and whose Python runtime is renamed: on libGame.so
every single one of the 1224 candidates came back with target_symbol == None, so the
name bonuses (70-120 points) never fired and the ranking degenerated into noise
(scores 12-18 from generic heuristics alone).

This version anchors on *behaviour and data*, which name obfuscation normally does
not touch:

  1. CPython emits the literal "invalid start argument" from exactly one place --
     check_start(), which is inlined into _PyRun_String() and _PyRun_File()
     (Python/pythonrun.c).  Nothing else in the process references that string.
  2. _PyRun_String() also materialises the anonymous filename "<string>" and looks
     up "__name__" in the globals dict.
  3. check_start() switches on Py_single_input(256) / Py_file_input(257) /
     Py_eval_input(258).
  4. PyRun_StringFlags() is the only caller of _PyRun_String() that passes
     name == NULL (i.e. r1 / x1 == 0 as the 2nd argument).

So: find the literal -> find the code that references it -> that code is
_PyRun_String -> walk its callers -> the one passing a null 2nd argument is
PyRun_StringFlags.

Memory
------
libGame.so is ~84 MB with a ~52 MB .text.  The old version handed capstone the whole
section in one disasm() call and retained every instruction object; that is what got
the process OOM-killed before its own instruction cap could trip.  This version:

  * mmaps the file instead of reading it,
  * never builds a global string table,
  * finds references with C-speed bytes.find() rather than Python loops,
  * only disassembles a few KB around confirmed candidates.

Usage
-----
    python pyrun_locator.py libGame.so --json report.json
    python pyrun_locator.py libGame.so --deep --entropy --json report.json

No third-party dependency is required.  capstone is used opportunistically for the
final verification disassembly when it happens to be installed.
"""
from __future__ import annotations

import argparse
import json
import math
import mmap
import os
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------- ELF
PT_LOAD = 1
PF_X = 0x1
SHF_EXECINSTR = 0x4
EM_ARM, EM_X86_64, EM_AARCH64, EM_386 = 40, 62, 183, 3

# CPython start tokens (Include/compile.h)
MODE_SINGLE, MODE_FILE, MODE_EVAL = 256, 257, 258
START_MODES = (MODE_SINGLE, MODE_FILE, MODE_EVAL)

# How far back to look for a function prologue when mapping an address to a function.
PROLOGUE_SCAN = 0x1200
# How far into a candidate function to look for the start-mode switch.
SWITCH_SCAN = 0x1000


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


@dataclass
class Segment:
    vaddr: int
    offset: int
    filesz: int
    memsz: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & PF_X)

    @property
    def end(self) -> int:
        return self.vaddr + self.filesz


@dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)


class ELF:
    """Minimal, mmap-backed ELF reader.  Deliberately stdlib-only: the previous
    version died because it materialised every segment, every string and every
    decoded instruction in RAM at once."""

    def __init__(self, path: str):
        self.path = path
        self.fp = open(path, "rb")
        self.filesize = os.fstat(self.fp.fileno()).st_size
        self.buf = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        if self.buf[:4] != b"\x7fELF":
            raise SystemExit(f"not an ELF file: {path}")
        self.bits = 64 if self.buf[4] == 2 else 32
        self.little = self.buf[5] == 1
        self.end = "<" if self.little else ">"
        self.machine = self.u16(18)
        self.e_flags = self.u32(36) if self.bits == 32 else self.u32(48)
        self.segments: List[Segment] = []
        self.sections: List[Section] = []
        self._parse_phdrs()
        self._parse_shdrs()
        self.image_base = min((s.vaddr for s in self.segments), default=0)

    # -- primitive reads ----------------------------------------------------
    def u16(self, off: int) -> int:
        return struct.unpack_from(self.end + "H", self.buf, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from(self.end + "I", self.buf, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from(self.end + "Q", self.buf, off)[0]

    def word(self, off: int) -> int:
        return self.u32(off) if self.bits == 32 else self.u64(off)

    def read(self, off: int, size: int) -> bytes:
        return bytes(self.buf[off:off + size])

    # -- headers ------------------------------------------------------------
    def _parse_phdrs(self) -> None:
        if self.bits == 32:
            phoff, phentsize, phnum = self.u32(28), self.u16(42), self.u16(44)
        else:
            phoff, phentsize, phnum = self.u64(32), self.u16(54), self.u16(56)
        for i in range(phnum):
            base = phoff + i * phentsize
            if base + phentsize > self.filesize:
                break
            p_type = self.u32(base)
            if p_type != PT_LOAD:
                continue
            if self.bits == 32:
                offset, vaddr = self.u32(base + 4), self.u32(base + 8)
                filesz, memsz = self.u32(base + 16), self.u32(base + 20)
                flags = self.u32(base + 24)
            else:
                flags, offset = self.u32(base + 4), self.u64(base + 8)
                vaddr, filesz = self.u64(base + 16), self.u64(base + 32)
                memsz = self.u64(base + 40)
            self.segments.append(Segment(vaddr, offset, filesz, memsz, flags))

    def _parse_shdrs(self) -> None:
        if self.bits == 32:
            shoff, shentsize, shnum, shstrndx = (
                self.u32(32), self.u16(46), self.u16(48), self.u16(50))
        else:
            shoff, shentsize, shnum, shstrndx = (
                self.u64(40), self.u16(58), self.u16(60), self.u16(62))
        if not shoff or not shnum:
            return
        raw = []
        for i in range(shnum):
            base = shoff + i * shentsize
            if base + shentsize > self.filesize:
                break
            if self.bits == 32:
                raw.append((self.u32(base), self.u32(base + 8), self.u32(base + 12),
                            self.u32(base + 16), self.u32(base + 20)))
            else:
                raw.append((self.u32(base), self.u64(base + 8), self.u64(base + 16),
                            self.u64(base + 24), self.u64(base + 32)))
        if shstrndx >= len(raw):
            return
        _, _, _, stroff, strsize = raw[shstrndx]
        strtab = bytes(self.buf[stroff:stroff + strsize])
        for sh_name, sh_flags, sh_addr, sh_offset, sh_size in raw:
            end = strtab.find(b"\x00", sh_name)
            name = strtab[sh_name:end].decode("utf-8", "replace") if end >= 0 else ""
            self.sections.append(Section(name, sh_addr, sh_offset, sh_size, sh_flags))

    # -- address translation ------------------------------------------------
    def va_to_off(self, va: int) -> Optional[int]:
        for seg in self.segments:
            if seg.vaddr <= va < seg.end:
                return seg.offset + (va - seg.vaddr)
        return None

    def off_to_va(self, off: int) -> Optional[int]:
        for seg in self.segments:
            if seg.offset <= off < seg.offset + seg.filesz:
                return seg.vaddr + (off - seg.offset)
        return None

    def rva(self, va: Optional[int]) -> Optional[int]:
        return None if va is None else int(va - self.image_base)

    def executable_ranges(self) -> List[Tuple[int, int, str]]:
        """(vaddr, file_offset, size, name) for every executable byte range."""
        out = []
        for sec in self.sections:
            if sec.executable and sec.size:
                out.append((sec.addr, sec.offset, sec.size, sec.name))
        if not out:
            for seg in self.segments:
                if seg.executable and seg.filesz:
                    out.append((seg.vaddr, seg.offset, seg.filesz, "PT_LOAD"))
        out.sort()
        return out

    def data_ranges(self) -> List[Tuple[int, int, int, str]]:
        """Non-executable PT_LOAD ranges: literal pools, GOT, .data.rel.ro, ..."""
        out = []
        for seg in self.segments:
            if seg.executable or not seg.filesz:
                continue
            out.append((seg.vaddr, seg.offset, seg.filesz, "PT_LOAD"))
        return out

    # -- byte search --------------------------------------------------------
    def find_all(self, needle: bytes, limit: int = 64) -> List[int]:
        """C-speed substring search over the whole mapped file."""
        hits: List[int] = []
        start = 0
        while len(hits) < limit:
            pos = self.buf.find(needle, start)
            if pos < 0:
                break
            hits.append(pos)
            start = pos + 1
        return hits

    def close(self) -> None:
        try:
            self.buf.close()
        finally:
            self.fp.close()


# ------------------------------------------------------------------------ anchors
@dataclass
class Anchor:
    needle: bytes
    weight: int
    note: str
    vas: List[int] = field(default_factory=list)


# Ordered by how uniquely they identify CPython's PyRun_StringFlags path.
ANCHOR_SPECS: Tuple[Tuple[bytes, int, str], ...] = (
    (b"invalid start argument", 120,
     "check_start() ValueError literal - only reachable from _PyRun_String/_PyRun_File"),
    (b"<string>", 45,
     "anonymous filename _PyRun_String substitutes when name == NULL"),
    (b"__name__", 18, "globals lookup performed by _PyRun_String"),
    (b"<stdin>", 12, "PyRun_AnyFile default filename (same translation unit)"),
    (b"<module>", 10, "code object name used by the compiler"),
    (b"Traceback (most recent call last):", 25, "CPython traceback printer"),
    (b"co_consts", 12, "code object attribute"),
    (b"co_code", 12, "code object attribute"),
    (b"__builtins__", 14, "exec/eval globals setup"),
    (b"importlib._bootstrap", 18, "frozen importlib bootstrap"),
    (b"sys.modules", 10, "import machinery"),
)

# Weaker markers: presence proves "a CPython runtime is in here" but not where.
MARKER_SPECS: Tuple[bytes, ...] = (
    b"SyntaxError: ", b"IndentationError", b"ZeroDivisionError",
    b"Py_Initialize", b"_PyRuntime", b"PyEval_EvalCode", b"frame object",
    b"__qualname__", b"__annotations__", b"__loader__", b"__spec__",
    b"unittest.mock", b"collections.abc",
)


def find_anchors(elf: ELF) -> List[Anchor]:
    """Resolve every anchor literal to its virtual address(es)."""
    anchors: List[Anchor] = []
    for needle, weight, note in ANCHOR_SPECS:
        anchor = Anchor(needle, weight, note)
        for off in elf.find_all(needle, limit=16):
            va = elf.off_to_va(off)
            if va is not None and va not in anchor.vas:
                anchor.vas.append(va)
        anchors.append(anchor)
    return anchors


def runtime_markers(elf: ELF) -> List[str]:
    """Which CPython marker strings are present at all (sanity check on the runtime)."""
    found = []
    for needle in MARKER_SPECS:
        if elf.find_all(needle, limit=1):
            found.append(needle.decode("utf-8", "replace"))
    return found


# -------------------------------------------------------------------------- xrefs
@dataclass
class Xref:
    va: int                 # address of the referencing code/data slot
    target: int             # anchor VA being referenced
    kind: str               # literal-pool | movw/movt | adrp/add | pc-relative | got
    note: str = ""


@dataclass
class CodeScan:
    """Results of the single linear pass over executable bytes."""
    calls: List[Tuple[int, int]] = field(default_factory=list)        # (site, target)
    movw: List[Tuple[int, int, int]] = field(default_factory=list)   # (site, rd, imm16)
    movt: List[Tuple[int, int, int]] = field(default_factory=list)
    mode_cmps: List[Tuple[int, int, int]] = field(default_factory=list)  # (site, reg, mode)
    pc_refs: List[Tuple[int, int]] = field(default_factory=list)     # (site, target)
    zeros: List[Tuple[int, int]] = field(default_factory=list)       # (site, reg)
    adrp: List[Tuple[int, int, int]] = field(default_factory=list)   # (site, rd, page)


def _words_of(elf: ELF, data: bytes) -> "array.array":
    import array
    usable = len(data) - (len(data) % 4)
    words = array.array("I")
    words.frombytes(data[:usable])
    if elf.little != (sys.byteorder == "little"):
        words.byteswap()
    return words


def _sign(value: int, bits: int) -> int:
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def scan_code(elf: ELF, deep: bool = False) -> CodeScan:
    """One linear pass over executable ranges collecting everything the later
    stages need (call sites, address materialisations, start-mode comparisons,
    register zeroing).  Kept in a single pass so we never revisit 52 MB of .text."""
    scan = CodeScan()
    for vaddr, off, size, _name in elf.executable_ranges():
        data = bytes(elf.buf[off:off + size])
        words = _words_of(elf, data)
        base = vaddr
        if elf.machine == EM_ARM:
            for idx, w in enumerate(words):
                site = base + idx * 4
                if (w & 0x0E000000) == 0x0A000000:                 # B / BL
                    imm = _sign(w & 0xFFFFFF, 24)
                    scan.calls.append((site, site + 8 + (imm << 2)))
                elif (w & 0x0FF00000) == 0x03000000:               # MOVW
                    rd = (w >> 12) & 0xF
                    imm16 = (((w >> 16) & 0xF) << 12) | (w & 0xFFF)
                    scan.movw.append((site, rd, imm16))
                elif (w & 0x0FF00000) == 0x03400000:               # MOVT
                    rd = (w >> 12) & 0xF
                    imm16 = (((w >> 16) & 0xF) << 12) | (w & 0xFFF)
                    scan.movt.append((site, rd, imm16))
                elif (w & 0xFFFF0000) == 0xE28F0000:               # ADD Rd, pc, #imm
                    scan.pc_refs.append((site, site + 8 + (w & 0xFFF)))
                elif (w & 0xFFF00000) == 0xE3500000:               # CMP Rd, #imm
                    imm = w & 0xFFF
                    if imm in START_MODES:
                        scan.mode_cmps.append((site, (w >> 16) & 0xF, imm))
                elif (w & 0xFFFF0000) in (0xE3A00000, 0xE3B00000):  # MOV/MOVS Rd, #0
                    if (w & 0xFFF) == 0:
                        scan.zeros.append((site, (w >> 12) & 0xF))
        elif elf.machine == EM_AARCH64:
            for idx, w in enumerate(words):
                site = base + idx * 4
                if (w & 0xFC000000) == 0x94000000:                 # BL
                    scan.calls.append((site, site + (_sign(w & 0x3FFFFFF, 26) << 2)))
                elif (w & 0x9F000000) == 0x90000000:               # ADRP
                    rd = w & 0x1F
                    immlo = (w >> 29) & 3
                    immhi = (w >> 5) & 0x7FFFF
                    imm = _sign((immhi << 2) | immlo, 21)
                    scan.adrp.append((site, rd, (site & ~0xFFF) + (imm << 12)))
                elif (w & 0x7F000000) == 0x11000000:               # ADD (imm)
                    scan.pc_refs.append((site, (w & 0x1F, (w >> 5) & 0x1F, (w >> 10) & 0xFFF)))
                elif (w & 0xFFC0001F) == 0xF100001F:               # CMP/SUBS xzr, xN, #imm
                    imm = (w >> 10) & 0xFFF
                    if imm in START_MODES:
                        scan.mode_cmps.append((site, (w >> 5) & 0x1F, imm))
                elif (w & 0x7F800000) == 0x52800000:               # MOVZ Wd, #0
                    if ((w >> 5) & 0xFFFF) == 0 and ((w >> 21) & 3) == 0:
                        scan.zeros.append((site, w & 0x1F))
        elif elf.machine in (EM_X86_64, EM_386):
            # x86 is best-effort here; capstone (when present) does the real work.
            pos = data.find(b"\xe8")
            while pos >= 0:
                if pos + 5 <= len(data):
                    rel = struct.unpack_from("<i", data, pos + 1)[0]
                    scan.calls.append((base + pos, base + pos + 5 + rel))
                pos = data.find(b"\xe8", pos + 1)
        if deep and elf.machine == EM_ARM:
            _scan_thumb16(elf, data, base, scan)
    return scan


def _scan_thumb16(elf: ELF, data: bytes, base: int, scan: CodeScan) -> None:
    """Thumb-16 ADR / MOVS-zero pass (2-byte aligned).  Thumb-2 32-bit forms are
    covered by the 4-byte pass above when they happen to be 4-aligned."""
    for pos in range(0, len(data) - 1, 2):
        hw = data[pos] | (data[pos + 1] << 8)
        site = base + pos
        if (hw & 0xF800) == 0xA000:                                # ADR Rd, #imm8
            scan.pc_refs.append((site, ((site + 4) & ~3) + ((hw & 0xFF) << 2)))
        elif (hw & 0xFF00) == 0x2000 and (hw & 0xFF) == 0:         # MOVS Rd, #0
            scan.zeros.append((site, (hw >> 8) & 7))


def collect_xrefs(elf: ELF, targets: Set[int], scan: CodeScan) -> List[Xref]:
    """All references to any anchor VA, from code or from data."""
    xrefs: List[Xref] = []
    seen: Set[Tuple[int, int]] = set()

    def add(va: int, target: int, kind: str, note: str = "") -> None:
        key = (va, target)
        if key in seen:
            return
        seen.add(key)
        xrefs.append(Xref(va, target, kind, note))

    # 1. Absolute pointer stored anywhere (literal pool, GOT, .data.rel.ro, vtable).
    #    C-speed: one bytes.find per (target, word-size) instead of a Python loop.
    for target in targets:
        if elf.bits == 32:
            packers = ((struct.pack("<I", target & 0xFFFFFFFF), 4),)
        else:
            packers = ((struct.pack("<Q", target & 0xFFFFFFFFFFFFFFFF), 8),)
        for needle, size in packers:
            for off in elf.find_all(needle, limit=64):
                va = elf.off_to_va(off)
                if va is None:
                    continue
                kind = "literal-pool" if _is_exec(elf, va) else "data-pointer"
                add(va, target, kind, f"{size}-byte pointer")

    # 2. ARM movw/movt pairs (how PIC code materialises a local address).
    pending: Dict[int, Tuple[int, int]] = {}
    for site, rd, imm16 in scan.movw:
        pending[rd] = (site, imm16)
    for site, rd, imm16 in scan.movt:
        prev = pending.get(rd)
        if not prev:
            continue
        movw_site, low = prev
        if site - movw_site > 64:
            continue
        value = (imm16 << 16) | low
        if value in targets:
            add(movw_site, value, "movw/movt", f"built in r{rd}")

    # 3. ARM64 ADRP + ADD pairs.
    adrp_state: Dict[int, int] = {}
    for site, rd, page in scan.adrp:
        adrp_state[rd] = page
    for entry in scan.pc_refs:
        if not isinstance(entry[1], tuple):
            continue
        site, (rd, rn, imm12) = entry
        page = adrp_state.get(rn)
        if page is None:
            continue
        value = page + imm12
        if value in targets:
            add(site, value, "adrp/add", f"x{rd} <- page(x{rn}) + {imm12}")

    # 4. ARM32 PC-relative ADD (no relocation needed, very common in PIC).
    for site, value in scan.pc_refs:
        if isinstance(value, int) and value in targets:
            add(site, value, "pc-relative", "add Rd, pc, #imm")

    return xrefs


def _is_exec(elf: ELF, va: int) -> bool:
    for vaddr, _off, size, _n in elf.executable_ranges():
        if vaddr <= va < vaddr + size:
            return True
    return False


# ------------------------------------------------------------------ function start
def prologue_before(elf: ELF, addr: int, max_back: int = PROLOGUE_SCAN) -> Optional[int]:
    """Best-effort enclosing-function start for `addr`, by scanning backwards for a
    recognised prologue.  Good enough to report an RVA; the capstone verification
    step afterwards confirms the hit."""
    rng = None
    for vaddr, off, size, _name in elf.executable_ranges():
        if vaddr <= addr < vaddr + size:
            rng = (vaddr, off, size)
            break
    if rng is None:
        return None
    vaddr, off, size = rng
    start_va = max(vaddr, addr - max_back)
    lo = off + (start_va - vaddr)
    hi = off + (addr - vaddr)
    data = bytes(elf.buf[lo:hi])
    if not data:
        return None

    if elf.machine == EM_ARM:
        for pos in range(len(data) - 4, -1, -2):
            w = struct.unpack_from("<I", data, pos)[0]
            if (w & 0xFFFF4000) == 0xE92D4000:        # stmdb sp!, {..., lr}
                return start_va + pos
        for pos in range(len(data) - 2, -1, -2):
            hw = data[pos] | (data[pos + 1] << 8)
            if (hw & 0xFF00) == 0xB500:               # thumb push {..., lr}
                return start_va + pos
    elif elf.machine == EM_AARCH64:
        for pos in range(len(data) - 4, -1, -4):
            w = struct.unpack_from("<I", data, pos)[0]
            if (w & 0xFFC07FFF) == 0xA9807BFD:        # stp x29, x30, [sp, #-N]!
                return start_va + pos
    elif elf.machine in (EM_X86_64, EM_386):
        for pos in range(len(data) - 1, -1, -1):
            if data[pos:pos + 4] == b"\xf3\x0f\x1e\xfa":   # endbr64
                return start_va + pos
            if data[pos] == 0x55:                          # push rbp
                return start_va + pos
    return None


# ------------------------------------------------------------------ identification
FUNCTION_SPAN = 0x2000      # how far past a function start we attribute evidence
NAME_ARG_REG = {EM_ARM: 1, EM_AARCH64: 1, EM_X86_64: 1, EM_386: 1}


@dataclass
class FunctionHit:
    va: int
    role: str
    score: int
    evidence: List[str] = field(default_factory=list)
    anchors: List[str] = field(default_factory=list)
    mode_cmps: List[int] = field(default_factory=list)
    call_sites: List[int] = field(default_factory=list)

    @property
    def rva(self) -> int:
        return self.va

    def as_dict(self, elf: ELF) -> dict:
        return {
            "role": self.role,
            "score": self.score,
            "va": hex(self.va),
            "rva": hex(elf.rva(self.va) or 0),
            "file_offset": _hex(elf.va_to_off(self.va)),
            "anchors": self.anchors,
            "start_mode_constants": [hex(m) for m in self.mode_cmps],
            "call_sites": [hex(c) for c in self.call_sites],
            "evidence": self.evidence,
        }


def _hex(value: Optional[int]) -> Optional[str]:
    return None if value is None else hex(value)


def group_by_function(elf: ELF, xrefs: Sequence[Xref]) -> Dict[int, List[Xref]]:
    grouped: Dict[int, List[Xref]] = {}
    for xref in xrefs:
        fn = prologue_before(elf, xref.va)
        if fn is None:
            continue
        grouped.setdefault(fn, []).append(xref)
    return grouped


def identify(elf: ELF, anchors: Sequence[Anchor], xrefs: Sequence[Xref],
             scan: CodeScan, deep: bool = False) -> Tuple[List[FunctionHit], List[FunctionHit]]:
    """Return (runtime_functions, flag_entrypoints).

    runtime_functions are the recovered _PyRun_String / _PyRun_File bodies;
    flag_entrypoints are the callers that pass name == NULL, i.e. the function the
    game actually calls -- PyRun_StringFlags under whatever name it now has."""
    anchor_by_va: Dict[int, Anchor] = {}
    for anchor in anchors:
        for va in anchor.vas:
            anchor_by_va[va] = anchor

    grouped = group_by_function(elf, xrefs)
    runtime: List[FunctionHit] = []

    for fn, hits in grouped.items():
        hit = FunctionHit(fn, "_PyRun_String / _PyRun_File", 0)
        for xref in hits:
            anchor = anchor_by_va.get(xref.target)
            if anchor is None:
                continue
            label = anchor.needle.decode("utf-8", "replace")
            if label in hit.anchors:
                continue                      # count each anchor once, not per xref
            hit.score += anchor.weight
            hit.anchors.append(label)
            hit.evidence.append(
                f"references \"{label}\" @ {hex(xref.target)} via {xref.kind} at {hex(xref.va)}")
        if hit.score:
            runtime.append(hit)

    # check_start()'s switch is inlined into both _PyRun_String and _PyRun_File,
    # so a function containing all three start tokens is a runtime candidate even
    # if every string literal was obfuscated away.
    cmps_by_fn: Dict[int, List[int]] = {}
    for site, _reg, mode in scan.mode_cmps:
        fn = prologue_before(elf, site)
        if fn is not None:
            cmps_by_fn.setdefault(fn, []).append(mode)
    for fn, modes in cmps_by_fn.items():
        if len(set(modes)) < 3:
            continue
        existing = next((h for h in runtime if h.va == fn), None)
        if existing is None:
            existing = FunctionHit(fn, "_PyRun_String / _PyRun_File", 0)
            runtime.append(existing)
        existing.mode_cmps = sorted(set(modes))
        existing.score += 25
        existing.evidence.append(
            "compares against all start tokens " + ", ".join(str(m) for m in sorted(set(modes))))

    runtime.sort(key=lambda h: -h.score)

    # PyRun_StringFlags is the unique caller of _PyRun_String that passes name=NULL.
    runtime_vas = {h.va for h in runtime}
    callers: Dict[int, List[int]] = {}
    for site, target in scan.calls:
        if target in runtime_vas:
            fn = prologue_before(elf, site)
            if fn is not None:
                callers.setdefault(fn, []).append(site)

    zero_by_reg: Dict[int, List[int]] = {}
    for site, reg in scan.zeros:
        zero_by_reg.setdefault(reg, []).append(site)
    name_reg = NAME_ARG_REG.get(elf.machine, 1)

    entrypoints: List[FunctionHit] = []
    for fn, sites in callers.items():
        if fn in runtime_vas:
            continue
        hit = FunctionHit(fn, "PyRun_StringFlags candidate", 40)
        hit.call_sites = sorted(sites)
        hit.evidence.append(
            f"calls the recovered runtime at {', '.join(hex(s) for s in hit.call_sites[:4])}")
        for site in sites:
            if any(0 <= site - z <= 64 for z in zero_by_reg.get(name_reg, ())):
                hit.score += 55
                hit.evidence.append(
                    f"zeroes argument register r{name_reg}/x{name_reg} before the call "
                    f"(name == NULL -> PyRun_StringFlags)")
                break
        entrypoints.append(hit)

    entrypoints.sort(key=lambda h: -h.score)
    return runtime, entrypoints


def capstone_verify(elf: ELF, va: int, anchor_vas: Dict[int, str],
                    span: int = 0x1000) -> Optional[List[str]]:
    """Opportunistic confirmation: disassemble the first `span` bytes of a function
    and report which anchors it actually loads.  Returns None when capstone is not
    installed, so the tool still works without it."""
    try:
        from capstone import (Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86,
                              CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
                              CS_MODE_LITTLE_ENDIAN)
    except ImportError:
        return None
    off = elf.va_to_off(va)
    if off is None:
        return None
    code = bytes(elf.buf[off:off + span])
    if not code:
        return None

    if elf.machine == EM_ARM:
        candidates = [(CS_ARCH_ARM, CS_MODE_ARM), (CS_ARCH_ARM, CS_MODE_THUMB)]
    elif elf.machine == EM_AARCH64:
        candidates = [(CS_ARCH_ARM64, CS_MODE_64)]
    elif elf.machine in (EM_X86_64, EM_386):
        candidates = [(CS_ARCH_X86, CS_MODE_64 if elf.bits == 64 else CS_MODE_32)]
    else:
        return None

    import re as _re
    best: Optional[List[str]] = None
    for arch, mode in candidates:
        md = Cs(arch, mode | CS_MODE_LITTLE_ENDIAN)
        md.detail = False
        notes: List[str] = []
        try:
            for insn in md.disasm(code, va):
                text = f"{insn.mnemonic} {insn.op_str}"
                for imm in _re.findall(r"#(0x[0-9a-f]+|\d+)", text):
                    value = int(imm, 0)
                    if value in anchor_vas:
                        notes.append(f"{hex(insn.address)}: {text}  ; \"{anchor_vas[value]}\"")
                if "pc" in insn.op_str or "rip" in insn.op_str:
                    m = _re.search(r"(?:pc|rip)[^#]*#(-?0x[0-9a-f]+|-?\d+)", insn.op_str)
                    if m:
                        disp = int(m.group(1), 0)
                        base = insn.address + insn.size + disp
                        if elf.machine == EM_ARM:
                            base = insn.address + 8 + disp
                        target = elf.off_to_va(base)
                        if target in anchor_vas:
                            notes.append(f"{hex(insn.address)}: {text}  ; \"{anchor_vas[target]}\"")
        except Exception:
            continue
        if notes and (best is None or len(notes) > len(best)):
            best = notes
    return best


# ------------------------------------------------------------------------ entropy
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    total = 0.0
    for c in counts:
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


def high_entropy_ranges(elf: ELF, budget: int = 16 * 1024 * 1024,
                        step: int = 4096, limit: int = 40) -> List[dict]:
    """Sampled scan -- never walks all 84 MB, never allocates per-window objects."""
    found: List[dict] = []
    remaining = budget
    for seg in elf.segments:
        if remaining <= 0:
            break
        end = min(seg.filesz, remaining)
        remaining -= end
        for rel in range(0, max(0, end - 256), step):
            chunk = bytes(elf.buf[seg.offset + rel: seg.offset + rel + 256])
            score = entropy(chunk)
            if score >= 7.2:
                found.append({
                    "va": hex(seg.vaddr + rel),
                    "file_offset": seg.offset + rel,
                    "size_scanned": len(chunk),
                    "entropy_bits_per_byte": round(score, 3),
                    "note": "high entropy; packed/compressed/ciphertext",
                })
    found.sort(key=lambda x: -x["entropy_bits_per_byte"])
    return found[:limit]


# ------------------------------------------------------------------------- report
def print_report(elf: ELF, anchors: Sequence[Anchor], markers: Sequence[str],
                 runtime: Sequence[FunctionHit], entrypoints: Sequence[FunctionHit],
                 verified: Dict[int, Optional[List[str]]], entropy_ranges: Sequence[dict],
                 limit: int) -> None:
    print(f"\n[+] File: {elf.path}")
    print(f"[+] ELF: {elf.bits}-bit {'little' if elf.little else 'big'}-endian, "
          f"machine={elf.machine}, base={hex(elf.image_base)}")
    print(f"[+] Executable ranges: {len(elf.executable_ranges())}")

    print("\n[+] Anchor literals:")
    for anchor in anchors:
        label = anchor.needle.decode("utf-8", "replace")
        if anchor.vas:
            print(f"    FOUND  {label!r} @ {', '.join(hex(v) for v in anchor.vas[:4])}")
        else:
            print(f"    absent {label!r}")

    print("\n[+] CPython runtime markers: " + (", ".join(markers) if markers else "none"))
    if not markers and not any(a.vas for a in anchors):
        print("    [!] No CPython markers at all -- the runtime may be packed, or the")
        print("        string table is obfuscated. Falling back to start-mode switches.")

    print("\n[+] Recovered runtime functions (_PyRun_String / _PyRun_File):")
    if not runtime:
        print("    (none)")
    for hit in runtime[:limit]:
        print(f"    {hit.role}  VA={hex(hit.va)} RVA={hex(elf.rva(hit.va) or 0)} "
              f"off={_hex(elf.va_to_off(hit.va))} score={hit.score}")
        for note in verified.get(hit.va) or []:
            print(f"      confirmed: {note}")
        for item in hit.evidence[:6]:
            print(f"      - {item}")

    print("\n[+] PyRun_StringFlags candidates (callers passing name == NULL):")
    if not entrypoints:
        print("    (none)")
    for hit in entrypoints[:limit]:
        print(f"    {hit.role}  VA={hex(hit.va)} RVA={hex(elf.rva(hit.va) or 0)} "
              f"off={_hex(elf.va_to_off(hit.va))} score={hit.score}")
        for item in hit.evidence[:6]:
            print(f"      - {item}")

    if entropy_ranges:
        print("\n[+] High-entropy ranges:")
        for item in entropy_ranges[:10]:
            print(f"    VA={item['va']} off={item['file_offset']} "
                  f"H={item['entropy_bits_per_byte']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Locate CPython PyRun_StringFlags without symbol names.")
    parser.add_argument("so", help="target ELF shared object")
    parser.add_argument("--window", type=int, default=28,
                        help="accepted for backward compatibility")
    parser.add_argument("--max-candidates", type=int, default=25)
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--entropy", action="store_true",
                        help="also report sampled high-entropy ranges")
    parser.add_argument("--deep", action="store_true",
                        help="adds the slower 2-byte Thumb pass and capstone checks")
    args = parser.parse_args()

    if not os.path.isfile(args.so):
        parser.error(f"file not found: {args.so}")

    started = time.time()
    elf = ELF(args.so)
    log(f"[*] mapped {elf.filesize / 1e6:.1f} MB in {time.time() - started:.1f}s "
        f"({elf.bits}-bit machine={elf.machine})")

    anchors = find_anchors(elf)
    log(f"[*] anchor literals resolved in {time.time() - started:.1f}s")
    markers = runtime_markers(elf)

    targets: Set[int] = {va for anchor in anchors for va in anchor.vas}
    scan = scan_code(elf, deep=args.deep)
    log(f"[*] decoded {len(scan.calls)} branches, {len(scan.movw)} movw, "
        f"{len(scan.movt)} movt in {time.time() - started:.1f}s")

    xrefs = collect_xrefs(elf, targets, scan)
    log(f"[*] {len(xrefs)} cross-references to anchor literals")

    runtime, entrypoints = identify(elf, anchors, xrefs, scan, deep=args.deep)

    verified: Dict[int, Optional[List[str]]] = {}
    if args.deep:
        anchor_vas = {va: a.needle.decode("utf-8", "replace")
                      for a in anchors for va in a.vas}
        for hit in list(runtime) + list(entrypoints):
            verified[hit.va] = capstone_verify(elf, hit.va, anchor_vas)

    entropy_ranges = high_entropy_ranges(elf) if args.entropy else []
    print_report(elf, anchors, markers, runtime, entrypoints, verified,
                 entropy_ranges, args.max_candidates)

    if args.json_path:
        report = {
            "file": os.path.abspath(args.so),
            "summary": {
                "bits": elf.bits,
                "endianness": "little" if elf.little else "big",
                "machine": elf.machine,
                "image_base": hex(elf.image_base),
                "executable_ranges": [
                    {"name": n, "va": hex(v), "size": s}
                    for v, _o, s, n in elf.executable_ranges()],
                "branch_count": len(scan.calls),
                "start_mode_comparisons": len(scan.mode_cmps),
                "anchor_count": sum(len(a.vas) for a in anchors),
                "xref_count": len(xrefs),
                "runtime_markers": markers,
            },
            "anchors": [
                {"text": a.needle.decode("utf-8", "replace"), "weight": a.weight,
                 "note": a.note, "vas": [hex(v) for v in a.vas]}
                for a in anchors],
            "py_functions": [hit.as_dict(elf) for hit in runtime],
            "candidates": [hit.as_dict(elf) for hit in entrypoints],
            "xrefs": [{"va": hex(x.va), "target": hex(x.target), "kind": x.kind,
                       "note": x.note} for x in xrefs[:500]],
            "high_entropy_ranges": list(entropy_ranges),
        }
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"\n[+] JSON report: {args.json_path}")

    elf.close()
    log(f"[*] done in {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


