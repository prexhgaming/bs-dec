#!/usr/bin/env python3
"""Locate ``pyrun_String*`` entry points inside a native Android library.

Three passes, cheapest first, so a stripped library still yields something:

1. **named symbols** — ``.symtab``/``.dynsym`` entries containing ``pyrun``
   (``PyRun_StringFlags``, ``pyrun_String``, ...), plus *undefined* imports that
   prove the module links against CPython's pythonrun.
2. **string literals** — every ``PyRun_``/``pyrun_`` byte sequence still present
   in the file, mapped to a virtual address.
3. **code references** (capstone) — disassemble executable sections in ARM,
   Thumb and AArch64, resolve ``movw``/``movt`` pairs, ``adr``/``adrp``+``add``
   and PC-relative literal loads, and report the instruction that points at a
   pass-2 string. The enclosing function is taken from the symbol table, or, when
   stripped, from the nearest prologue walked back from the hit — the closest
   surviving approximation of the original method boundary. A sha256 fingerprint
   of that region lets a 32-bit and a 64-bit build be compared.

Runs offline; the APK is read with :mod:`zipfile` (CRC-checked), never by ranged
pulls, so a corrupt transfer can never masquerade as a scan result.

    python3 analysis/scan_pyrun.py app.apk --abi arm64-v8a --json report.json
    python3 analysis/scan_pyrun.py libGame.so --json report.json

Exit codes: 0 scanned (hits or not), 2 the file/member could not be read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHT_NOBITS = 8
STT_FUNC = 2
SHF_EXECINSTR = 0x4

MACHINES = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
NEEDLES = (b"PyRun_", b"pyrun_", b"PyRun_String", b"pyrun_String")

# Broader evidence table. A build can embed CPython without ever keeping a
# ``PyRun_`` literal (the symbol is stripped and the string may be gone), so the
# report counts every marker family that would prove the interpreter is inside.
MARKERS: Tuple[Tuple[str, bytes], ...] = (
    ("PyRun_ (pythonrun)", b"PyRun_"),
    ("pyrun_", b"pyrun_"),
    ("PyRun_StringFlags", b"PyRun_StringFlags"),
    ("Py_Initialize", b"Py_Initialize"),
    ("PyEval_", b"PyEval_"),
    ("PyImport_", b"PyImport_"),
    ("PyObject_", b"PyObject_"),
    ("PyGILState_", b"PyGILState_"),
    ("Py_BuildValue", b"Py_BuildValue"),
    ("PyArg_Parse", b"PyArg_Parse"),
    ("PyModule_", b"PyModule_"),
    ("libpython", b"libpython"),
    ("python3.", b"python3."),
    ("JNI_OnLoad", b"JNI_OnLoad"),
    ("il2cpp", b"il2cpp"),
    ("UnityPlayer", b"UnityPlayer"),
    ("mono_", b"mono_"),
    ("lua_State", b"lua_State"),
    ("Lua 5", b"Lua 5"),
)

# Section names that betray a protector/packer: code is encrypted at rest, so a
# string or symbol search cannot see anything until it is unpacked at runtime.
PACKER_HINTS = (
    "upx",
    "execv3",
    "secneo",
    "libnesec",
    "bangcle",
    "ijiami",
    "jiagu",
    "360",
    "tencent",
    "stub",
    "packed",
    "encrypt",
)

try:  # optional dependency: pass 3 only
    import capstone  # type: ignore
except Exception:  # noqa: BLE001 - a missing capstone must not abort the scan
    capstone = None  # type: ignore


# --------------------------------------------------------------------- ELF model


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int

    def contains_offset(self, offset: int) -> bool:
        return self.offset <= offset < self.offset + self.size

    def contains_addr(self, addr: int) -> bool:
        return self.addr <= addr < self.addr + self.size


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    type: int
    bind: int
    shndx: int

    @property
    def is_function(self) -> bool:
        return self.type == STT_FUNC and self.value > 0

    @property
    def is_import(self) -> bool:
        return self.shndx == 0 and self.value == 0


@dataclass
class Elf:
    data: bytes
    bits: int = 32
    machine: int = 0
    sections: List[Section] = field(default_factory=list)
    symbols: List[Symbol] = field(default_factory=list)

    @property
    def machine_name(self) -> str:
        return MACHINES.get(self.machine, f"machine-{self.machine}")

    @property
    def has_symtab(self) -> bool:
        return any(section.type == SHT_SYMTAB for section in self.sections)

    def exec_sections(self) -> List[Section]:
        return [s for s in self.sections if s.flags & SHF_EXECINSTR and s.size]

    def functions(self) -> List[Symbol]:
        return sorted((s for s in self.symbols if s.is_function), key=lambda s: s.value)

    def read(self, offset: int, size: int) -> bytes:
        return self.data[offset : offset + size]

    def offset_to_vaddr(self, offset: int) -> Optional[int]:
        for section in self.sections:
            if section.type != SHT_NOBITS and section.contains_offset(offset):
                return section.addr + (offset - section.offset)
        return None

    def vaddr_to_offset(self, addr: int) -> Optional[int]:
        for section in self.sections:
            if section.type != SHT_NOBITS and section.contains_addr(addr):
                return section.offset + (addr - section.addr)
        return None


def parse_elf(data: bytes) -> Elf:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    bits = 64 if data[4] == 2 else 32
    endian = "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    elf = Elf(data=data, bits=bits, machine=machine)

    if bits == 32:
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
        sh_fmt = endian + "IIIIIIIIII"
    else:
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
        sh_fmt = endian + "IIQQQQIIQQ"

    raw_sections: List[Tuple[int, ...]] = []
    for index in range(shnum):
        start = shoff + index * shentsize
        if start + struct.calcsize(sh_fmt) > len(data):
            break
        raw_sections.append(struct.unpack_from(sh_fmt, data, start))

    names_blob = b""
    if shstrndx < len(raw_sections):
        names_offset = raw_sections[shstrndx][4]
        names_size = raw_sections[shstrndx][5]
        names_blob = data[names_offset : names_offset + names_size]

    for item in raw_sections:
        name_off, sh_type, flags, addr, offset, size, link = item[:7]
        entsize = item[9]
        name = _cstring(names_blob, name_off)
        elf.sections.append(Section(name, sh_type, flags, addr, offset, size, link, entsize))

    for section in elf.sections:
        if section.type not in (SHT_SYMTAB, SHT_DYNSYM) or not section.entsize:
            continue
        strtab = elf.sections[section.link] if section.link < len(elf.sections) else None
        strings = (
            data[strtab.offset : strtab.offset + strtab.size] if strtab is not None else b""
        )
        count = section.size // section.entsize
        for index in range(count):
            start = section.offset + index * section.entsize
            if start + section.entsize > len(data):
                break
            if bits == 32:
                st_name, value, size_, info, _other, shndx = struct.unpack_from(
                    endian + "IIIBBH", data, start
                )
            else:
                st_name, info, _other, shndx, value, size_ = struct.unpack_from(
                    endian + "IBBHQQ", data, start
                )
            symbol_name = _cstring(strings, st_name)
            if not symbol_name:
                continue
            elf.symbols.append(Symbol(symbol_name, value, size_, info & 0xF, info >> 4, shndx))

    return elf


def _cstring(blob: bytes, offset: int) -> str:
    if not blob or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


# ------------------------------------------------------------------ pass 1 and 2


def scan_symbols(elf: Elf) -> List[Dict[str, object]]:
    hits: List[Dict[str, object]] = []
    for symbol in elf.symbols:
        lowered = symbol.name.lower()
        if "pyrun" not in lowered and "pyrun_string" not in lowered:
            continue
        hits.append(
            {
                "name": symbol.name,
                "address": f"0x{symbol.value:x}" if symbol.value else None,
                "address_int": symbol.value,
                "size": symbol.size or None,
                "kind": "import" if symbol.is_import else ("function" if symbol.is_function else "data"),
            }
        )
    hits.sort(key=lambda item: (str(item["kind"]), str(item["name"])))
    return hits


@dataclass
class StringHit:
    needle: str
    text: str
    offset: int
    address: Optional[int]

    def as_dict(self) -> Dict[str, object]:
        return {
            "needle": self.needle,
            "text": self.text,
            "file_offset": self.offset,
            "address": f"0x{self.address:x}" if self.address is not None else None,
            "address_int": self.address,
        }


def scan_strings(elf: Elf, needles: Sequence[bytes] = NEEDLES) -> List[StringHit]:
    hits: List[StringHit] = []
    seen: set = set()
    for needle in needles:
        start = 0
        while True:
            index = elf.data.find(needle, start)
            if index < 0:
                break
            start = index + 1
            if index in seen:
                continue
            seen.add(index)
            hits.append(
                StringHit(
                    needle=needle.decode("ascii", "replace"),
                    text=_printable_at(elf.data, index),
                    offset=index,
                    address=elf.offset_to_vaddr(index),
                )
            )
    hits.sort(key=lambda hit: hit.offset)
    return hits


def _printable_at(data: bytes, index: int, limit: int = 96) -> str:
    start = index
    while start > 0 and 0x20 <= data[start - 1] < 0x7F:
        start -= 1
    end = index
    while end < len(data) and 0x20 <= data[end] < 0x7F and end - start < limit:
        end += 1
    return data[start:end].decode("ascii", "replace")


# ---------------------------------------------------------------------- pass 3


@dataclass
class Reference:
    instruction: str
    insn_address: int
    mode: str
    target: int
    string: Optional[str]
    function: Dict[str, object]

    def as_dict(self) -> Dict[str, object]:
        return {
            "instruction": self.instruction,
            "insn_address": f"0x{self.insn_address:x}",
            "mode": self.mode,
            "target": f"0x{self.target:x}",
            "string": self.string,
            "function": self.function,
        }


def _arm_modes(machine: int) -> List[Tuple[str, int]]:
    if capstone is None:
        return []
    if machine == 40:  # ARM
        return [
            ("arm", capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN),
            ("thumb", capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN),
        ]
    if machine == 183:  # AArch64
        return [("aarch64", capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)]
    return []


def scan_references(
    elf: Elf,
    strings: Sequence[StringHit],
    *,
    limit: int = 4000,
) -> List[Reference]:
    if capstone is None:
        return []
    targets: Dict[int, str] = {
        hit.address: hit.text for hit in strings if hit.address is not None
    }
    if not targets:
        return []

    arch = capstone.CS_ARCH_ARM if elf.machine == 40 else capstone.CS_ARCH_ARM64
    by_address = {hit.address: hit.text for hit in strings if hit.address is not None}
    references: List[Reference] = []

    for section in elf.exec_sections():
        code = elf.read(section.offset, section.size)
        for mode_name, mode in _arm_modes(elf.machine):
            references.extend(
                _disassemble(
                    elf,
                    code,
                    section.addr,
                    arch,
                    mode,
                    mode_name,
                    by_address,
                    limit=limit,
                )
            )
    # one hit per instruction address, preferring the ARM-mode (non-Thumb) decode
    best: Dict[int, Reference] = {}
    for reference in references:
        existing = best.get(reference.insn_address)
        if existing is None or (existing.mode == "thumb" and reference.mode != "thumb"):
            best[reference.insn_address] = reference
    return [best[address] for address in sorted(best)]


def _disassemble(
    elf: Elf,
    code: bytes,
    base: int,
    arch: int,
    mode: int,
    mode_name: str,
    targets: Dict[int, str],
    *,
    limit: int,
) -> List[Reference]:
    hits: List[Reference] = []
    try:
        engine = capstone.Cs(arch, mode)
        engine.detail = True
        engine.skipdata = True
    except Exception:  # noqa: BLE001 - unsupported mode on this capstone build
        return hits

    pending: Dict[str, int] = {}
    for insn in engine.disasm(code, base):
        mnemonic = insn.mnemonic
        operands = insn.operands
        value: Optional[int] = None

        if mnemonic in ("movw", "movw_u"):
            if len(operands) == 2 and operands[0].type == capstone.arm.ARM_OP_REG:
                pending[insn.reg_name(operands[0].reg)] = operands[1].imm & 0xFFFF
        elif mnemonic in ("movt",):
            if len(operands) == 2 and operands[0].type == capstone.arm.ARM_OP_REG:
                register = insn.reg_name(operands[0].reg)
                low = pending.get(register, 0) & 0xFFFF
                value = (operands[1].imm & 0xFFFF) << 16 | low
                pending[register] = value
        elif mnemonic in ("adr", "adrp"):
            if len(operands) == 2:
                register = insn.reg_name(operands[0].reg)
                value = operands[1].imm
                pending[register] = value
        elif mnemonic in ("add", "sub") and len(operands) == 3:
            base_reg = insn.reg_name(operands[1].reg) if operands[1].type == capstone.arm.ARM_OP_REG else None
            if base_reg in pending and operands[2].type == capstone.arm.ARM_OP_IMM:
                delta = operands[2].imm
                value = pending[base_reg] + delta if mnemonic == "add" else pending[base_reg] - delta
                pending[insn.reg_name(operands[0].reg)] = value
        elif mnemonic in ("ldr", "ldr.w") and len(operands) == 2:
            literal = _pc_literal(elf, insn, operands, mode_name)
            if literal is not None:
                value = literal

        if value is not None and value in targets:
            hits.append(
                Reference(
                    instruction=f"{mnemonic}\t{insn.op_str}",
                    insn_address=insn.address,
                    mode=mode_name,
                    target=value,
                    string=targets[value],
                    function=_function_for(elf, insn.address, mode_name),
                )
            )
        if len(hits) >= limit:
            break
    return hits


def _pc_literal(elf: Elf, insn, operands, mode_name: str) -> Optional[int]:
    memory = operands[1]
    if memory.type != capstone.arm.ARM_OP_MEM:
        return None
    base = memory.mem.base
    if not base:
        return None
    base_name = insn.reg_name(base)
    if base_name not in ("pc", "PC"):
        return None
    # PC reads as address+8 in ARM, +4 (aligned) in Thumb/AArch64
    pc_value = insn.address + (8 if mode_name == "arm" else 4)
    literal_addr = pc_value + memory.mem.disp
    offset = elf.vaddr_to_offset(literal_addr)
    if offset is None:
        return None
    raw = elf.read(offset, 8 if elf.bits == 64 else 4)
    if len(raw) < (8 if elf.bits == 64 else 4):
        return None
    return int.from_bytes(raw, "little")


PROLOGUES_ARM = (b"\x2d\xe9",)  # push {..., lr}
PROLOGUES_AARCH64 = (b"\xfd\x7b\xbf\xa9", b"\xfd\x7b\xbe\xa9")


def _function_for(elf: Elf, address: int, mode_name: str) -> Dict[str, object]:
    functions = elf.functions()
    containing = None
    for symbol in functions:
        if symbol.value <= address and (symbol.size == 0 or address < symbol.value + symbol.size):
            if containing is None or symbol.value >= containing.value:
                containing = symbol
    if containing is not None:
        return {
            "name": containing.name,
            "address": f"0x{containing.value:x}",
            "size": containing.size or None,
            "source": "symbol",
            "fingerprint": _fingerprint(elf, containing.value, address + 4),
        }
    start = _walk_back(elf, address, mode_name)
    return {
        "name": None,
        "address": f"0x{start:x}" if start is not None else None,
        "size": address + 4 - start if start is not None else None,
        "source": "prologue-heuristic",
        "fingerprint": _fingerprint(elf, start, address + 4) if start is not None else None,
    }


def _walk_back(elf: Elf, address: int, mode_name: str, window: int = 8192) -> Optional[int]:
    offset = elf.vaddr_to_offset(address)
    if offset is None:
        return None
    start = max(0, offset - window)
    blob = elf.data[start : offset + 4]
    needles = PROLOGUES_AARCH64 if mode_name == "aarch64" else PROLOGUES_ARM
    best = None
    for needle in needles:
        index = blob.rfind(needle)
        if index >= 0:
            size = len(needle)
            if best is None or index > best[0]:
                best = (index, start + index, size)
    if best is None:
        return None
    return elf.offset_to_vaddr(best[1])


def _fingerprint(elf: Elf, start: Optional[int], end: int) -> Optional[str]:
    if start is None or end <= start:
        return None
    begin = elf.vaddr_to_offset(start)
    finish = elf.vaddr_to_offset(end)
    if begin is None or finish is None or finish <= begin:
        return None
    return hashlib.sha256(elf.data[begin:finish]).hexdigest()


# ------------------------------------------------------------------- packaging


def load_from_zip(archive: Path, so_name: str, abi: str) -> Tuple[bytes, str]:
    wanted_dir = f"/lib/{abi.strip().lower()}/"
    with zipfile.ZipFile(archive) as bundle:
        candidates = []
        for info in bundle.infolist():
            path = info.filename.replace("\\", "/")
            if path.rsplit("/", 1)[-1].lower() != so_name.lower():
                continue
            if wanted_dir in "/" + path.lower().lstrip("/"):
                candidates.append(info)
        if not candidates:
            available = [
                info.filename
                for info in bundle.infolist()
                if info.filename.rsplit("/", 1)[-1].lower() == so_name.lower()
            ]
            if available:
                raise SystemExit(
                    f"error: {so_name} is not under lib/{abi}/; present at: {', '.join(available)}"
                )
            raise SystemExit(f"error: {so_name} is not inside {archive.name}")
        candidates.sort(key=lambda info: info.file_size, reverse=True)
        chosen = candidates[0]
        return bundle.read(chosen), chosen.filename


def analyse(data: bytes, label: str) -> Dict[str, object]:
    elf = parse_elf(data)
    strings = scan_strings(elf)
    references = scan_references(elf, strings)
    named = scan_symbols(elf)
    sections = section_inventory(elf)
    imports = scan_imports(elf)
    markers = scan_markers(data)
    needed = scan_needed(elf)
    executables = enumerate_functions(elf)
    return {
        "file": label,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "elf": {
            "bits": elf.bits,
            "machine": elf.machine_name,
            "stripped": not elf.has_symtab,
            "sections": len(elf.sections),
            "executable_sections": [section.name for section in elf.exec_sections()],
            "function_candidates": len(executables),
        },
        "capstone": None if capstone is None else getattr(capstone, "__version__", "present"),
        "linking": needed,
        "imports": {"count": len(imports), "names": imports[:200]},
        "sections": sections,
        "protection": protection_notes(elf, sections),
        "markers": markers,
        "symbols": named,
        "strings": [hit.as_dict() for hit in strings],
        "references": [reference.as_dict() for reference in references],
        "summary": _summary(named, strings, references, markers, imports, needed, sections),
    }


def _summary(named, strings, references, markers, imports, needed, sections) -> Dict[str, object]:
    named_functions = [item for item in named if item["kind"] == "function"]
    present = [row["marker"] for row in markers if row["count"]]
    python_markers = [
        row["marker"]
        for row in markers
        if row["count"] and str(row["marker"]).startswith(("Py", "pyrun", "libpython", "python3"))
    ]
    high_entropy = [
        row["name"] for row in sections
        if row["executable"] and float(row["entropy"]) >= ENTROPY_PACKED
    ]
    return {
        "named_symbols": len(named),
        "named_functions": len(named_functions),
        "imports": len([item for item in named if item["kind"] == "import"]),
        "strings": len(strings),
        "code_references": len(references),
        "method_names_found": sorted({str(item["name"]) for item in named_functions}),
        "markers_present": present,
        "python_markers": python_markers,
        "total_imports": len(imports),
        "needed_libraries": list(needed.get("needed", [])),
        "high_entropy_code": high_entropy,
        "verdict": _verdict(named, references, present, imports, needed, high_entropy),
    }


def _verdict(named, references, present, imports, needed, high_entropy) -> str:
    if any(item["kind"] == "function" for item in named):
        return "method names present in the symbol table"
    if references:
        return "stripped, but pyrun strings are referenced from code"
    if high_entropy and not present:
        return ("no traces, and executable sections look packed/encrypted "
                f"({', '.join(high_entropy)}): unpack before scanning")
    if any("python" in str(row).lower() or str(row).startswith(("Py", "pyrun")) for row in present):
        return "CPython strings present but no PyRun_ entry point found"
    needed_libs = [str(name) for name in needed.get("needed", [])]
    if any("python" in name.lower() for name in needed_libs):
        return "libpython is linked, but the PyRun_ symbol was stripped"
    if imports:
        return f"no CPython evidence: {len(imports)} imports, none from libpython"
    return "no pyrun traces found (and no dynamic imports to cross-check)"


# ---------------------------------------------------------------- evidence


def scan_markers(data: bytes, limit: int = 0) -> List[Dict[str, object]]:
    """Count every interesting marker family, whether or not it is a pyrun one."""
    rows: List[Dict[str, object]] = []
    for label, needle in MARKERS:
        count = data.count(needle)
        if count:
            sample = _printable_at(data, data.find(needle), limit=limit or 72)
        else:
            sample = None
        rows.append({"marker": label, "needle": needle.decode("ascii", "replace"),
                     "count": count, "sample": sample})
    return rows


def scan_imports(elf: Elf) -> List[str]:
    """Every undefined dynamic symbol, i.e. what the library imports."""
    names = {symbol.name for symbol in elf.symbols if symbol.is_import}
    return sorted(names)


def scan_needed(elf: Elf) -> Dict[str, object]:
    """DT_NEEDED / SONAME / RUNPATH: what the loader links this library against."""
    dynamic = next((s for s in elf.sections if s.name == ".dynamic" or s.type == 6), None)
    result: Dict[str, object] = {"needed": [], "soname": None, "rpath": None}
    if dynamic is None or dynamic.size == 0:
        return result
    # .dynamic entries point into .dynstr, which the section's sh_link names
    strtab = elf.sections[dynamic.link] if dynamic.link < len(elf.sections) else None
    strings = (
        elf.data[strtab.offset : strtab.offset + strtab.size] if strtab is not None else b""
    )
    step = 16 if elf.bits == 64 else 8
    fmt = "<qQ" if elf.bits == 64 else "<iI"
    needed: List[str] = []
    for offset in range(dynamic.offset, dynamic.offset + dynamic.size, step):
        if offset + step > len(elf.data):
            break
        tag, value = struct.unpack_from(fmt, elf.data, offset)
        if tag == 0:  # DT_NULL
            break
        if tag == 1:  # DT_NEEDED
            name = _cstring(strings, value)
            if name:
                needed.append(name)
        elif tag == 14:  # DT_SONAME
            result["soname"] = _cstring(strings, value) or None
        elif tag in (15, 29):  # DT_RPATH / DT_RUNPATH
            result["rpath"] = _cstring(strings, value) or None
    result["needed"] = needed
    return result


def _entropy(blob: bytes, sample: int = 1 << 20) -> float:
    if not blob:
        return 0.0
    chunk = blob[:sample]
    counts = [0] * 256
    for byte in chunk:
        counts[byte] += 1
    total = len(chunk)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def section_inventory(elf: Elf) -> List[Dict[str, object]]:
    """Name/type/size/entropy per section — high entropy in .text means packed."""
    rows: List[Dict[str, object]] = []
    for section in elf.sections:
        if not section.name or section.type == SHT_NOBITS or not section.size:
            continue
        blob = elf.data[section.offset : section.offset + min(section.size, 1 << 20)]
        rows.append(
            {
                "name": section.name,
                "type": section.type,
                "size": section.size,
                "address": f"0x{section.addr:x}",
                "executable": bool(section.flags & SHF_EXECINSTR),
                "entropy": _entropy(blob),
            }
        )
    return rows


def protection_notes(elf: Elf, sections: Sequence[Dict[str, object]]) -> List[str]:
    notes: List[str] = []
    names = " ".join(str(row["name"]).lower() for row in sections)
    for hint in PACKER_HINTS:
        if hint in names:
            notes.append(f"section name mentions '{hint}'")
    for row in sections:
        if not row["executable"]:
            continue
        entropy = float(row["entropy"])
        if entropy >= ENTROPY_PACKED:
            notes.append(f"{row['name']} has entropy {entropy}: encrypted or packed code")
        elif entropy >= ENTROPY_NOTE:
            notes.append(
                f"{row['name']} has entropy {entropy}: normal for dense ARM code, "
                "but also what a light packer looks like"
            )
    if not elf.has_symtab:
        notes.append("no .symtab: local symbols were stripped before release")
    return notes


# ------------------------------------------------- function inventory / match


ENTROPY_NOTE = 7.5   # dense ARM code reaches this; worth mentioning
ENTROPY_PACKED = 7.85  # encrypted/packed sections sit here

ARM_PUSH_LR = 0xE92D4000
ARM_PUSH_MASK = 0xFFFF4000
THUMB_PUSH_LR = 0xB500
THUMB_PUSH_MASK = 0xFF00
AARCH64_STP = b"\xfd\x7b"


def enumerate_functions(elf: Elf, *, limit: int = 250_000) -> List[int]:
    """Addresses that look like function entry points, symbols first."""
    named = [symbol.value for symbol in elf.functions()]
    if named:
        return sorted(set(named))

    starts: set = set()
    for section in elf.exec_sections():
        code = elf.read(section.offset, section.size)
        base = section.addr
        if elf.bits == 64:
            for offset in range(0, len(code) - 4, 4):
                if code[offset : offset + 2] == AARCH64_STP:
                    starts.add(base + offset)
        else:
            for offset in range(0, len(code) - 4, 4):
                word = int.from_bytes(code[offset : offset + 4], "little")
                if (word & ARM_PUSH_MASK) == ARM_PUSH_LR:
                    starts.add(base + offset)
            for offset in range(0, len(code) - 2, 2):
                half = int.from_bytes(code[offset : offset + 2], "little")
                if (half & THUMB_PUSH_MASK) == THUMB_PUSH_LR and half & 0x0100:
                    starts.add(base + offset)
        if len(starts) >= limit:
            break
    return sorted(starts)[:limit]


def function_fingerprints(
    elf: Elf, starts: Sequence[int], *, window: int = 96
) -> Dict[str, List[int]]:
    """Map ``sha256(first window bytes)`` -> addresses, for cross-build matching."""
    table: Dict[str, List[int]] = {}
    for address in starts:
        offset = elf.vaddr_to_offset(address)
        if offset is None:
            continue
        blob = elf.data[offset : offset + window]
        if len(blob) < 16:
            continue
        digest = hashlib.sha256(blob).hexdigest()
        table.setdefault(digest, []).append(address)
    return table


def match_functions(
    left: Elf, right: Elf, *, window: int = 96, limit: int = 50
) -> Dict[str, object]:
    """Find functions whose leading bytes are identical in both libraries."""
    left_starts = enumerate_functions(left)
    right_starts = enumerate_functions(right)
    right_table = function_fingerprints(right, right_starts, window=window)
    matches: List[Dict[str, object]] = []
    for address in left_starts:
        offset = left.vaddr_to_offset(address)
        if offset is None:
            continue
        blob = left.data[offset : offset + window]
        if len(blob) < 16:
            continue
        digest = hashlib.sha256(blob).hexdigest()
        for counterpart in right_table.get(digest, []):
            matches.append(
                {
                    "left": f"0x{address:x}",
                    "right": f"0x{counterpart:x}",
                    "window": len(blob),
                    "sha256": digest[:16],
                }
            )
            if len(matches) >= limit:
                break
        if len(matches) >= limit:
            break
    return {
        "window": window,
        "left_functions": len(left_starts),
        "right_functions": len(right_starts),
        "identical": len(matches),
        "matches": matches,
    }


# ------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a native library for pyrun_String* entry points.")
    parser.add_argument("target", help="an .so file, or an .apk/.xapk to read the member from")
    parser.add_argument("--so-name", default="libGame.so", help="member name inside an archive")
    parser.add_argument("--abi", default="armeabi-v7a", help="lib/<abi>/ member to read from an archive")
    parser.add_argument("--match-lib", help="second library/archive: report byte-identical functions")
    parser.add_argument("--match-abi", help="lib/<abi>/ member to read from --match-lib (default: --abi)")
    parser.add_argument("--match-window", type=int, default=96, help="bytes compared per function")
    parser.add_argument("--match-limit", type=int, default=50, help="stop after this many matches")
    parser.add_argument("--dump-functions", help="write every function candidate address here")
    parser.add_argument("--json", dest="json_out", help="write the full report here")
    parser.add_argument("--quiet", action="store_true", help="print only the summary lines")
    return parser


def _load(target: Path, so_name: str, abi: str) -> Tuple[bytes, str]:
    if target.suffix.lower() in (".apk", ".xapk", ".apks", ".aab", ".zip"):
        return load_from_zip(target, so_name, abi)
    return target.read_bytes(), target.name


def _print_evidence(report: Dict[str, object], quiet: bool) -> None:
    summary = report["summary"]
    linking = report["linking"]
    needed = linking.get("needed") or []
    print(f"  imports             : {summary['total_imports']}")
    if needed:
        print(f"  DT_NEEDED           : {', '.join(str(name) for name in needed)}")
    interesting = [row for row in report["markers"] if row["count"]]
    if interesting:
        print("  markers present     :")
        for row in interesting[:12]:
            print(f"      {row['marker']:<24} x{row['count']:<5} {row['sample']!r}")
    if report["protection"]:
        print("  protection          :")
        for note in report["protection"]:
            print(f"      {note}")
    if not quiet:
        rows = sorted(report["sections"], key=lambda row: -row["size"])[:8]
        print("  sections            :")
        for row in rows:
            print(f"      {row['name']:<18} {row['size']:>10} bytes  "
                  f"entropy {row['entropy']:<6} {'exec' if row['executable'] else ''}")
        for name in list(report["imports"]["names"])[:15]:
            print(f"      import {name}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    target = Path(args.target)
    if not target.is_file():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2

    try:
        data, label = _load(target, args.so_name, args.abi)
    except (SystemExit, zipfile.BadZipFile) as exc:
        print(str(exc) if isinstance(exc, SystemExit) else f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        report = analyse(data, label)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    print(f"{label}: {report['elf']['machine']} {report['elf']['bits']}-bit, "
          f"{'stripped' if report['elf']['stripped'] else 'symbols present'}, "
          f"{report['size']} bytes, {report['elf']['function_candidates']} function candidates")
    print(f"  named pyrun symbols : {summary['named_symbols']} "
          f"({summary['named_functions']} defined, {summary['imports']} pyrun imports)")
    print(f"  string literals     : {summary['strings']}")
    print(f"  code references     : {summary['code_references']}"
          + ("" if report["capstone"] else " (capstone missing: pass 3 skipped)"))
    print(f"  verdict             : {summary['verdict']}")
    _print_evidence(report, args.quiet)

    if not args.quiet:
        for item in report["symbols"][:20]:
            print(f"    symbol {item['kind']:<9} {item['name']}"
                  + (f" @ {item['address']} size {item['size']}" if item.get("address") else " (import)"))
        for reference in report["references"][:20]:
            function = reference["function"]
            label_name = function.get("name") or f"sub_{function.get('address')}"
            print(f"    ref @ {reference['insn_address']} ({reference['mode']}) -> "
                  f"{reference['string']!r} in {label_name} [{function.get('source')}]")

    if args.match_lib:
        try:
            other_data, other_label = _load(
                Path(args.match_lib), args.so_name, args.match_abi or args.abi
            )
            other = parse_elf(other_data)
            left = parse_elf(data)
            result = match_functions(
                left, other, window=args.match_window, limit=args.match_limit
            )
            report["match"] = {"other": other_label, **result}
            print(f"  match vs {other_label}: {result['identical']} identical function(s) "
                  f"of {result['left_functions']} vs {result['right_functions']} candidates")
            for item in result["matches"][:10]:
                print(f"      {item['left']} == {item['right']} ({item['window']}B, {item['sha256']})")
        except (ValueError, SystemExit, OSError, zipfile.BadZipFile) as exc:
            print(f"error: could not compare with {args.match_lib}: {exc}", file=sys.stderr)
            return 2

    if args.dump_functions:
        left = parse_elf(data)
        starts = enumerate_functions(left)
        Path(args.dump_functions).parent.mkdir(parents=True, exist_ok=True)
        with open(args.dump_functions, "w", encoding="utf-8") as handle:
            for address in starts:
                handle.write(f"0x{address:x}\n")
        print(f"function candidates written to {args.dump_functions} ({len(starts)} addresses)")

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"report written to {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
