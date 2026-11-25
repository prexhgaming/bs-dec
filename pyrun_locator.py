#!/usr/bin/env python3
"""Heuristic locator for CPython PyRun_StringFlags-like call sites in stripped ELF .so files.

This is static analysis only. It does not execute the target, decrypt arbitrary strings,
or claim that a heuristic match is exact. Requires: pip install pyelftools capstone

Examples:
  python3 pyrun_locator.py libgame.so
  python3 pyrun_locator.py libgame.so --window 40 --max-candidates 30
  python3 pyrun_locator.py libgame.so --json report.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.relocation import RelocationSection
    from capstone import (
        Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64,
        CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
        CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN,
    )
    from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
    from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM
    from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM
except ImportError as exc:
    # Do not hide the actual failing import: an installed package can still have
    # a missing/incompatible submodule or native extension (common on Android).
    print(f"Dependency import failed: {exc!r}", file=sys.stderr)
    print("Check with: python3 -c 'import elftools, capstone; print(elftools.__file__); print(capstone.__file__)'", file=sys.stderr)
    raise SystemExit(2) from exc

PYRUN_NAMES = {
    "PyRun_StringFlags": 120,
    "PyRun_String": 110,
    "PyRun_SimpleStringFlags": 100,
    "PyRun_SimpleString": 90,
    "PyRun_FileExFlags": 100,
    "PyRun_FileFlags": 95,
    "Py_CompileString": 75,
    "Py_CompileStringExFlags": 80,
}
PYTHON_CLUES = (
    b"python", b"pyobject", b"pyrun", b"py_eval_input", b"py_file_input",
    b"marshal", b"bytecode", b"__main__", b"builtins", b"compile", b"eval",
    b"exec", b"importlib", b"sys.modules", b"Py_Initialize", b"PyErr_",
)
DECODE_MNEMONICS = {
    "xor", "eor", "add", "sub", "ror", "rol", "and", "orr", "not",
    "neg", "shl", "shr", "lsl", "lsr", "asr", "rev", "bswap",
}

@dataclass
class Segment:
    vaddr: int
    offset: int
    filesz: int
    memsz: int
    flags: int
    data: bytes
    name: str = "LOAD"

@dataclass
class Candidate:
    score: int
    call_va: int
    call_rva: int
    call_file_offset: Optional[int]
    function_guess: Optional[int]
    function_rva_guess: Optional[int]
    target_va: Optional[int]
    target_rva: Optional[int]
    target_symbol: Optional[str]
    call_kind: str
    start_argument: Optional[int]
    start_argument_register: Optional[str]
    arg0_pointer: Optional[int]
    arg0_preview: Optional[str]
    evidence: List[str] = field(default_factory=list)

class ELFImage:
    def __init__(self, path: str):
        self.path = path
        self.fp = open(path, "rb")
        self.elf = ELFFile(self.fp)
        self.bits = self.elf.elfclass
        self.little = self.elf.little_endian
        self.machine = self.elf.header["e_machine"]
        self.segments: List[Segment] = []
        self.image_base = 0
        self.executable: List[Tuple[int, bytes, str]] = []
        self.strings: List[Tuple[int, bytes]] = []
        self.imports: Dict[int, str] = {}
        self.symbol_names: Dict[str, int] = {}
        self.plt_targets: Dict[int, str] = {}
        self.relocations: Dict[int, str] = {}
        self._load_segments()
        self._load_sections()
        self._load_symbols_and_relocations()
        self._load_strings()

    def close(self):
        self.fp.close()

    def _load_segments(self):
        for i, seg in enumerate(self.elf.iter_segments()):
            if seg["p_type"] != "PT_LOAD":
                continue
            data = seg.data()
            self.segments.append(Segment(
                int(seg["p_vaddr"]), int(seg["p_offset"]), int(seg["p_filesz"]),
                int(seg["p_memsz"]), int(seg["p_flags"]), data, f"PT_LOAD[{i}]"))
        if self.segments:
            self.image_base = min(s.vaddr & ~0xFFF for s in self.segments)

    def va_to_rva(self, va: Optional[int]) -> Optional[int]:
        return None if va is None else int(va - self.image_base)

    def _load_sections(self):
        # Prefer executable sections; use executable PT_LOAD segments when section headers are absent.
        for sec in self.elf.iter_sections():
            try:
                flags = int(sec["sh_flags"])
                if flags & 0x4 and sec["sh_size"]:
                    self.executable.append((int(sec["sh_addr"]), sec.data(), sec.name or ".text"))
            except Exception:
                pass
        if not self.executable:
            for seg in self.segments:
                if seg.flags & 1 and seg.filesz:
                    self.executable.append((seg.vaddr, seg.data, seg.name))
        # Deduplicate identical ranges (some unusual ELFs expose section/segment aliases).
        seen = set()
        unique = []
        for va, data, name in self.executable:
            key = (va, len(data))
            if key not in seen:
                seen.add(key)
                unique.append((va, data, name))
        self.executable = sorted(unique, key=lambda x: x[0])

    def _load_symbols_and_relocations(self):
        for sec in self.elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    value = int(sym["st_value"])
                    self.symbol_names[name] = value
                    if sec.name == ".dynsym" and sym["st_shndx"] == "SHN_UNDEF":
                        self.imports[value] = name
            if isinstance(sec, RelocationSection):
                symtab = self.elf.get_section(sec["sh_link"])
                for rel in sec.iter_relocations():
                    sym_idx = int(rel["r_info_sym"])
                    if not sym_idx or symtab is None:
                        continue
                    try:
                        name = symtab.get_symbol(sym_idx).name
                    except Exception:
                        name = ""
                    if name:
                        self.relocations[int(rel["r_offset"])] = name
        self.plt_targets = self._guess_plt_targets()

    def _guess_plt_targets(self) -> Dict[int, str]:
        result: Dict[int, str] = {}
        relsec = None
        for sec in self.elf.iter_sections():
            if sec.name in (".rela.plt", ".rel.plt", ".rela.plt.sec", ".rel.plt.sec"):
                relsec = sec
                break
        if relsec is None:
            return result
        names = []
        symtab = self.elf.get_section(relsec["sh_link"])
        for rel in relsec.iter_relocations():
            idx = int(rel["r_info_sym"])
            try:
                names.append(symtab.get_symbol(idx).name if idx else "")
            except Exception:
                names.append("")
        for sec in self.elf.iter_sections():
            if sec.name not in (".plt", ".plt.sec", ".iplt"):
                continue
            entsize = int(sec["sh_entsize"] or 0)
            if not entsize:
                entsize = 16 if self.bits == 64 else 12
            data = sec.data()
            count = len(data) // entsize
            # Traditional .plt has one resolver stub before symbol stubs; .plt.sec does not.
            first = 0 if sec.name in (".plt.sec", ".iplt") else 1
            for i, name in enumerate(names):
                slot = i + first
                if slot < count and name:
                    result[int(sec["sh_addr"]) + slot * entsize] = name
        return result

    def _load_strings(self):
        # Scan file-backed load segments rather than just .rodata, so stripped/odd ELFs still work.
        seen = set()
        for seg in self.segments:
            data = seg.data
            for m in re.finditer(rb"[\x20-\x7e]{5,}\x00", data):
                va = seg.vaddr + m.start()
                raw = m.group()[:-1]
                if (va, raw) not in seen:
                    seen.add((va, raw))
                    self.strings.append((va, raw))
        self.strings.sort(key=lambda x: x[0])

    def va_to_offset(self, va: int) -> Optional[int]:
        for seg in self.segments:
            if seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.offset + (va - seg.vaddr)
        return None

    def read_va(self, va: int, size: int) -> bytes:
        for seg in self.segments:
            if seg.vaddr <= va < seg.vaddr + seg.filesz:
                off = va - seg.vaddr
                return seg.data[off:off + size]
        return b""

    def preview_string(self, va: int, limit: int = 96) -> Optional[str]:
        if va is None:
            return None
        raw = self.read_va(va, limit)
        if not raw:
            return None
        raw = raw.split(b"\x00", 1)[0]
        if len(raw) < 3:
            return None
        printable = sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13))
        if printable / max(1, len(raw)) < 0.75:
            return None
        return raw.decode("utf-8", "replace")[:limit]

    def closest_string(self, va: int, max_distance: int = 0x100) -> Optional[Tuple[int, str]]:
        best = None
        for sva, raw in self.strings:
            d = abs(sva - va)
            if d <= max_distance and (best is None or d < best[0]):
                best = (d, sva, raw.decode("utf-8", "replace"))
        return (best[1], best[2]) if best else None


def make_disassembler(img: ELFImage):
    mach = str(img.machine)
    endian = CS_MODE_LITTLE_ENDIAN if img.little else CS_MODE_BIG_ENDIAN
    if mach in ("EM_X86_64", "62") or ("X86" in mach and img.bits == 64):
        arch, mode = CS_ARCH_X86, CS_MODE_64
    elif mach in ("EM_386", "3") or ("X86" in mach and img.bits == 32):
        arch, mode = CS_ARCH_X86, CS_MODE_32
    elif mach in ("EM_AARCH64", "183") or "AARCH64" in mach:
        arch, mode = CS_ARCH_ARM64, endian
    elif mach in ("EM_ARM", "40") or mach.endswith("ARM"):
        arch = CS_ARCH_ARM
        flags = int(img.elf.header["e_flags"])
        # ARM ELF files are commonly ARM state. Thumb ranges are still attempted through ARM mode.
        mode = (CS_MODE_THUMB if (flags & 0x20) else CS_MODE_ARM) | endian
    else:
        raise RuntimeError(f"Unsupported ELF machine: {img.machine}")
    md = Cs(arch, mode)
    md.detail = True
    md.skipdata = True
    return md, arch


def reg_name(md, reg_id: int) -> str:
    try:
        name = md.reg_name(reg_id).lower()
    except Exception:
        return ""
    # Canonicalize ABI argument registers across 32/64-bit aliases.
    x86_aliases = {
        "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
        "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
        "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
        "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp",
    }
    if name in x86_aliases:
        return x86_aliases[name]
    if re.fullmatch(r"r(?:[89]|1[0-5])d", name):
        return name[:-1]
    if re.fullmatch(r"w[0-9]+", name):
        return "x" + name[1:]
    return name


def is_call(insn) -> bool:
    m = insn.mnemonic.lower()
    return m in {"call", "callq", "bl", "blr", "blx"} or m.startswith("call ")


def is_ret(insn) -> bool:
    m = insn.mnemonic.lower()
    opstr = insn.op_str.lower()
    return m.startswith("ret") or (m == "bx" and "lr" in opstr) or (m == "pop" and "pc" in opstr)


def get_ops(insn):
    try:
        return insn.operands
    except Exception:
        return []


def effective_mem_address(insn, op, state: Dict[str, int], arch: int) -> Optional[int]:
    try:
        mem = op.mem
        base = reg_name(insn, mem.base) if mem.base else ""
        index = reg_name(insn, mem.index) if mem.index else ""
        disp = int(mem.disp)
        if arch == CS_ARCH_X86:
            if base in ("rip", "eip"):
                return int(insn.address + insn.size + disp)
            value = state.get(base, 0) if base else 0
            if index:
                value += state.get(index, 0) * int(mem.scale or 1)
            return value + disp if base or index else None
        if base:
            return state.get(base, 0) + disp if base in state else None
        return disp if disp else None
    except Exception:
        return None


def immediate_value(insn, op) -> Optional[int]:
    try:
        if op.type in (X86_OP_IMM, ARM_OP_IMM, ARM64_OP_IMM):
            return int(op.imm)
    except Exception:
        pass
    return None


def destination_reg(insn, arch: int) -> Optional[str]:
    ops = get_ops(insn)
    if not ops:
        return None
    try:
        if ops[0].type in (X86_OP_REG, ARM_OP_REG, ARM64_OP_REG):
            return reg_name(insn, ops[0].reg)
    except Exception:
        pass
    return None


def classify_call_target(insn, state: Dict[str, int], arch: int) -> Tuple[Optional[int], str]:
    ops = get_ops(insn)
    if not ops:
        return None, "indirect/unknown"
    op = ops[0]
    value = immediate_value(insn, op)
    if value is not None:
        return value, "direct"
    try:
        if op.type in (X86_OP_REG, ARM_OP_REG, ARM64_OP_REG):
            r = reg_name(insn, op.reg)
            value = state.get(r)
            return value, "register-indirect" if value is not None else "register-indirect/unknown"
        if op.type in (X86_OP_MEM, ARM_OP_MEM, ARM64_OP_MEM):
            slot = effective_mem_address(insn, op, state, arch)
            return slot, "memory-indirect" if slot is not None else "memory-indirect/unknown"
    except Exception:
        pass
    return None, "indirect/unknown"


def update_state(insn, state: Dict[str, int], arch: int):
    """Small constant/address propagation pass; intentionally conservative."""
    m = insn.mnemonic.lower()
    ops = get_ops(insn)
    dst = destination_reg(insn, arch)
    if not dst:
        return
    # Most two-operand move/address-building instructions.
    if len(ops) >= 2:
        # ARM/AArch64 ADD commonly encodes the immediate in operand 3.
        if m in ("add", "adds") and len(ops) >= 3:
            src = reg_name(insn, ops[1].reg) if ops[1].type in (X86_OP_REG, ARM_OP_REG, ARM64_OP_REG) else ""
            add_imm = immediate_value(insn, ops[2])
            if src in state and add_imm is not None:
                state[dst] = state[src] + add_imm
                return
        imm = immediate_value(insn, ops[1])
        if imm is not None:
            if m in ("movk", "movk.w"):
                shift = 0
                for op in ops[2:]:
                    if immediate_value(insn, op) is not None:
                        shift = int(op.imm)
                old = state.get(dst, 0)
                mask = 0xFFFF << shift
                state[dst] = (old & ~mask) | ((imm << shift) & mask)
            elif m in ("movz", "movn"):
                shift = 0
                if len(ops) >= 3:
                    sh = immediate_value(insn, ops[2])
                    if sh is not None:
                        shift = sh
                state[dst] = ((~imm if m == "movn" else imm) << shift) & ((1 << 64) - 1)
            elif m in ("adr", "adrp"):
                state[dst] = (imm & ~0xFFF) if m == "adrp" else imm
            elif m in ("add", "adds") and ops[1].type in (X86_OP_REG, ARM_OP_REG, ARM64_OP_REG):
                src = reg_name(insn, ops[1].reg)
                if src in state:
                    state[dst] = state[src] + imm
                else:
                    state.pop(dst, None)
            else:
                state[dst] = imm
            return
        # register copies
        try:
            if ops[1].type in (X86_OP_REG, ARM_OP_REG, ARM64_OP_REG):
                src = reg_name(insn, ops[1].reg)
                if src in state:
                    state[dst] = state[src]
                    return
        except Exception:
            pass
        # Address of memory operand or a GOT/data slot.
        try:
            if ops[1].type in (X86_OP_MEM, ARM_OP_MEM, ARM64_OP_MEM):
                ea = effective_mem_address(insn, ops[1], state, arch)
                if ea is not None:
                    state[dst] = ea
                    return
        except Exception:
            pass
    # Instructions that invalidate their destination register.
    state.pop(dst, None)


def argument_registers(img: ELFImage, arch: int) -> List[str]:
    m = str(img.machine)
    if arch == CS_ARCH_X86 and img.bits == 64:
        # System V AMD64 ABI (Android/Linux x86_64).
        return ["rdi", "rsi", "rdx", "rcx", "r8"]
    if arch == CS_ARCH_ARM64:
        return ["x0", "x1", "x2", "x3", "x4"]
    if arch == CS_ARCH_ARM:
        return ["r0", "r1", "r2", "r3"]
    return []


def is_python_start(value: Optional[int]) -> bool:
    return value in (256, 257, 258, 0x100, 0x101, 0x102)


def looks_like_decoder(insns, start: int, end: int) -> Tuple[int, List[str]]:
    window = insns[start:end]
    counts = Counter(i.mnemonic.lower().split(".")[0] for i in window)
    bitops = sum(counts[m] for m in DECODE_MNEMONICS)
    branches = sum(1 for i in window if i.mnemonic.lower().startswith(("b", "j")) and not i.mnemonic.lower().startswith(("bic", "bfi", "bfx")))
    stores = sum(1 for i in window if i.mnemonic.lower().startswith(("str", "st", "mov", "stos")))
    score = 0
    evidence = []
    if bitops >= 3:
        score += min(20, bitops * 2)
        evidence.append(f"transform-like arithmetic/bitwise instructions: {bitops}")
    if branches >= 2:
        score += 8
        evidence.append(f"loop/branch-like instructions: {branches}")
    if stores >= 2:
        score += 4
        evidence.append(f"write/move instructions: {stores}")
    return score, evidence


def guess_function_start(insns, index: int, arch: int) -> Optional[int]:
    # Best-effort prologue search. Stripped binaries do not retain reliable function boundaries.
    lo = max(0, index - 220)
    candidates = []
    for j in range(index, lo - 1, -1):
        m = insns[j].mnemonic.lower()
        opstr = insns[j].op_str.lower()
        if arch == CS_ARCH_X86:
            if m == "push" and ("rbp" in opstr or "ebp" in opstr):
                candidates.append(j)
            elif m in ("endbr64", "endbr32"):
                candidates.append(j)
        elif arch == CS_ARCH_ARM64:
            if m == "stp" and "x29" in opstr and "x30" in opstr:
                candidates.append(j)
            elif m == "sub" and opstr.startswith("sp, sp,"):
                candidates.append(j)
        elif arch == CS_ARCH_ARM:
            if m in ("push", "stmdb") and ("lr" in opstr or "sp!" in opstr):
                candidates.append(j)
        # Stop once a return/unconditional branch separates the current region.
        if j < index and (is_ret(insns[j]) or m in ("b", "jmp", "bx")):
            break
    return insns[candidates[0]].address if candidates else None


def decode_analysis(img: ELFImage, window: int = 28) -> Tuple[List[Candidate], Dict[str, object]]:
    md, arch = make_disassembler(img)
    argregs = argument_registers(img, arch)
    candidates: List[Candidate] = []
    decoder_windows = []
    analyzed_instructions = 0
    string_ref_count = 0
    imported_python = {n: a for a, n in img.imports.items() if n.startswith("Py") or "python" in n.lower()}
    py_clue_strings = [(va, s.decode("utf-8", "replace")) for va, s in img.strings
                       if any(clue.lower() in s.lower() for clue in PYTHON_CLUES)]

    for base, code, secname in img.executable:
        try:
            insns = list(md.disasm(code, base))
        except Exception:
            continue
        analyzed_instructions += len(insns)
        if not insns:
            continue
        # Build a lightweight VA -> string index for direct pointer argument previews.
        for i, insn in enumerate(insns):
            if not is_call(insn):
                continue
            lo = max(0, i - window)
            state: Dict[str, int] = {}
            # Re-evaluate the pre-call slice in sequence so arg constants/addresses are available.
            for prev in insns[lo:i]:
                update_state(prev, state, arch)
            arg_values = [state.get(r) for r in argregs]
            start_value = arg_values[1] if len(arg_values) > 1 else None
            arg0 = arg_values[0] if arg_values else None
            target, call_kind = classify_call_target(insn, state, arch)
            target_symbol = None
            if target is not None:
                target_symbol = img.plt_targets.get(target) or img.relocations.get(target)
                if target_symbol is None:
                    # If the indirect target is a relocation/GOT slot, identify it.
                    target_symbol = img.relocations.get(target)
            score = 0
            evidence = []
            if target_symbol in PYRUN_NAMES:
                score += PYRUN_NAMES[target_symbol]
                evidence.append(f"call target resolves to {target_symbol}")
            elif target_symbol and (target_symbol.startswith("PyRun_") or target_symbol.startswith("Py_Compile")):
                score += 70
                evidence.append(f"call target is Python execution/compile API: {target_symbol}")
            if is_python_start(start_value):
                score += 42
                evidence.append(f"second ABI argument is Python start mode {start_value} (0x{start_value:x})")
            elif start_value is not None and start_value in (0, 1, 2, 3):
                # Some wrappers pass a normalized enum rather than CPython's public constants.
                score += 4
                evidence.append(f"second ABI argument is small enum-like value {start_value}")
            arg0_preview = img.preview_string(arg0) if arg0 is not None else None
            if arg0_preview:
                score += 15
                evidence.append("first ABI argument points to a readable string")
                if any(k in arg0_preview.lower() for k in ("import ", "def ", "class ", "exec", "eval", "python")):
                    score += 7
                    evidence.append("first argument text resembles Python source or execution text")
            elif arg0 is not None and img.va_to_offset(arg0) is not None:
                score += 5
                evidence.append("first ABI argument points inside a file-backed ELF segment")
            # Nearby imports and strings give context, but are weak signals on their own.
            nearby = insns[lo:i]
            has_python_context = any(
                (img.plt_targets.get(int(op.imm), "").startswith("Py") if immediate_value(x, op) is not None else False)
                for x in nearby for op in get_ops(x)
            )
            if has_python_context:
                score += 5
                evidence.append("nearby code references a Python PLT entry")
            if imported_python:
                score += 2
                evidence.append(f"ELF imports Python-related APIs ({len(imported_python)} found)")
            # A likely decode routine in the same local instruction window can indicate obfuscated source.
            dec_score, dec_evidence = looks_like_decoder(insns, lo, i + 1)
            if dec_score:
                score += min(8, dec_score // 4)
                evidence.extend(dec_evidence[:2])
            # Do not flood output with every call in a Python-linked binary.
            if score >= 12:
                off = img.va_to_offset(insn.address)
                fn = guess_function_start(insns, i, arch)
                candidates.append(Candidate(
                    score=score,
                    call_va=int(insn.address),
                    call_rva=int(img.va_to_rva(int(insn.address))),
                    call_file_offset=off,
                    function_guess=fn,
                    function_rva_guess=img.va_to_rva(fn),
                    target_va=target,
                    target_rva=img.va_to_rva(target),
                    target_symbol=target_symbol,
                    call_kind=call_kind,
                    start_argument=start_value,
                    start_argument_register=argregs[1] if len(argregs) > 1 else None,
                    arg0_pointer=arg0,
                    arg0_preview=arg0_preview,
                    evidence=evidence,
                ))
        # Score overlapping windows for decoder-like routines. This is a lead, not proof of encryption.
        step = 24
        for st in range(0, max(1, len(insns) - 48), step):
            sc, ev = looks_like_decoder(insns, st, min(len(insns), st + 72))
            if sc >= 18:
                decoder_windows.append({
                    "va": int(insns[st].address),
                    "file_offset": img.va_to_offset(int(insns[st].address)),
                    "score": sc,
                    "section": secname,
                    "evidence": ev,
                })

    # Add direct import/relocation information as high-confidence leads even if there are few call sites.
    summary = {
        "architecture": str(img.machine),
        "bits": img.bits,
        "endianness": "little" if img.little else "big",
        "image_base": hex(img.image_base),
        "executable_ranges": [{"name": n, "va": hex(a), "size": len(d)} for a, d, n in img.executable],
        "instruction_count": analyzed_instructions,
        "python_related_imports": sorted(set(img.imports.values()).intersection(
            set(PYRUN_NAMES) | {n for n in img.imports.values() if n.startswith("Py")})),
        "python_clue_strings": [{"va": hex(a), "text": s[:180]} for a, s in py_clue_strings[:100]],
        "decoder_like_windows": sorted(decoder_windows, key=lambda x: x["score"], reverse=True)[:40],
        "relocation_count": len(img.relocations),
    }
    # Merge duplicate call site results, then sort by score and address.
    dedup = {}
    for c in candidates:
        key = c.call_va
        if key not in dedup or c.score > dedup[key].score:
            dedup[key] = c
    return sorted(dedup.values(), key=lambda c: (-c.score, c.call_va)), summary


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def find_high_entropy_ranges(img: ELFImage, min_size: int = 32, max_ranges: int = 60):
    found = []
    for seg in img.segments:
        data = seg.data
        # Scan aligned chunks. High entropy can mean compression, ciphertext, or simply binary data.
        step = 16
        for off in range(0, len(data) - min_size + 1, step):
            chunk = data[off:off + max(min_size, 96)]
            e = entropy(chunk)
            if e >= 7.1:
                found.append({
                    "va": hex(seg.vaddr + off),
                    "file_offset": seg.offset + off,
                    "size_scanned": len(chunk),
                    "entropy_bits_per_byte": round(e, 3),
                    "note": "high entropy only; may be ciphertext, compressed data, or ordinary binary data",
                })
    # Keep highest entropy and avoid many adjacent windows.
    found.sort(key=lambda x: x["entropy_bits_per_byte"], reverse=True)
    result = []
    used = []
    for item in found:
        off = item["file_offset"]
        if any(abs(off - old) < 96 for old in used):
            continue
        result.append(item)
        used.append(off)
        if len(result) >= max_ranges:
            break
    return result


def print_report(img: ELFImage, candidates: List[Candidate], summary: Dict[str, object], entropy_ranges, limit: int):
    print(f"\n[+] File: {img.path}")
    print(f"[+] ELF: {summary['bits']}-bit {summary['endianness']} endian, machine={summary['architecture']}")
    print(f"[+] Disassembled instructions: {summary['instruction_count']}")
    print(f"[+] Image base (page-aligned PT_LOAD minimum): {summary['image_base']}")
    print(f"[+] Relocations: {summary['relocation_count']}")
    pyimports = summary["python_related_imports"]
    print("[+] Python-related imports: " + (", ".join(pyimports) if pyimports else "none found"))
    clues = summary["python_clue_strings"]
    print(f"[+] Readable Python clue strings: {len(clues)}")
    for item in clues[:12]:
        print(f"    {item['va']}: {item['text'][:120]!r}")

    print("\n[+] Ranked PyRun_StringFlags-like call-site candidates:")
    if not candidates:
        print("    No call sites passed the heuristic threshold.")
    for c in candidates[:limit]:
        print(f"\n    score={c.score}  call_RVA=0x{c.call_rva:x}  call_VA=0x{c.call_va:x}  file_offset={hex(c.call_file_offset) if c.call_file_offset is not None else 'n/a'}")
        print(f"      function_RVA_guess={hex(c.function_rva_guess) if c.function_rva_guess is not None else 'unknown'}  target_RVA={hex(c.target_rva) if c.target_rva is not None else 'unknown'}  target_VA={hex(c.target_va) if c.target_va is not None else 'unknown'}")
        print(f"      target_symbol={c.target_symbol or 'unresolved'}  call={c.call_kind}")
        print(f"      {c.start_argument_register or 'arg1'}={c.start_argument if c.start_argument is not None else 'unknown'}  arg0={hex(c.arg0_pointer) if c.arg0_pointer is not None else 'unknown'}")
        if c.arg0_preview:
            print(f"      arg0_text={c.arg0_preview[:140]!r}")
        for e in c.evidence:
            print(f"      - {e}")

    print("\n[+] Decoder-like code windows (heuristic; not proof of encryption):")
    dec = summary["decoder_like_windows"]
    for item in dec[:12]:
        print(f"    VA={item['va']} file_offset={item['file_offset']} score={item['score']} section={item['section']}")
        print("      " + "; ".join(item["evidence"]))
    if not dec:
        print("    none found")

    print("\n[+] High-entropy data candidates (may be compressed or unrelated):")
    for item in entropy_ranges[:12]:
        print(f"    VA={item['va']} file_offset={item['file_offset']} entropy={item['entropy_bits_per_byte']}")
    if not entropy_ranges:
        print("    none found")

    print("\n[!] Interpretation notes:")
    print("    - For PyRun_StringFlags, CPython's second argument is commonly 256, 257, or 258.")
    print("    - The reported call-site VA is not necessarily the API function's own address.")
    print("    - 'function_guess' is a prologue-based estimate and can be wrong in stripped code.")
    print("    - Unknown string encryption cannot be reliably reversed from entropy/opcodes alone.")
    print("    - Use dynamic tracing or compare call sites against the exact CPython ABI/build to confirm.")


def main():
    ap = argparse.ArgumentParser(description="Heuristically locate PyRun_StringFlags usage in stripped ELF shared libraries.")
    ap.add_argument("so", help="path to ELF .so")
    ap.add_argument("--window", type=int, default=28, help="instructions before each call to inspect (default: 28)")
    ap.add_argument("--max-candidates", type=int, default=25, help="maximum candidates printed (default: 25)")
    ap.add_argument("--json", dest="json_path", help="write complete report as JSON")
    ap.add_argument("--entropy", action="store_true", help="include slower high-entropy data scan")
    args = ap.parse_args()
    if not os.path.isfile(args.so):
        ap.error(f"file not found: {args.so}")
    try:
        img = ELFImage(args.so)
        candidates, summary = decode_analysis(img, max(8, args.window))
        entropy_ranges = find_high_entropy_ranges(img) if args.entropy else []
        print_report(img, candidates, summary, entropy_ranges, args.max_candidates)
        if args.json_path:
            report = {
                "file": os.path.abspath(args.so),
                "summary": summary,
                "candidates": [asdict(c) for c in candidates],
                "high_entropy_ranges": entropy_ranges,
            }
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] JSON report written to {args.json_path}")
        img.close()
    except Exception as exc:
        print(f"[!] Analysis failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()