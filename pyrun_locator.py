#!/usr/bin/env python3
"""Heuristic locator for CPython PyRun_StringFlags-like call sites in stripped ELF .so files.

This is static analysis only. Requires: pip install pyelftools capstone
"""
from __future__ import annotations

import argparse, json, math, os, re, sys, time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.relocation import RelocationSection          # FIX 1
    from capstone import (
        Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64,
        CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
        CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN,
    )
    from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_OP_MEM
    from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM
    from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM
except ImportError as exc:
    print(f"Dependency import failed: {exc!r}", file=sys.stderr)
    raise SystemExit(2) from exc

PYRUN_NAMES = {
    "PyRun_StringFlags": 120, "PyRun_String": 110,
    "PyRun_SimpleStringFlags": 100, "PyRun_SimpleString": 90,
    "PyRun_FileExFlags": 100, "PyRun_FileFlags": 95,
    "Py_CompileString": 75, "Py_CompileStringExFlags": 80,
}
PYTHON_CLUES = (
    b"python", b"pyobject", b"pyrun", b"py_eval_input", b"py_file_input",
    b"marshal", b"bytecode", b"__main__", b"builtins", b"compile", b"eval",
    b"exec", b"importlib", b"sys.modules", b"Py_Initialize", b"PyErr_",
)
DECODE_MNEMONICS = {"xor","eor","add","sub","ror","rol","and","orr","not",
                    "neg","shl","shr","lsl","lsr","asr","rev","bswap"}

MAX_INSTRUCTIONS_PER_SECTION = 1_500_000
MAX_STRINGS                  = 400_000
MAX_ENTROPY_BYTES            = 32 * 1024 * 1024   # cap total bytes scanned for entropy
MAX_STR                   = 5_000_000             # abort if .so text loading is insane

def log(msg: str):
    print(msg, file=sys.stderr, flush=True)

@dataclass
class Segment:
    vaddr: int; offset: int; filesz: int; memsz: int; flags: int; data: bytes; name: str = "LOAD"

@dataclass
class Candidate:
    score: int; call_va: int; call_rva: int
    call_file_offset: Optional[int]; function_guess: Optional[int]
    function_rva_guess: Optional[int]; target_va: Optional[int]
    target_rva: Optional[int]; target_symbol: Optional[str]
    call_kind: str; start_argument: Optional[int]
    start_argument_register: Optional[str]; arg0_pointer: Optional[int]
    arg0_preview: Optional[str]; evidence: List[str] = field(default_factory=list)

class ELFImage:
    def __init__(self, path: str):
        self.path = path; self.fp = open(path, "rb")
        self.elf = ELFFile(self.fp)
        self.bits = self.elf.elfclass; self.little = self.elf.little_endian
        self.machine = self.elf.header["e_machine"]
        self.segments: List[Segment] = []; self.image_base = 0
        self.executable: List[Tuple[int, bytes, str]] = []
        self.strings: List[Tuple[int, bytes]] = []
        self.imports: Dict[int, str] = {}; self.symbol_names: Dict[str, int] = {}
        self.plt_targets: Dict[int, str] = {}; self.relocations: Dict[int, str] = {}
        self._load_segments(); self._load_sections()
        self._load_symbols_and_relocations(); self._load_strings()

    def close(self): self.fp.close()

    def _load_segments(self):
        for i, seg in enumerate(self.elf.iter_segments()):
            if seg["p_type"] != "PT_LOAD": continue
            self.segments.append(Segment(
                int(seg["p_vaddr"]), int(seg["p_offset"]), int(seg["p_filesz"]),
                int(seg["p_memsz"]), int(seg["p_flags"]), seg.data(), f"PT_LOAD[{i}]"))
        if self.segments:
            self.image_base = min(s.vaddr & ~0xFFF for s in self.segments)

    def va_to_rva(self, va): return None if va is None else int(va - self.image_base)

    def _load_sections(self):
        for sec in self.elf.iter_sections():
            try:
                if int(sec["sh_flags"]) & 0x4 and sec["sh_size"]:
                    self.executable.append((int(sec["sh_addr"]), sec.data(), sec.name or ".text"))
            except Exception: pass
        if not self.executable:
            for seg in self.segments:
                if seg.flags & 1 and seg.filesz:
                    self.executable.append((seg.vaddr, seg.data, seg.name))
        seen = set(); unique = []
        for va, data, name in self.executable:
            k = (va, len(data))
            if k not in seen: seen.add(k); unique.append((va, data, name))
        self.executable = sorted(unique, key=lambda x: x[0])

    def _load_symbols_and_relocations(self):
        for sec in self.elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if not sym.name: continue
                    v = int(sym["st_value"]); self.symbol_names[sym.name] = v
                    if sec.name == ".dynsym" and sym["st_shndx"] == "SHN_UNDEF":
                        self.imports[v] = sym.name
            if isinstance(sec, RelocationSection):
                symtab = self.elf.get_section(sec["sh_link"])
                for rel in sec.iter_relocations():
                    idx = int(rel["r_info_sym"])
                    if not idx or symtab is None: continue
                    try: name = symtab.get_symbol(idx).name
                    except Exception: name = ""
                    if name: self.relocations[int(rel["r_offset"])] = name
        self.plt_targets = self._guess_plt_targets()

    def _guess_plt_targets(self):
        result: Dict[int, str] = {}
        relsec = None
        for sec in self.elf.iter_sections():
            if sec.name in (".rela.plt", ".rel.plt", ".rela.plt.sec", ".rel.plt.sec"):
                relsec = sec; break
        if relsec is None: return result
        names = []
        symtab = self.elf.get_section(relsec["sh_link"])
        for rel in relsec.iter_relocations():
            idx = int(rel["r_info_sym"])
            try: names.append(symtab.get_symbol(idx).name if idx else "")
            except Exception: names.append("")
        for sec in self.elf.iter_sections():
            if sec.name not in (".plt", ".plt.sec", ".iplt"): continue
            entsize = int(sec["sh_entsize"] or 0) or (16 if self.bits == 64 else 12)
            data = sec.data(); count = len(data) // entsize
            first = 0 if sec.name in (".plt.sec", ".iplt") else 1
            for i, name in enumerate(names):
                slot = i + first
                if slot < count and name:
                    result[int(sec["sh_addr"]) + slot * entsize] = name
        return result

    # FIX 2: cap the string table so a huge .so cannot OOM the runner.
    def _load_strings(self):
        seen = set(); scanned = 0
        for seg in self.segments:
            data = seg.data
            for m in re.finditer(rb"[\x20-\x7e]{5,}\x00", data):
                va = seg.vaddr + m.start(); raw = m.group()[:-1]
                if (va, raw) not in seen:
                    seen.add((va, raw))
                    self.strings.append((va, raw))
                    if len(self.strings) >= MAX_STRINGS:
                        log(f"    [warn] string cap reached ({MAX_STRINGS}), stopping scan")
                        self.strings.sort(key=lambda x: x[0]); return
            scanned += len(data)
            if scanned >= MAX_STR: break
        self.strings.sort(key=lambda x: x[0])

    def va_to_offset(self, va):
        for seg in self.segments:
            if seg.vaddr <= va < seg.vaddr + seg.filesz:
                return seg.offset + (va - seg.vaddr)
        return None

    def read_va(self, va, size):
        for seg in self.segments:
            if seg.vaddr <= va < seg.vaddr + seg.filesz:
                off = va - seg.vaddr
                return seg.data[off:off + size]
        return b""

    def preview_string(self, va, limit=96):
        if va is None: return None
        raw = self.read_va(va, limit)
        if not raw: return None
        raw = raw.split(b"\x00", 1)[0]
        if len(raw) < 3: return None
        printable = sum(1 for c in raw if 32 <= c < 127 or c in (9,10,13))
        if printable / max(1, len(raw)) < 0.75: return None
        return raw.decode("utf-8", "replace")[:limit]

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
        flags = int(img.elf.header["e_flags"])
        arch = CS_ARCH_ARM
        mode = (CS_MODE_THUMB if (flags & 0x20) else CS_MODE_ARM) | endian
    else:
        raise RuntimeError(f"Unsupported ELF machine: {img.machine}")
    md = Cs(arch, mode); md.detail = True; md.skipdata = True
    return md, arch

def reg_name(md, rid):
    try: name = md.reg_name(rid).lower()
    except Exception: return ""
    aliases = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi",
               "ebp":"rbp","esp":"rsp","ax":"rax","bx":"rbx","cx":"rcx","dx":"rdx",
               "si":"rsi","di":"rdi","bp":"rbp","sp":"rsp"}
    if name in aliases: return aliases[name]
    if re.fullmatch(r"r(?:[89]|1[0-5])d", name): return name[:-1]
    if re.fullmatch(r"w[0-9]+", name): return "x" + name[1:]
    return name

def is_call(i):
    m = i.mnemonic.lower()
    return m in {"call","callq","bl","blr","blx"} or m.startswith("call ")

def is_ret(i):
    m = i.mnemonic.lower(); o = i.op_str.lower()
    return m.startswith("ret") or (m == "bx" and "lr" in o) or (m == "pop" and "pc" in o)

def get_ops(i):
    try: return i.operands
    except Exception: return []

def effective_mem_address(i, op, state, arch):
    try:
        mem = op.mem
        base = reg_name(i, mem.base) if mem.base else ""
        index = reg_name(i, mem.index) if mem.index else ""
        disp = int(mem.disp)
        if arch == CS_ARCH_X86:
            if base in ("rip","eip"): return int(i.address + i.size + disp)
            v = state.get(base, 0) if base else 0
            if index: v += state.get(index, 0) * int(mem.scale or 1)
            return v + disp if base or index else None
        if base: return state.get(base, 0) + disp if base in state else None
        return disp if disp else None
    except Exception: return None

def immediate_value(i, op):
    try:
        if op.type in (X86_OP_IMM, ARM_OP_IMM, ARM64_OP_IMM): return int(op.imm)
    except Exception: pass
    return None

def destination_reg(i, arch):
    ops = get_ops(i)
    if not ops: return None
    try:
        if ops[0].type in (X86_OP_REG, ARM_OP_REG, ARM64_OP_REG): return reg_name(i, ops[0].reg)
    except Exception: pass
    return None

def classify_call_target(i, state, arch):
    ops = get_ops(i)
    if not ops: return None, "indirect/unknown"
    op = ops[0]; v = immediate_value(i, op)
    if v is not None: return v, "direct"
    try:
        if op.type in (X86_OP_REG, ARM_OP_REG, ARM64_OP_REG):
            r = reg_name(i, op.reg); v = state.get(r)
            return v, "register-indirect" if v is not None else "register-indirect/unknown"
        if op.type in (X86_OP_MEM, ARM_OP_MEM, ARM64_OP_MEM):
            s = effective_mem_address(i, op, state, arch)
            return s, "memory-indirect" if s is not None else "memory-indirect/unknown"
    except Exception: pass
    return None, "indirect/unknown"

def update_state(i, state, arch):
    m = i.mnemonic.lower(); ops = get_ops(i)
    dst = destination_reg(i, arch)
    if not dst: return
    if len(ops) >= 2:
        if m in ("add","adds") and len(ops) >= 3:
            src = reg_name(i, ops[1].reg) if ops[1].type in (X86_OP_REG,ARM_OP_REG,ARM64_OP_REG) else ""
            ai = immediate_value(i, ops[2])
            if src in state and ai is not None:
                state[dst] = state[src] + ai; return
        imm = immediate_value(i, ops[1])
        if imm is not None:
            if m in ("movk","movk.w"):
                shift = 0
                for op in ops[2:]:
                    if immediate_value(i, op) is not None: shift = int(op.imm)
                old = state.get(dst, 0); mask = 0xFFFF << shift
                state[dst] = (old & ~mask) | ((imm << shift) & mask)
            elif m in ("movz","movn"):
                shift = 0
                if len(ops) >= 3:
                    sh = immediate_value(i, ops[2])
                    if sh is not None: shift = sh
                state[dst] = ((~imm if m == "movn" else imm) << shift) & ((1<<64)-1)
            elif m in ("adr","adrp"):
                state[dst] = (imm & ~0xFFF) if m == "adrp" else imm
            elif m in ("add","adds") and ops[1].type in (X86_OP_REG,ARM_OP_REG,ARM64_OP_REG):
                src = reg_name(i, ops[1].reg)
                if src in state: state[dst] = state[src] + imm
                else: state.pop(dst, None)
            else: state[dst] = imm
            return
        try:
            if ops[1].type in (X86_OP_REG,ARM_OP_REG,ARM64_OP_REG):
                src = reg_name(i, ops[1].reg)
                if src in state: state[dst] = state[src]; return
        except Exception: pass
        try:
            if ops[1].type in (X86_OP_MEM,ARM_OP_MEM,ARM64_OP_MEM):
                ea = effective_mem_address(i, ops[1], state, arch)
                if ea is not None: state[dst] = ea; return
        except Exception: pass
    state.pop(dst, None)

def argument_registers(img, arch):
    if arch == CS_ARCH_X86 and img.bits == 64: return ["rdi","rsi","rdx","rcx","r8"]
    if arch == CS_ARCH_ARM64: return ["x0","x1","x2","x3","x4"]
    if arch == CS_ARCH_ARM: return ["r0","r1","r2","r3"]
    return []

def is_python_start(v): return v in (256,257,258,0x100,0x101,0x102)

def looks_like_decoder(insns, start, end):
    window = insns[start:end]
    counts = Counter(i.mnemonic.lower().split(".")[0] for i in window)
    bitops = sum(counts[m] for m in DECODE_MNEMONICS)
    branches = sum(1 for i in window if i.mnemonic.lower().startswith(("b","j"))
                   and not i.mnemonic.lower().startswith(("bic","bfi","bfx")))
    stores = sum(1 for i in window if i.mnemonic.lower().startswith(("str","st","mov","stos")))
    score = 0; ev = []
    if bitops >= 3: score += min(20, bitops*2); ev.append(f"bitwise ops: {bitops}")
    if branches >= 2: score += 8; ev.append(f"branches: {branches}")
    if stores >= 2:  score += 4; ev.append(f"stores: {stores}")
    return score, ev

def guess_function_start(insns, index, arch):
    lo = max(0, index - 220); cands = []
    for j in range(index, lo - 1, -1):
        m = insns[j].mnemonic.lower(); o = insns[j].op_str.lower()
        if arch == CS_ARCH_X86:
            if m == "push" and ("rbp" in o or "ebp" in o): cands.append(j)
            elif m in ("endbr64","endbr32"): cands.append(j)
        elif arch == CS_ARCH_ARM64:
            if m == "stp" and "x29" in o and "x30" in o: cands.append(j)
            elif m == "sub" and o.startswith("sp, sp,"): cands.append(j)
        elif arch == CS_ARCH_ARM:
            if m in ("push","stmdb") and ("lr" in o or "sp!" in o): cands.append(j)
        if j < index and (is_ret(insns[j]) or m in ("b","jmp","bx")): break
    return insns[cands[0]].address if cands else None

# FIX 3: stream disassembly, cap instructions, progress log.
def decode_analysis(img: ELFImage, window: int = 28):
    md, arch = make_disassembler(img)
    argregs = argument_registers(img, arch)
    candidates: List[Candidate] = []
    decoder_windows = []; total_insns = 0
    imported_python = {n: a for a, n in img.imports.items() if n.startswith("Py") or "python" in n.lower()}
    py_clue_strings = [(va, s.decode("utf-8","replace")) for va, s in img.strings
                       if any(c.lower() in s.lower() for c in PYTHON_CLUES)]

    for base, code, secname in img.executable:
        log(f"[*] disassembling {secname} @ 0x{base:x} ({len(code)} bytes)")
        insns = []
        try:
            for ins in md.disasm(code, base):
                insns.append(ins)
                if len(insns) >= MAX_INSTRUCTIONS_PER_SECTION:
                    log(f"    [warn] instruction cap reached at 0x{ins.address:x}")
                    break
        except Exception as e:
            log(f"    [warn] disasm error: {e!r}")
        total_insns += len(insns)
        log(f"    -> {len(insns)} instructions")
        if not insns: continue

        for i, insn in enumerate(insns):
            if not is_call(insn): continue
            lo = max(0, i - window); state = {}
            for prev in insns[lo:i]: update_state(prev, state, arch)
            av = [state.get(r) for r in argregs]
            start_value = av[1] if len(av) > 1 else None
            arg0 = av[0] if av else None
            target, kind = classify_call_target(insn, state, arch)
            sym = None
            if target is not None:
                sym = img.plt_targets.get(target) or img.relocations.get(target)
            score = 0; ev = []
            if sym in PYRUN_NAMES:
                score += PYRUN_NAMES[sym]; ev.append(f"target={sym}")
            elif sym and (sym.startswith("PyRun_") or sym.startswith("Py_Compile")):
                score += 70; ev.append(f"python API target={sym}")
            if is_python_start(start_value):
                score += 42; ev.append(f"start_mode={start_value}")
            elif start_value in (0,1,2,3):
                score += 4; ev.append(f"small enum arg1={start_value}")
            prev_str = img.preview_string(arg0) if arg0 is not None else None
            if prev_str:
                score += 15; ev.append("arg0 -> readable string")
                if any(k in prev_str.lower() for k in ("import ","def ","class ","exec","eval","python")):
                    score += 7; ev.append("arg0 looks like Python source")
            elif arg0 is not None and img.va_to_offset(arg0) is not None:
                score += 5; ev.append("arg0 points into ELF")
            nearby = insns[lo:i]
            if any((img.plt_targets.get(int(op.imm), "").startswith("Py") if immediate_value(x, op) is not None else False)
                   for x in nearby for op in get_ops(x)):
                score += 5; ev.append("nearby Python PLT reference")
            if imported_python: score += 2; ev.append(f"imports {len(imported_python)} Py APIs")
            ds, de = looks_like_decoder(insns, lo, i + 1)
            if ds: score += min(8, ds // 4); ev.extend(de[:2])
            if score >= 12:
                off = img.va_to_offset(insn.address)
                fn = guess_function_start(insns, i, arch)
                candidates.append(Candidate(
                    score=score, call_va=int(insn.address),
                    call_rva=int(img.va_to_rva(int(insn.address))),
                    call_file_offset=off, function_guess=fn,
                    function_rva_guess=img.va_to_rva(fn),
                    target_va=target, target_rva=img.va_to_rva(target),
                    target_symbol=sym, call_kind=kind,
                    start_argument=start_value,
                    start_argument_register=argregs[1] if len(argregs) > 1 else None,
                    arg0_pointer=arg0, arg0_preview=prev_str, evidence=ev))

        for st in range(0, max(1, len(insns) - 48), 24):
            sc, ev = looks_like_decoder(insns, st, min(len(insns), st + 72))
            if sc >= 18:
                decoder_windows.append({
                    "va": int(insns[st].address),
                    "file_offset": img.va_to_offset(int(insns[st].address)),
                    "score": sc, "section": secname, "evidence": ev})

    summary = {
        "architecture": str(img.machine), "bits": img.bits,
        "endianness": "little" if img.little else "big",
        "image_base": hex(img.image_base),
        "executable_ranges": [{"name": n, "va": hex(a), "size": len(d)} for a, d, n in img.executable],
        "instruction_count": total_insns,
        "python_related_imports": sorted(set(img.imports.values()).intersection(
            set(PYRUN_NAMES) | {n for n in img.imports.values() if n.startswith("Py")})),
        "python_clue_strings": [{"va": hex(a), "text": s[:180]} for a, s in py_clue_strings[:100]],
        "decoder_like_windows": sorted(decoder_windows, key=lambda x: x["score"], reverse=True)[:40],
        "relocation_count": len(img.relocations),
    }
    dedup = {}
    for c in candidates:
        if c.call_va not in dedup or c.score > dedup[c.call_va].score:
            dedup[c.call_va] = c
    return sorted(dedup.values(), key=lambda c: (-c.score, c.call_va)), summary

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data); n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in counts.values())

# FIX 4: cap total bytes scanned; cheap stride; bail out early.
def find_high_entropy_ranges(img: ELFImage, min_size=32, max_ranges=60):
    found = []; budget = MAX_ENTROPY_BYTES
    for seg in img.segments:
        data = seg.data
        if not data or budget <= 0: break
        take = min(len(data), budget); budget -= take
        step = 64
        for off in range(0, take - min_size + 1, step):
            chunk = data[off:off + 96]
            e = entropy(chunk)
            if e >= 7.1:
                found.append({"va": hex(seg.vaddr + off),
                              "file_offset": seg.offset + off,
                              "size_scanned": len(chunk),
                              "entropy_bits_per_byte": round(e, 3),
                              "note": "high entropy; may be ciphertext/compressed"})
    found.sort(key=lambda x: x["entropy_bits_per_byte"], reverse=True)
    res = []; used = []
    for it in found:
        if any(abs(it["file_offset"] - u) < 96 for u in used): continue
        res.append(it); used.append(it["file_offset"])
        if len(res) >= max_ranges: break
    return res

def print_report(img, candidates, summary, entropy_ranges, limit):
    print(f"\n[+] File: {img.path}")
    print(f"[+] ELF: {summary['bits']}-bit {summary['endianness']}, machine={summary['architecture']}")
    print(f"[+] Instructions: {summary['instruction_count']}")
    print(f"[+] Image base: {summary['image_base']}")
    print(f"[+] Relocations: {summary['relocation_count']}")
    py = summary["python_related_imports"]
    print("[+] Python imports: " + (", ".join(py) if py else "none"))
    clues = summary["python_clue_strings"]
    print(f"[+] Clue strings: {len(clues)}")
    for it in clues[:12]: print(f"    {it['va']}: {it['text'][:120]!r}")
    print("\n[+] Call-site candidates:")
    if not candidates: print("    (none)")
    for c in candidates[:limit]:
        print(f"\n    score={c.score} RVA=0x{c.call_rva:x} VA=0x{c.call_va:x} "
              f"off={hex(c.call_file_offset) if c.call_file_offset is not None else 'n/a'}")
        print(f"      fn_rva={hex(c.function_rva_guess) if c.function_rva_guess is not None else '?'} "
              f"tgt={c.target_symbol or '?'} kind={c.call_kind}")
        print(f"      arg1={c.start_argument} arg0={hex(c.arg0_pointer) if c.arg0_pointer is not None else '?'}")
        if c.arg0_preview: print(f"      arg0_text={c.arg0_preview[:140]!r}")
        for e in c.evidence: print(f"      - {e}")
    print("\n[+] Decoder-like windows:")
    for it in summary["decoder_like_windows"][:12]:
        print(f"    VA={it['va']} off={it['file_offset']} score={it['score']} sec={it['section']}")
    if not summary["decoder_like_windows"]: print("    (none)")
    print("\n[+] High-entropy ranges:")
    for it in entropy_ranges[:12]:
        print(f"    VA={it['va']} off={it['file_offset']} H={it['entropy_bits_per_byte']}")
    if not entropy_ranges: print("    (none)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("so")
    ap.add_argument("--window", type=int, default=28)
    ap.add_argument("--max-candidates", type=int, default=25)
    ap.add_argument("--json", dest="json_path")
    ap.add_argument("--entropy", action="store_true")
    args = ap.parse_args()
    if not os.path.isfile(args.so):
        ap.error(f"file not found: {args.so}")
    t0 = time.time()
    img = ELFImage(args.so)
    log(f"[*] ELF loaded in {time.time()-t0:.1f}s "
        f"({sum(len(s.data) for s in img.segments)/1e6:.1f} MB, {len(img.strings)} strings)")
    candidates, summary = decode_analysis(img, max(8, args.window))
    entropy_ranges = find_high_entropy_ranges(img) if args.entropy else []
    print_report(img, candidates, summary, entropy_ranges, args.max_candidates)
    if args.json_path:
        report = {"file": os.path.abspath(args.so), "summary": summary,
                  "candidates": [asdict(c) for c in candidates],
                  "high_entropy_ranges": entropy_ranges}
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report: {args.json_path}")
    img.close()
    log(f"[*] Done in {time.time()-t0:.1f}s")

if __name__ == "__main__":
    main()