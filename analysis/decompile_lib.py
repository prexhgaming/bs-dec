#!/usr/bin/env python3
"""Disassemble a whole native library with capstone and write it out for local study.

The scanner (:mod:`analysis.scan_pyrun`) answers *does this library contain
CPython*; this tool answers *what does the code actually do*. It walks every
function candidate in an ELF (a symbol table if one survived, otherwise
prologue heuristics), disassembles each function with capstone, and streams the
result into gzipped JSONL parts so a 40 MB ``.text`` becomes an artifact that
can be downloaded and searched offline.

    # straight from a downloaded APK (CRC-checked member read, no ranged pulls)
    python3 analysis/decompile_lib.py downloads/app.apk \\
        --abi armeabi-v7a --out decompiled

    # from an extracted .so
    python3 analysis/decompile_lib.py libGame.so --out decompiled --text

Output (``--out`` directory):

``part-0001.jsonl.gz`` ... gzipped JSON Lines, one object per function:
    ``{"a": "0x1f2c4", "n": 412, "m": "thumb", "h": "<sha256>", "i": [...]}``
    where each instruction is ``{"a": "0x1f2c4", "b": "0f4c", "t": "ldr r4, [pc, #60]"}``
``listing.txt``       optional human-readable listing (``--text``)
``manifest.json``     input hashes, engine versions, counts, coverage, part sizes

Every record keeps the raw instruction bytes, so a locally rebuilt listing can be
diffed against the same library from another build (or the 64-bit sibling)
without trusting this script's formatting.

Exit codes: 0 decompiled, 2 the input/member could not be read, 3 capstone is
missing or the architecture is unsupported.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

try:
    from . import scan_pyrun as sp
except ImportError:  # run as a plain script
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import scan_pyrun as sp  # type: ignore

DEFAULT_MAX_INSTRUCTIONS = 0
DEFAULT_SPLIT_MB = 48
APK_SUFFIXES = (".apk", ".xapk", ".apks", ".apkm")


# --------------------------------------------------------------------------- ELF


@dataclass
class Target:
    """A loaded library plus where it came from."""

    data: bytes
    elf: sp.Elf
    label: str
    sha256: str

    @property
    def bitness(self) -> int:
        return self.elf.bits


def load_target(path: Path, *, abi: str = "", member: str = "") -> Target:
    """Read a raw .so, or pull one member out of an APK/XAPK with zipfile."""
    if not path.exists():
        raise SystemExit(f"no such file: {path}")
    if path.suffix.lower() in APK_SUFFIXES:
        with zipfile.ZipFile(path) as archive:
            name = pick_member(archive.namelist(), abi, member)
            if not name:
                raise SystemExit(
                    f"{path.name} has no lib for ABI '{abi or 'any'}'; "
                    f"try one of: {', '.join(sorted(guess_abis(archive.namelist()))) or 'none'}"
                )
            # zipfile verifies the CRC on read, so a damaged member cannot slip through
            data = archive.read(name)
            label = f"{path.name}:{name}"
    else:
        data = path.read_bytes()
        label = path.name
    if data[:4] != b"\x7fELF":
        raise SystemExit(f"{label} is not an ELF file (magic {data[:4]!r})")
    return Target(data=data, elf=sp.parse_elf(data), label=label, sha256=hashlib.sha256(data).hexdigest())


def guess_abis(names: Iterable[str]) -> List[str]:
    found = set()
    for name in names:
        if name.startswith("lib/") and name.count("/") >= 2:
            found.add(name.split("/")[1])
    return sorted(found)


def pick_member(names: Sequence[str], abi: str, wanted: str = "") -> Optional[str]:
    """Pick ``lib/<abi>/<wanted>`` from an archive; ``wanted`` may be bare or full."""
    candidates = [n for n in names if n.lower().endswith(".so")]
    if not candidates:
        return None
    if wanted:
        target = wanted.replace("\\", "/").lower()
        base = target.rsplit("/", 1)[-1]
        for name in candidates:  # exact member path first
            if name.replace("\\", "/").lower() == target:
                return name
        for name in candidates:  # then the same file name under any ABI directory
            if name.replace("\\", "/").lower().rsplit("/", 1)[-1] == base:
                if not abi or f"/{abi.lower()}/" in name.lower():
                    return name
        for name in candidates:  # finally accept the bare name anywhere
            if name.replace("\\", "/").lower().rsplit("/", 1)[-1] == base:
                return name
        return None
    if abi:
        wanted_abi = abi.lower()
        for name in candidates:
            if name.lower().startswith(f"lib/{wanted_abi}/"):
                return name
        return None
    for name in candidates:
        if name.lower().startswith("lib/"):
            return name
    return candidates[0]


def machine_name(elf: sp.Elf) -> str:
    """The ELF machine as a name; ``Elf.machine`` is the numeric e_machine."""
    return getattr(elf, "machine_name", None) or sp.MACHINES.get(elf.machine, str(elf.machine))


# --------------------------------------------------------------- disassembly


def capstone_module():
    try:
        import capstone  # type: ignore
    except ImportError:  # pragma: no cover - depends on the runner
        print(
            "capstone is not installed; install it with 'pip install capstone' "
            "(CI does this in decompile-lib.yml)",
            file=sys.stderr,
        )
        raise SystemExit(3)
    return capstone


def build_disassembler(capstone, machine, *, thumb: bool):
    """Return a capstone ``Cs`` for the ELF machine, or raise SystemExit(3)."""
    if not isinstance(machine, str):  # tolerate a raw e_machine number
        machine = sp.MACHINES.get(machine, str(machine))
    if machine == "ARM":
        mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM
        return capstone.Cs(capstone.CS_ARCH_ARM, mode | capstone.CS_MODE_LITTLE_ENDIAN)
    if machine == "AArch64":
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    if machine == "x86":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if machine == "x86-64":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    print(f"capstone support for {machine} is not wired up", file=sys.stderr)
    raise SystemExit(3)


def section_of(elf: sp.Elf, addr: int) -> Optional[sp.Section]:
    for section in elf.exec_sections():
        if section.contains_addr(addr):
            return section
    return None


def function_windows(
    elf: sp.Elf,
    starts: Sequence[int],
    *,
    max_bytes: int = 1 << 20,
) -> Iterator[Tuple[int, int, int]]:
    """Yield ``(address, offset, size)`` for each candidate, clipped to its section."""
    for index, addr in enumerate(starts):
        section = section_of(elf, addr)
        if section is None:
            continue
        section_end = section.addr + section.size
        end = section_end
        if index + 1 < len(starts):
            following = starts[index + 1]
            if addr < following < end:
                end = following
        size = min(end - addr, max_bytes)
        offset = elf.vaddr_to_offset(addr)
        if offset is None or size <= 0:
            continue
        yield addr, offset, size


def choose_mode(capstone, elf: sp.Elf, addr: int, offset: int, forced: str) -> Tuple[bool, str]:
    """Pick ARM vs Thumb for a 32-bit function; ``forced`` is auto/thumb/arm."""
    machine = machine_name(elf)
    if machine != "ARM":
        return False, "arm" if elf.bits == 32 else "a64"
    if forced == "thumb":
        return True, "thumb"
    if forced == "arm":
        return False, "arm"
    # auto: Thumb-2 is the norm on Android, but verify the first instruction decodes
    probe = elf.data[offset : offset + 16]
    for thumb in (True, False):
        cs = build_disassembler(capstone, machine, thumb=thumb)
        decoded = list(cs.disasm(probe, addr))
        if decoded:
            return thumb, "thumb" if thumb else "arm"
    return True, "thumb"


def disassemble_function(
    capstone,
    elf: sp.Elf,
    addr: int,
    offset: int,
    size: int,
    *,
    forced_mode: str,
    max_instructions: int,
) -> Tuple[Dict[str, object], List[str]]:
    """Disassemble one function window into a record plus printable lines."""
    thumb, mode = choose_mode(capstone, elf, addr, offset, forced_mode)
    cs = build_disassembler(capstone, machine_name(elf), thumb=thumb)
    cs.detail = False
    code = elf.data[offset : offset + size]
    instructions: List[Dict[str, str]] = []
    lines: List[str] = []
    truncated = False
    for insn in cs.disasm(code, addr):
        if max_instructions and len(instructions) >= max_instructions:
            truncated = True
            break
        text = f"{insn.mnemonic} {insn.op_str}".strip()
        instructions.append({"a": f"0x{insn.address:x}", "b": insn.bytes.hex(), "t": text})
        lines.append(f"  {insn.address:08x}  {insn.bytes.hex():<16}  {text}")
    record: Dict[str, object] = {
        "a": f"0x{addr:x}",
        "s": size,
        "n": len(instructions),
        "m": mode,
        "h": hashlib.sha256(code[:96]).hexdigest(),
        "i": instructions,
    }
    if truncated:
        record["truncated"] = True
    return record, lines


# ------------------------------------------------------------------- writing


class PartWriter:
    """Rolls gzipped JSONL parts so one artifact stays a sane size."""

    def __init__(self, out_dir: Path, *, split_bytes: int, prefix: str = "part") -> None:
        self.out_dir = out_dir
        self.split_bytes = max(split_bytes, 1 << 20)
        self.prefix = prefix
        self.parts: List[Dict[str, object]] = []
        self._handle: Optional[gzip.GzipFile] = None
        self._path: Optional[Path] = None
        self._uncompressed = 0
        self._records = 0

    def _open_next(self) -> None:
        self.close_part()
        index = len(self.parts) + 1
        self._path = self.out_dir / f"{self.prefix}-{index:04d}.jsonl.gz"
        self._handle = gzip.open(self._path, "wb", compresslevel=6)
        self._uncompressed = 0
        self._records = 0

    def write(self, record: Dict[str, object]) -> None:
        if self._handle is None:
            self._open_next()
        payload = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        assert self._handle is not None
        self._handle.write(payload)
        self._uncompressed += len(payload)
        self._records += 1
        if self._uncompressed >= self.split_bytes:
            self.close_part()

    def close_part(self) -> None:
        if self._handle is None or self._path is None:
            return
        self._handle.close()
        self.parts.append(
            {
                "name": self._path.name,
                "records": self._records,
                "uncompressed_bytes": self._uncompressed,
                "compressed_bytes": self._path.stat().st_size,
            }
        )
        self._handle = None
        self._path = None

    def close(self) -> List[Dict[str, object]]:
        self.close_part()
        return self.parts


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


# ------------------------------------------------------------------------ CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decompile_lib.py",
        description="Disassemble a whole native library with capstone into gzipped JSONL parts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 analysis/decompile_lib.py downloads/app.apk --abi armeabi-v7a --out decompiled\n"
            "  python3 analysis/decompile_lib.py libGame.so --out decompiled --text --max-functions 500\n"
        ),
    )
    parser.add_argument("target", type=Path, help="a .so, or an .apk/.xapk to read the member from")
    parser.add_argument("--abi", default="", help="ABI to pull from an archive (lib/<abi>/*.so)")
    parser.add_argument("--member", default="", help="exact member name inside the archive")
    parser.add_argument("--out", type=Path, default=Path("decompiled"), help="output directory")
    parser.add_argument(
        "--thumb",
        choices=("auto", "thumb", "arm"),
        default="auto",
        help="32-bit ARM instruction set (auto probes each function)",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="stop after N functions (0 = every candidate)",
    )
    parser.add_argument(
        "--max-instructions",
        type=int,
        default=DEFAULT_MAX_INSTRUCTIONS,
        help="per-function instruction cap (0 = no cap)",
    )
    parser.add_argument(
        "--split-mb",
        type=int,
        default=DEFAULT_SPLIT_MB,
        help=f"start a new part after this many uncompressed MiB (default {DEFAULT_SPLIT_MB})",
    )
    parser.add_argument("--text", action="store_true", help="also write a human-readable listing.txt")
    parser.add_argument("--manifest", type=Path, default=None, help="manifest path (default <out>/manifest.json)")
    parser.add_argument("--quiet", action="store_true", help="no progress on stderr")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    target = load_target(args.target, abi=args.abi, member=args.member)
    capstone = capstone_module()

    elf = target.elf
    log(
        f"{target.label}: {machine_name(elf)} {elf.bits}-bit, "
        f"{'symbols present' if elf.has_symtab else 'stripped'}, {len(target.data)} bytes"
    )

    starts = sp.enumerate_functions(elf)
    if not starts:
        log("no function candidates found; nothing to disassemble")
        return 0
    if args.max_functions:
        starts = starts[: args.max_functions]
    log(f"function candidates: {len(starts)}")

    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    writer = PartWriter(out_dir, split_bytes=args.split_mb * (1 << 20))
    text_handle = open(out_dir / "listing.txt", "w", encoding="utf-8") if args.text else None

    started = time.time()
    total_instructions = 0
    truncated = 0
    written = 0
    last_report = 0.0
    for addr, offset, size in function_windows(elf, starts):
        record, lines = disassemble_function(
            capstone,
            elf,
            addr,
            offset,
            size,
            forced_mode=args.thumb,
            max_instructions=args.max_instructions,
        )
        if not record["n"]:
            continue
        writer.write(record)
        written += 1
        total_instructions += int(record["n"])
        if record.get("truncated"):
            truncated += 1
        if text_handle is not None:
            text_handle.write(
                f"\n; {record['a']} size={record['s']} mode={record['m']} "
                f"insns={record['n']} sha256={str(record['h'])[:16]}\n"
            )
            text_handle.write("\n".join(lines) + "\n")
        now = time.time()
        if not args.quiet and now - last_report > 5:
            rate = written / max(now - started, 1e-6)
            log(f"  {written}/{len(starts)} functions, {total_instructions} instructions, {rate:.0f} fn/s")
            last_report = now

    parts = writer.close()
    if text_handle is not None:
        text_handle.close()

    elapsed = time.time() - started
    manifest = {
        "tool": "analysis/decompile_lib.py",
        "engine": "capstone",
        "capstone": getattr(capstone, "__version__", "unknown"),
        "input": {
            "label": target.label,
            "path": str(args.target),
            "abi": args.abi or None,
            "sha256": target.sha256,
            "bytes": len(target.data),
        },
        "elf": {
            "machine": elf.machine,
            "bits": elf.bits,
            "stripped": not elf.has_symtab,
            "sections": len(elf.sections),
            "exec_sections": [s.name for s in elf.exec_sections()],
        },
        "options": {
            "thumb": args.thumb,
            "max_functions": args.max_functions or None,
            "max_instructions": args.max_instructions,
            "split_mb": args.split_mb,
        },
        "result": {
            "function_candidates": len(starts),
            "functions_written": written,
            "instructions": total_instructions,
            "truncated_functions": truncated,
            "parts": parts,
            "uncompressed_bytes": sum(int(p["uncompressed_bytes"]) for p in parts),
            "compressed_bytes": sum(int(p["compressed_bytes"]) for p in parts),
            "seconds": round(elapsed, 2),
        },
        "format": {
            "record": {"a": "address", "s": "size", "n": "instruction count", "m": "mode", "h": "sha256 of first 96 bytes", "i": "instructions"},
            "instruction": {"a": "address", "b": "raw bytes hex", "t": "mnemonic + operands"},
        },
    }
    manifest_path = args.manifest or (out_dir / "manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    log(
        f"done: {written} functions, {total_instructions} instructions, "
        f"{manifest['result']['compressed_bytes'] / (1 << 20):.1f} MiB compressed "
        f"in {len(parts)} part(s), {elapsed:.1f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
