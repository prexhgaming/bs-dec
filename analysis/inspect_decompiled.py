#!/usr/bin/env python3
"""Search the decompiled parts produced by ``analysis/decompile_lib.py``.

The CI job uploads gzipped JSONL parts; download the artifact, unzip it, and use
this to find things without a disassembler to hand:

    # what is at (or contains) an address
    python3 analysis/inspect_decompiled.py decompiled --address 0x1f2c4

    # every function whose disassembly contains a pattern (mnemonic or operand)
    python3 analysis/inspect_decompiled.py decompiled --grep "PyRun" --limit 20

    # which functions call a given target address
    python3 analysis/inspect_decompiled.py decompiled --calls 0x4a120

    # biggest functions, or a flat listing of one function
    python3 analysis/inspect_decompiled.py decompiled --largest 15
    python3 analysis/inspect_decompiled.py decompiled --address 0x1f2c4 --listing

Nothing here needs capstone: it only reads the JSONL that CI already wrote.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence


@dataclass
class Function:
    address: int
    size: int
    mode: str
    digest: str
    instructions: List[Dict[str, str]]
    truncated: bool = False

    @property
    def text(self) -> List[str]:
        return [f"{int(i['a'], 16):08x}  {i['b']:<16}  {i['t']}" for i in self.instructions]


def part_files(directory: Path) -> List[Path]:
    parts = sorted(directory.glob("part-*.jsonl.gz")) + sorted(directory.glob("part-*.jsonl"))
    if not parts:
        raise SystemExit(f"no part-*.jsonl.gz files in {directory}")
    return parts


def read_functions(path: Path) -> Iterator[Function]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as handle:  # type: ignore[operator]
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            yield Function(
                address=int(record["a"], 16),
                size=int(record.get("s", 0)),
                mode=str(record.get("m", "?")),
                digest=str(record.get("h", "")),
                instructions=list(record.get("i", [])),
                truncated=bool(record.get("truncated")),
            )


def load_manifest(directory: Path) -> Dict[str, object]:
    path = directory / "manifest.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def callees(function: Function) -> List[int]:
    """Direct branch targets (bl/b/b.w/cbz...), resolved from the operand text."""
    targets: List[int] = []
    for insn in function.instructions:
        text = insn["t"]
        if not text.startswith(("bl ", "b ", "bx ", "blx ", "cbz ", "cbnz ", "tbnz ", "tbz ")):
            continue
        match = re.search(r"#?(0x[0-9a-fA-F]+)", text)
        if match:
            targets.append(int(match.group(1), 16))
    return targets


def find(functions: Iterable[Function], address: int) -> Optional[Function]:
    for function in functions:
        if function.address == address:
            return function
        if function.address < address < function.address + function.size:
            return function
    return None


def print_function(function: Function, *, listing: bool, limit: int = 60) -> None:
    span = f"0x{function.address:x}-0x{function.address + function.size:x}"
    print(
        f"function 0x{function.address:x}  size={function.size}  mode={function.mode}  "
        f"insns={len(function.instructions)}  sha256={function.digest[:16]}{'  (truncated)' if function.truncated else ''}"
    )
    print(f"span     {span}")
    if not listing:
        for insn in function.instructions[:limit]:
            print(f"  {int(insn['a'], 16):08x}  {insn['b']:<16}  {insn['t']}")
        if len(function.instructions) > limit:
            print(f"  ... {len(function.instructions) - limit} more (use --listing for all)")
    else:
        for insn in function.instructions:
            print(f"  {int(insn['a'], 16):08x}  {insn['b']:<16}  {insn['t']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inspect_decompiled.py",
        description="Query the JSONL parts written by analysis/decompile_lib.py.",
    )
    parser.add_argument("directory", type=Path, help="the artifact directory (contains part-*.jsonl.gz)")
    parser.add_argument("--address", default="", help="show the function at/containing this hex address")
    parser.add_argument("--listing", action="store_true", help="print every instruction of the match")
    parser.add_argument("--grep", default="", help="regex over the instruction text")
    parser.add_argument("--calls", default="", help="show functions branching to this hex address")
    parser.add_argument("--largest", type=int, default=0, help="show the N largest functions")
    parser.add_argument("--limit", type=int, default=20, help="how many matches to show (default 20)")
    parser.add_argument("--json", action="store_true", help="machine-readable output for --grep/--calls")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    directory: Path = args.directory
    manifest = load_manifest(directory)
    if manifest:
        result = manifest.get("result", {})
        elf = manifest.get("elf", {})
        print(
            f"{manifest.get('input', {}).get('label', '?')}: "
            f"{elf.get('machine', '?')} {elf.get('bits', '?')}-bit, "
            f"{result.get('functions_written', '?')} functions, "
            f"{result.get('instructions', '?')} instructions"
        )
    parts = part_files(directory)

    def stream() -> Iterator[Function]:
        for part in parts:
            yield from read_functions(part)

    did_something = False

    if args.address:
        did_something = True
        wanted = int(args.address, 0)
        function = find(stream(), wanted)
        if function is None:
            print(f"no function contains 0x{wanted:x}", file=sys.stderr)
            return 1
        print_function(function, listing=args.listing)

    if args.grep:
        did_something = True
        pattern = re.compile(args.grep, re.I)
        hits = 0
        for function in stream():
            matching = [i for i in function.instructions if pattern.search(i["t"])]
            if not matching:
                continue
            hits += 1
            if hits > args.limit:
                break
            if args.json:
                print(json.dumps({"address": f"0x{function.address:x}", "matches": matching}))
            else:
                print(f"\nfunction 0x{function.address:x}  ({len(matching)} match(es))")
                for insn in matching[:8]:
                    print(f"  {int(insn['a'], 16):08x}  {insn['b']:<16}  {insn['t']}")
                if len(matching) > 8:
                    print(f"  ... {len(matching) - 8} more in this function")
        if not args.json:
            print(f"\n{hits} function(s) matched {args.grep!r}")
        if not hits:
            return 1

    if args.calls:
        did_something = True
        target = int(args.calls, 0)
        found = [f for f in stream() if target in callees(f)]
        for function in found[: args.limit]:
            if args.json:
                print(json.dumps({"address": f"0x{function.address:x}", "callers_of": f"0x{target:x}"}))
            else:
                print(f"0x{function.address:x}  size={function.size}  mode={function.mode}")
        if not args.json:
            print(f"\n{len(found)} function(s) branch to 0x{target:x}")
        if not found:
            return 1

    if args.largest:
        did_something = True
        everything = list(stream())
        everything.sort(key=lambda f: f.size, reverse=True)
        for function in everything[: args.largest]:
            print(
                f"0x{function.address:x}  size={function.size:<8} insns={len(function.instructions):<6} "
                f"mode={function.mode}"
            )

    if not did_something:
        print(f"{len(parts)} part(s):")
        for part in parts:
            print(f"  {part.name}  {part.stat().st_size / (1 << 20):.1f} MiB")
        print("\npick an action: --address, --grep, --calls or --largest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
