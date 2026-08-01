#!/usr/bin/env python3
"""Run Ghidra headless over a native host binary and export its attack surface.

Stage 2 of the pipeline. Stage 1 (`native_host_hunt.py`) found the binary and
proved it belongs to a given extension; this turns it into something an agent
can read: decompiled C for every function that can reach an OS sink, the sink
call graph, and the string table with cross-references.

Managed binaries are NOT sent to Ghidra — .NET, Java, Electron and PyInstaller
all decompile to near-source with the right tool, and Ghidra would only produce
worse output for the CLR/JVM stub. `route` tells you which tool to use.

Usage:
    python3 scripts/ghidra_decompile.py route    <BINARY>
    python3 scripts/ghidra_decompile.py analyze  <BINARY> [--out DIR] [--timeout S]
    python3 scripts/ghidra_decompile.py sinks    <OUT_DIR>

Requires GHIDRA_INSTALL_DIR (the directory containing support/analyzeHeadless).
Nothing here executes the binary under analysis — Ghidra only ever reads it.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
GHIDRA_SCRIPTS = SCRIPT_DIR / "ghidra_scripts"


def magic(p: Path) -> bytes:
    with p.open("rb") as fh:
        return fh.read(64)


def route(binary: Path) -> dict:
    """Decide which decompiler this binary actually wants."""
    head = magic(binary)
    blob = binary.read_bytes()[:8_000_000]

    fmt, tool, why = "unknown", "ghidra", ""
    if head[:2] == b"MZ":
        fmt = "pe"
        if b"mscoree.dll" in blob or b"_CorExeMain" in blob or b"#~\x00" in blob:
            fmt, tool = "dotnet", "ilspycmd / dnSpy"
            why = "CLR image — Ghidra would only see the loader stub"
        elif b"PyInstaller" in blob or b"pyi-windows-manifest" in blob:
            fmt, tool = "pyinstaller", "pyinstxtractor + decompyle3"
        elif b"UPX!" in blob:
            fmt, tool = "pe-packed", "upx -d, then re-route"
        else:
            tool, why = "ghidra", "unmanaged PE"
    elif head[:4] == b"\x7fELF":
        fmt, tool, why = "elf", "ghidra", "unmanaged ELF"
    elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        fmt, tool, why = "macho", "ghidra", "unmanaged Mach-O"
    elif head[:2] == b"PK":
        fmt = "zip-like"
        if b"META-INF" in blob:
            fmt, tool = "jar", "cfr / procyon / jd-cli"
        elif b"app.asar" in blob or b"node_modules" in blob:
            fmt, tool = "electron", "asar extract"
        else:
            tool = "unzip, then re-route on the contents"
    elif head[:2] in (b"#!", b"@e") or binary.suffix.lower() in (".bat", ".cmd", ".sh"):
        fmt, tool = "script", "read it"
        why = "a stub — find the real executable it invokes and route that"

    if b"Go build ID" in blob:
        fmt, tool = "go", "ghidra + a Go symbol restorer"

    return {"binary": str(binary), "format": fmt, "tool": tool, "why": why,
            "ghidra_appropriate": tool.startswith("ghidra")}


def ghidra_home() -> Path:
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and (Path(env) / "support" / "analyzeHeadless").exists():
        return Path(env)
    found = shutil.which("analyzeHeadless")
    if found:
        return Path(found).resolve().parent.parent
    sys.exit("GHIDRA_INSTALL_DIR is not set and analyzeHeadless is not on PATH")


def analyze(binary: Path, out: Path, timeout: int) -> int:
    r = route(binary)
    if not r["ghidra_appropriate"]:
        print(f"REFUSING: {binary.name} is {r['format']} — use {r['tool']}.")
        print(f"  {r['why']}")
        print("  Ghidra on a managed binary produces worse output than the right tool.")
        return 2

    out.mkdir(parents=True, exist_ok=True)
    headless = ghidra_home() / "support" / "analyzeHeadless"

    with tempfile.TemporaryDirectory(prefix="ghidra-proj-") as proj:
        cmd = [
            str(headless), proj, "nhh",
            "-import", str(binary),
            "-scriptPath", str(GHIDRA_SCRIPTS),
            "-postScript", "ExportNativeHostSurface.java", str(out),
            "-deleteProject",
            # analysis only ever reads the file; nothing is executed
            "-noanalysis" if os.environ.get("NHH_NO_ANALYSIS") else "-analysisTimeoutPerFile",
        ]
        if not os.environ.get("NHH_NO_ANALYSIS"):
            cmd.append(str(timeout))

        print(f"$ {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 600)
        tail = (proc.stdout or "")[-2500:]
        print(tail)
        if proc.returncode != 0:
            print((proc.stderr or "")[-1500:], file=sys.stderr)
            return proc.returncode

    summary = out / "summary.json"
    if summary.exists():
        s = json.loads(summary.read_text())
        print(f"\n{s.get('functions_decompiled')} functions decompiled of "
              f"{s.get('functions_total')}; {s.get('sink_symbols_found')} sink symbols; "
              f"{len(s.get('entry_candidates', []))} entry candidates")
        print(f"decomp C in {out / 'decomp'}")
    return 0


def sinks(out: Path) -> int:
    """Rank what to read first: shallowest path to the most dangerous sink."""
    f = out / "sinks.json"
    if not f.exists():
        sys.exit(f"no sinks.json in {out} — run analyze first")
    data = json.loads(f.read_text())
    rows = []
    for sink, callers in data.get("sinks", {}).items():
        for c in callers:
            rows.append((c.get("depth_to_sink", 99), sink, c["function"], c["entry"]))
    if not rows:
        print("no sink imports found — either it is a pure-compute host, or the "
              "sinks are resolved dynamically (check GetProcAddress usage)")
        return 0
    rows.sort()
    print(f"{'depth':>5}  {'sink':<24} {'caller':<40} entry")
    for depth, sink, fn, entry in rows[:60]:
        print(f"{depth:>5}  {sink:<24} {fn[:40]:<40} {entry}")
    print("\nRead the shallowest first — depth is calls between this function "
          "and the sink, not distance from the message loop.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("route", help="which decompiler does this binary want?")
    p.add_argument("binary", type=Path)

    p = sub.add_parser("analyze", help="run Ghidra headless + export the surface")
    p.add_argument("binary", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--timeout", type=int, default=1800)

    p = sub.add_parser("sinks", help="rank sink call sites from a finished run")
    p.add_argument("out_dir", type=Path)

    args = ap.parse_args()
    if args.cmd == "route":
        print(json.dumps(route(args.binary), indent=2))
        return 0
    if args.cmd == "analyze":
        out = args.out or (args.binary.parent / f"{args.binary.name}.ghidra")
        return analyze(args.binary, out, args.timeout)
    return sinks(args.out_dir)


if __name__ == "__main__":
    sys.exit(main())
