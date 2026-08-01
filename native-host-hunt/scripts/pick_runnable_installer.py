#!/usr/bin/env python3
"""Pick the one runnable Windows installer per extension and copy it out.

The hunt tree keeps everything: vendor zips, nested cabs, per-platform builds.
That is right for research and wrong for a Desktop — an analyst wants exactly
one file per folder they can double-click. This picks it.

Preference order:
  1. a .msi anywhere shallow in the tree (MSI = the real Windows installer)
  2. a self-extracting / NSIS / Inno .exe whose name looks like a setup
  3. install.bat, when the vendor genuinely ships no compiled installer
     (some vendors' entire Windows distribution is a zip of batch + JS)

Usage:
    python3 scripts/pick_runnable_installer.py --out <scratch>/stage/run
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

HUNT_ROOT = Path(os.environ.get("NATIVE_HOST_ROOT", "<quarantine-root>"))
# "installer"/"setup" in the filename is decisive; the rest are weak hints that
# also match component binaries (Foo-Service.exe, foo_plugin.exe).
STRONG = ("installer", "setup", "install")
SETUPISH = ("client", "plugin", "host", "signtool", "tool", "sign",
            "opener", "connector", "activator", "launcher")
SKIP = ("uninstall", "unins", "spuninst", "vcredist", "dotnet", "redist",
        "msvc", "kb9", "windowsxp", "windowsserver", "rgb9rast",
        # node.exe is a runtime some installers download, not an installer
        "node.exe")
# An installer is a .msi or a .exe. .ocx/.dll/.sys are components, and .doc/.xls
# share OLE compound magic with .msi — magic bytes alone happily pick a Word
# document, so the suffix has to agree.
ALLOWED_SUFFIX = (".msi", ".exe")
DOC_SUFFIX = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".vsd", ".msg")

# Files a hunt downloaded specifically to DISPROVE, keyed by extension id.
# A hunt often fetches a plausible-but-wrong installer to check whether it
# carries the host (e.g. a vendor's flagship desktop suite, when the host in
# fact ships only in a small standalone add-on). Those must never win the pick
# on size alone, so list them here once disproved:
#   DISPROVEN = {"<ext_id>": ("WrongInstallerName",)}
DISPROVEN: dict[str, tuple[str, ...]] = {}


def magic(p: Path) -> str:
    try:
        with p.open("rb") as fh:
            b = fh.read(8)
    except OSError:
        return ""
    if b[:2] == b"MZ":
        return "exe"
    if b[:4] == b"\xd0\xcf\x11\xe0":
        # OLE compound: MSI, but also .doc/.xls. Trust it only for .msi.
        # Extensionless downloads keep the server's bytes but lose the name;
        # an OLE file arriving that way is an MSI, not somebody's Word doc.
        # A version-numbered download like `win-chrome-x64-1.3.21` parses as
        # suffix ".21", so test against real document types instead of
        # whitelisting ".msi": OLE that isn't an Office file is an installer.
        return "ole-doc" if p.suffix.lower() in DOC_SUFFIX else "msi"
    return ""


def score(p: Path, proven: set | None = None) -> tuple:
    """Lower is better."""
    name = p.name.lower()
    kind = magic(p)
    is_msi = kind == "msi" or p.suffix.lower() == ".msi"
    strong = any(s in name for s in STRONG)
    setupish = any(s in name for s in SETUPISH)
    # MSI outranks everything: a vendor's .msi is the installer even when some
    # bundled helper is called SetupUtility.exe.
    return (
        0 if (proven and p in proven) else 1,   # provably yielded the host binary
        0 if is_msi else 1,
        0 if strong else 1,           # then a name that says "installer"
        0 if setupish else 1,         # a name that says "setup" beats one that doesn't
        len(p.parts),                 # shallower beats deeper
        -p.stat().st_size,            # bigger beats smaller (full installer, not stub)
    )


def proven_installers(state: dict) -> set[Path]:
    """Installers whose own unpack tree yielded a linked host binary.

    Without this a hunt that downloaded a candidate to *disprove* it can still
    win the pick on size alone — a vendor's 240 MB flagship suite installer was
    fetched purely to show it does NOT carry the host, then got shipped as the
    installer because it was the biggest MSI present. If unpacking a file never produced a host binary, it is not the
    installer, however big and however official the name looks.
    """
    linked = [Path(b["path"]) for b in state.get("link", {}).get("binaries", [])]
    linked += [Path(t["path"]) for t in (state.get("triage") or [])]
    if not linked:
        return set()
    out: set[Path] = set()
    for r in state.get("unpacked", {}).get("results", []):
        dest = r.get("dest")
        if not (r.get("ok") and dest):
            continue
        if any(str(b).startswith(dest) for b in linked):
            src = Path(r["src"])
            # Walk back to the top-level download this nested archive came from.
            out.add(src)
            parent = r.get("parent")
            while parent:
                out.add(Path(parent))
                parent = next((x.get("parent") for x in
                               state.get("unpacked", {}).get("results", [])
                               if x.get("src") == parent), None)
    return out


def candidates(ext_dir: Path, proven: set | None = None) -> list[Path]:
    out = []
    for p in ext_dir.rglob("*"):
        if not p.is_file():
            continue
        try:
            if p.stat().st_size < 64 * 1024:
                continue
        except OSError:
            continue
        name = p.name.lower()
        if any(s in name for s in SKIP):
            continue
        if len(p.relative_to(ext_dir).parts) > 6:
            continue
        suf = p.suffix.lower()
        # Trust content over filename: downloads land with whatever the URL
        # basename was (`win-chrome-x64-1.3.21` -> suffix ".21"). magic()
        # already rules out Office documents.
        if suf in ALLOWED_SUFFIX or magic(p) in ("exe", "msi"):
            out.append(p)
    return sorted(out, key=lambda q: score(q, proven))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--inherit", help="JSON {target: source} for shared hosts")
    args = ap.parse_args()

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    inherit = json.loads(Path(args.inherit).read_text()) if args.inherit else {}
    picked: dict[str, Path] = {}

    for hj in sorted(HUNT_ROOT.glob("*/hunt.json")):
        ext_id = hj.parent.name
        state = json.loads(hj.read_text())
        if not (state.get("link", {}).get("binaries") or state.get("triage")):
            continue
        cands = [c for c in candidates(hj.parent, proven_installers(state))
                 if not any(bad in c.name for bad in DISPROVEN.get(ext_id, ()))]
        if not cands:
            print(f"{ext_id[:16]:<17} SKIP - no installer acquired")
            continue
        picked[ext_id] = cands[0]

    # Shared hosts inherit their source's installer.
    for target, source in inherit.items():
        if source in picked:
            picked[target] = picked[source]

    # Vendors that ship no compiled installer at all: install.bat IS the installer.
    addon_bat = Path(os.environ.get("SCRIPT_INSTALLER_FALLBACK", "/nonexistent"))
    for target, source in inherit.items():
        if target not in picked and addon_bat.exists():
            picked[target] = addon_bat

    for ext_id, src in sorted(picked.items()):
        d = out / ext_id
        d.mkdir(parents=True, exist_ok=True)
        name = src.name
        if not Path(name).suffix:
            name += "." + (magic(src) or "bin")
        dst = d / f"INSTALLER_{name}"
        shutil.copy2(src, dst)
        print(f"{ext_id[:16]:<17} {dst.name[:52]:<53} {src.stat().st_size/1e6:8.1f} MB")

    print(f"\n{len(picked)} installers picked -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
