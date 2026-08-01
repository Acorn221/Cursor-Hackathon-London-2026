#!/usr/bin/env python3
"""Native-host hunt: extension ID in, native host binary out.

The deterministic half of the native-messaging RCE pipeline. It does the
plumbing an LLM shouldn't be doing by hand — resolving the extension on disk,
pulling the native host names out of the JS, downloading and unpacking the
vendor installer, and proving the link between the two — and leaves the actual
judgement (which host matters, where the installer lives, is this reachable
from a web page) to the agents in `.claude/workflows/native-host-hunt.js`.

Funnel:

    discover   ext id  -> host names + call sites + acquisition leads   (local)
    fetch      url     -> installer in quarantine                        (net)
    unpack     ---     -> recursive extract, never execute               (local)
    link       ---     -> NM manifest whose allowed_origins == this ext  (local)
    triage     ---     -> binary format / imports / opcode correlation   (local)
    report     ---     -> REPORT.md research packet

State accumulates in `<root>/<ext_id>/hunt.json`; every stage is re-runnable
and only overwrites its own section.

Usage:
    python3 scripts/native_host_hunt.py discover <EXT_ID> [--version V] [--json]
    python3 scripts/native_host_hunt.py fetch    <EXT_ID> --url URL [--label NAME]
    python3 scripts/native_host_hunt.py unpack   <EXT_ID> [--max-depth 4]
    python3 scripts/native_host_hunt.py link     <EXT_ID>
    python3 scripts/native_host_hunt.py triage   <EXT_ID>
    python3 scripts/native_host_hunt.py report   <EXT_ID>
    python3 scripts/native_host_hunt.py status   <EXT_ID>

NOTHING here executes a downloaded installer. Unpack only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

try:
    # In-house layout resolver, if you have one.
    import paths  # noqa: E402
except ImportError:
    # Standalone fallback: extensions live at
    #   $EXTENSION_ROOT/{ext_id}/{version}/extension/{extracted,deobfuscated}/
    class _Paths:
        ROOT = Path(os.environ.get("EXTENSION_ROOT", "./extensions"))

        def ext_root(self, ext_id):
            return self.ROOT / ext_id

        def version_dir(self, ext_id, version):
            return self.ROOT / ext_id / version

        def extension_dir(self, ext_id, version):
            return self.version_dir(ext_id, version) / "extension"

        def extracted_dir(self, ext_id, version):
            return self.extension_dir(ext_id, version) / "extracted"

        def deobfuscated_dir(self, ext_id, version):
            return self.extension_dir(ext_id, version) / "deobfuscated"

        def list_versions(self, ext_id):
            d = self.ext_root(ext_id)
            return sorted(p.name for p in d.iterdir()) if d.is_dir() else []

        def resolve_version(self, ext_id, version=None, conn=None):
            if version:
                return version
            vs = self.list_versions(ext_id)
            return vs[-1] if vs else None

    paths = _Paths()  # noqa: N816

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Quarantine root for everything downloaded. Installers are large; point this
# at a disk with room. Never inside your repo.
def _default_root() -> Path:
    return Path(os.environ.get("NATIVE_HOST_ROOT", PROJECT_ROOT / "native-hosts"))


ROOT = _default_root()

SCAN_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".json", ".html", ".htm"}
SKIP_DIRS = {"node_modules", "_metadata", ".git", "__pycache__"}

# chrome.runtime.connectNative(...) / sendNativeMessage(...) — grab the first arg.
NATIVE_CALL_RE = re.compile(
    r"\b(connectNative|sendNativeMessage)\s*\(\s*([^,)\n]{0,240})"
)
# A bare string literal as the first arg.
LITERAL_ARG_RE = re.compile(r"""^\s*["'`]([^"'`]{1,120})["'`]""")
# An identifier we may be able to resolve to a literal in the same file.
IDENT_ARG_RE = re.compile(r"^\s*([A-Za-z_$][\w$.]{0,60})\s*$")

# Native host names are reverse-DNS-ish: lowercase, dot separated, no spaces.
HOSTNAME_SHAPE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_-]+){1,6}$")
QUOTED_HOSTLIKE = re.compile(r"""["']([a-z][a-z0-9_]*(?:\.[a-z0-9_-]+){1,6})["']""")

# Leading segment of a reverse-DNS name — a strong signal it's a host name and
# not a filename or a domain.
REVERSE_DNS_HEADS = {
    "com", "org", "net", "io", "de", "ru", "jp", "cn", "eu", "br", "co", "us",
    "fr", "kr", "pl", "it", "es", "nl", "se", "ca", "au", "in", "tw", "ua",
    "tr", "gov", "mil", "edu", "cz", "dk", "fi", "no", "hu", "ro", "gr", "pt",
    "ch", "at", "be", "il", "za", "mx", "ar", "cl", "sg", "hk", "my", "th",
    "vn", "id", "ph", "nz", "ie", "sk", "si", "bg", "hr", "rs", "lt", "lv",
    "ee", "by", "kz", "ir", "sa", "ae", "eg", "ng", "ke", "app", "dev", "ai",
}
# Suffixes that mean "this is a file/domain/mime", not a host name. Reverse-DNS
# host names *start* with a TLD-ish segment, they don't end with one — so a
# trailing TLD is the tell that we're looking at a domain (expressprovider.com).
NOT_HOST_SUFFIX = {
    "js", "mjs", "cjs", "json", "html", "htm", "css", "png", "jpg", "jpeg",
    "gif", "svg", "woff", "woff2", "ttf", "eot", "map", "txt", "md", "xml",
    "wasm", "ico", "webp", "mp4", "webm", "zip", "crx", "min", "gz", "br",
} | (REVERSE_DNS_HEADS - {"app", "dev", "ai", "io", "co", "in", "at", "it", "by"})

# Identifiers too generic to resolve by name alone — `e.name` would happily bind
# to any `name = "..."` in the file. Leave these unresolved; the agent reads them.
GENERIC_IDENTS = {
    "name", "id", "key", "value", "type", "url", "path", "target", "src",
    "data", "msg", "message", "n", "e", "t", "r", "a", "s", "o", "i", "x",
}
# ...unless the identifier itself says what it holds.
HOSTISH_IDENT = re.compile(r"(host|native|nm|bridge|connector|helper|app|port|agent)", re.I)
NOISE_HOSTS = {
    "chrome.runtime", "browser.runtime", "window.location", "document.body",
    "navigator.userAgent", "process.env",
}

# URLs in the extension that smell like "download our desktop helper".
INSTALLER_URL_RE = re.compile(r"""https?://[^\s"'`<>\\)]{6,240}""")
INSTALLER_HINT = re.compile(
    r"(download|install|setup|helper|host|agent|client|desktop|native|plugin|"
    r"companion|\.exe|\.msi|\.dmg|\.pkg|\.deb|\.rpm|\.zip)",
    re.I,
)

# Native-side sinks worth grepping the binary for once we have it.
BINARY_SINKS = [
    "CreateProcess", "ShellExecute", "WinExec", "system", "popen", "execve",
    "_wsystem", "LoadLibrary", "RegSetValue", "RegCreateKey", "URLDownloadToFile",
    "WriteFile", "CopyFile", "MoveFile", "DeleteFile", "SetWindowsHookEx",
    "CryptUnprotectData", "OpenProcess", "WriteProcessMemory", "NtCreateThreadEx",
    "curl_easy_setopt", "sqlite3_open", "InternetOpenUrl", "WinHttpConnect",
]

ARCHIVE_SUFFIXES = {
    ".msi", ".exe", ".cab", ".zip", ".7z", ".rar", ".dmg", ".pkg", ".xar",
    ".rpm", ".deb", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".iso", ".msix",
    ".appx", ".nupkg", ".jar", ".asar", ".wim",
}
MAX_UNPACK_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB total per extension


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

def hunt_dir(ext_id: str) -> Path:
    return ROOT / ext_id


def state_path(ext_id: str) -> Path:
    return hunt_dir(ext_id) / "hunt.json"


def load_state(ext_id: str) -> dict:
    p = state_path(ext_id)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            pass
    return {"ext_id": ext_id}


def save_state(ext_id: str, state: dict) -> None:
    d = hunt_dir(ext_id)
    d.mkdir(parents=True, exist_ok=True)
    tmp = state_path(ext_id).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    tmp.replace(state_path(ext_id))


def db_conn():
    try:
        from db import get_connection  # scripts/lib
        return get_connection()
    except Exception:
        return None


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# stage 1: discover
# ---------------------------------------------------------------------------

@dataclass
class HostHit:
    host: str
    confidence: str          # literal | resolved | shaped
    file: str = ""
    line: int = 0
    snippet: str = ""
    api: str = ""


@dataclass
class Discovery:
    ext_id: str
    version: str | None = None
    source: str = "cws"
    name: str = ""
    user_count: int | None = None
    author: str = ""
    author_url: str = ""
    homepage_url: str = ""
    code_dir: str = ""
    manifest_version: int | None = None
    declares_native_messaging: bool = False
    content_script_matches: list[str] = field(default_factory=list)
    externally_connectable: dict = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    hosts: list[dict] = field(default_factory=list)
    bundled_executables: list[dict] = field(default_factory=list)
    call_sites: list[dict] = field(default_factory=list)
    acquisition_leads: list[str] = field(default_factory=list)
    message_keys: list[str] = field(default_factory=list)
    existing_claims: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _ensure_on_disk(ext_id: str, version: str | None, conn) -> tuple[str | None, Path | None, list[str]]:
    """Resolve (version, code_dir), downloading + deobfuscating if needed."""
    notes: list[str] = []
    source = "cws"
    if conn is not None:
        with conn.cursor() as cur:
            cur.execute("SELECT source FROM extensions WHERE id = %s", (ext_id,))
            row = cur.fetchone()
            if row and row[0]:
                source = row[0]

    v = paths.resolve_version(ext_id, version, conn)
    if v and paths.extracted_dir(ext_id, v).is_dir():
        pass
    else:
        downloader = {
            "cws": "download_cws_extension.py",
            "edge": "download_edge_extension.py",
            "firefox": "download_firefox_extension.py",
        }.get(source)
        if downloader is None:
            notes.append(f"source={source} has no downloader (Safari is not CRX-based)")
            return v, None, notes
        notes.append(f"not on disk — running {downloader}")
        r = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "scripts" / downloader), ext_id],
            capture_output=True, text=True, timeout=600,
        )
        if r.returncode != 0:
            notes.append(f"download failed: {(r.stderr or r.stdout)[-400:]}")
            return v, None, notes
        v = paths.resolve_version(ext_id, version, conn)

    if not v:
        notes.append("no version resolvable")
        return None, None, notes

    deob = paths.deobfuscated_dir(ext_id, v)
    if not deob.is_dir():
        notes.append("deobfuscating")
        r = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "scripts" / "decompile_extensions.py"),
             "--extension", ext_id, "--version", v],
            capture_output=True, text=True, timeout=1800,
        )
        if r.returncode != 0:
            notes.append(f"decompile failed: {(r.stderr or r.stdout)[-400:]}")

    deob = paths.deobfuscated_dir(ext_id, v)
    extracted = paths.extracted_dir(ext_id, v)
    code_dir = deob if deob.is_dir() else (extracted if extracted.is_dir() else None)
    if code_dir is None:
        notes.append("no extracted/ or deobfuscated/ on disk")
    return v, code_dir, notes


EXE_MAGIC = {
    b"MZ": "PE (Windows)",
    b"\x7fELF": "ELF",
    b"\xcf\xfa\xed\xfe": "Mach-O 64",
    b"\xce\xfa\xed\xfe": "Mach-O 32",
    b"\xca\xfe\xba\xbe": "Mach-O universal",
}


def _find_bundled_executables(ext_dir: Path) -> list[dict]:
    """Native hosts sometimes ship *inside* the CRX (ACD ships its host as a
    web-accessible `.dat`), which makes the whole acquisition ladder moot. Cheap
    magic-byte sweep — extension declares no compiled code, so any hit is
    interesting regardless of what it's named."""
    out = []
    for p in ext_dir.rglob("*"):
        if not p.is_file():
            continue
        try:
            if p.stat().st_size < 4096:
                continue
            with p.open("rb") as fh:
                head = fh.read(4)
        except OSError:
            continue
        for magic, label in EXE_MAGIC.items():
            if head.startswith(magic):
                kind = subprocess.run(["file", "-b", str(p)],
                                      capture_output=True, text=True).stdout.strip()
                out.append({"path": str(p), "rel": str(p.relative_to(ext_dir)),
                            "magic": label, "file": kind, "size": p.stat().st_size})
                break
    return out


def _iter_code_files(code_dir: Path):
    for p in code_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if p.stat().st_size > 24 * 1024 * 1024:
            continue
        yield p


def _looks_like_host(s: str) -> bool:
    if s in NOISE_HOSTS or not HOSTNAME_SHAPE.match(s):
        return False
    parts = s.split(".")
    if parts[-1].lower() in NOT_HOST_SUFFIX:
        return False
    if len(parts) < 2:
        return False
    return True


def _in_comment(content: str, pos: int) -> bool:
    """Is `pos` inside a // or /* */ comment?

    Vendors leave dead native-host names commented out next to the live one
    (vendors ship `//hostName = "com.vendor.test.reflect"` directly
    above the real assignment). Reporting those as hosts sends a hunter after a
    binary that was never built.
    """
    line_start = content.rfind("\n", 0, pos) + 1
    if "//" in content[line_start:pos]:
        return True
    last_open = content.rfind("/*", 0, pos)
    return last_open > content.rfind("*/", 0, pos)


def _resolve_ident(ident: str, content: str, call_at: int) -> str | None:
    """`const NM_HOST = "com.x.y"` / `NM_HOST: "com.x.y"` in the same file.

    Name-based binding is coarse — in minified code `e.name` collides with every
    `name = "..."` in the bundle — so it only fires when the identifier itself
    reads like a host holder, or when the value is unmistakably reverse-DNS.
    Among the candidates, the assignment nearest the call site wins.
    """
    base = ident.split(".")[-1]
    if len(base) < 2:
        return None
    ident_is_hostish = bool(HOSTISH_IDENT.search(ident))
    if base.lower() in GENERIC_IDENTS and not ident_is_hostish:
        return None

    candidates: list[tuple[int, str]] = []
    for pat in (
        rf"""\b{re.escape(base)}\s*=\s*["'`]([^"'`]{{2,120}})["'`]""",
        rf"""["']?{re.escape(base)}["']?\s*:\s*["'`]([^"'`]{{2,120}})["'`]""",
    ):
        for m in re.finditer(pat, content):
            val = m.group(1)
            if not _looks_like_host(val) or _in_comment(content, m.start()):
                continue
            # A reverse-DNS head is proof enough on its own; anything weaker
            # needs the identifier to have vouched for it.
            if val.split(".")[0] in REVERSE_DNS_HEADS or ident_is_hostish:
                candidates.append((abs(m.start() - call_at), val))
    if not candidates:
        return None
    return min(candidates)[1]


def scan_code(code_dir: Path) -> tuple[list[HostHit], list[dict], list[str], list[str]]:
    """Return (host hits, call sites, acquisition leads, message key leads)."""
    hits: list[HostHit] = []
    call_sites: list[dict] = []
    leads: set[str] = set()
    msg_keys: dict[str, int] = {}
    files_with_calls: list[tuple[Path, str]] = []

    for p in _iter_code_files(code_dir):
        try:
            content = p.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(p.relative_to(code_dir))

        if "connectNative" in content or "sendNativeMessage" in content:
            files_with_calls.append((p, content))
            lines = content.splitlines()
            for m in NATIVE_CALL_RE.finditer(content):
                if _in_comment(content, m.start()):
                    continue
                api, arg = m.group(1), m.group(2)
                line_no = content.count("\n", 0, m.start()) + 1
                snippet = lines[line_no - 1].strip()[:300] if line_no <= len(lines) else ""
                host, conf = None, None
                lit = LITERAL_ARG_RE.match(arg)
                if lit and _looks_like_host(lit.group(1)):
                    host, conf = lit.group(1), "literal"
                elif lit:
                    host, conf = lit.group(1), "literal-odd"
                else:
                    ident = IDENT_ARG_RE.match(arg)
                    if ident:
                        resolved = _resolve_ident(ident.group(1), content, m.start())
                        if resolved:
                            host, conf = resolved, "resolved"
                call_sites.append({
                    "api": api, "file": rel, "line": line_no,
                    "arg": arg.strip()[:120], "host": host, "snippet": snippet,
                })
                if host:
                    hits.append(HostHit(host, conf, rel, line_no, snippet, api))

            # Short string keys near the native calls: the wire protocol's
            # opcodes usually live here. Leads only — the agent reads the code.
            for m in re.finditer(r"""["']([a-zA-Z][\w:.\-]{2,32})["']\s*:""", content):
                k = m.group(1)
                msg_keys[k] = msg_keys.get(k, 0) + 1

        for m in INSTALLER_URL_RE.finditer(content):
            u = m.group(0).rstrip(".,);'\"")
            if INSTALLER_HINT.search(u) and "chrome.google.com" not in u:
                leads.add(u)

    # Files that call native messaging but whose host name we couldn't pin to a
    # call site: harvest host-shaped literals from them.
    pinned = {h.host for h in hits}
    # Vendors namespace their wire opcodes under the same reverse-DNS prefix as
    # the host itself (`com.vendor.nmhost` alongside `com.vendor.nm.abort`),
    # so anything sharing a pinned host's first two segments is protocol, not a
    # second host.
    pinned_prefixes = {".".join(h.split(".")[:2]) for h in pinned if h.count(".") >= 1}
    shaped: list[HostHit] = []
    for p, content in files_with_calls:
        rel = str(p.relative_to(code_dir))
        for m in QUOTED_HOSTLIKE.finditer(content):
            s = m.group(1)
            if s in pinned or not _looks_like_host(s) or _in_comment(content, m.start()):
                continue
            if s.split(".")[0] not in REVERSE_DNS_HEADS:
                continue
            line_no = content.count("\n", 0, m.start()) + 1
            shaped.append(HostHit(s, "shaped", rel, line_no, "", ""))
            pinned.add(s)

    # A crowd of siblings under a prefix we already pinned is the vendor's opcode
    # namespace, not seven native hosts. One lone sibling is plausibly a second
    # real host (some vendors ship a product host and a test host) — keep it.
    family: dict[str, int] = {}
    for h in shaped:
        family[".".join(h.host.split(".")[:2])] = family.get(".".join(h.host.split(".")[:2]), 0) + 1
    hits += [h for h in shaped
             if not (family[".".join(h.host.split(".")[:2])] >= 3
                     and ".".join(h.host.split(".")[:2]) in pinned_prefixes)]

    order = {"literal": 0, "resolved": 1, "shaped": 2, "literal-odd": 3}
    hits.sort(key=lambda h: (order.get(h.confidence, 9), h.host))
    keys = [k for k, _ in sorted(msg_keys.items(), key=lambda kv: -kv[1])[:40]]
    return hits, call_sites, sorted(leads)[:60], keys


def cmd_discover(args) -> int:
    ext_id = args.ext_id
    conn = db_conn()
    d = Discovery(ext_id=ext_id)

    if conn is not None:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, user_count, author, author_url, source, manifest_version "
                "FROM extensions WHERE id = %s", (ext_id,))
            row = cur.fetchone()
            if row:
                d.name, d.user_count, d.author, d.author_url, d.source, d.manifest_version = row
            cur.execute(
                "SELECT id, cwe, severity, short_title, summary, verification_status "
                "FROM claims WHERE extension_id = %s "
                "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 ELSE 3 END LIMIT 25", (ext_id,))
            for cid, cwe, sev, title, summary, vs in cur.fetchall():
                d.existing_claims.append({
                    "id": cid, "cwe": cwe, "severity": sev,
                    "title": title or (summary or "")[:120], "status": vs,
                })

    version, code_dir, notes = _ensure_on_disk(ext_id, args.version, conn)
    d.version, d.notes = version, notes
    if conn is not None:
        conn.close()
    if code_dir is None:
        state = load_state(ext_id)
        state["discovery"] = d.__dict__
        save_state(ext_id, state)
        print(json.dumps(d.__dict__, indent=2, default=str) if args.json
              else f"FAIL {ext_id}: {'; '.join(notes)}")
        return 1
    d.code_dir = str(code_dir)

    manifest_path = code_dir / "manifest.json"
    if not manifest_path.exists():
        manifest_path = paths.extracted_dir(ext_id, version) / "manifest.json"
    if manifest_path.exists():
        try:
            mf = json.loads(manifest_path.read_text(errors="ignore"))
        except json.JSONDecodeError:
            mf = {}
        perms = list(mf.get("permissions", []) or [])
        opt = list(mf.get("optional_permissions", []) or [])
        d.permissions = [p for p in perms + opt if isinstance(p, str)]
        d.host_permissions = [p for p in (mf.get("host_permissions") or []) if isinstance(p, str)]
        d.host_permissions += [p for p in perms if isinstance(p, str) and ("://" in p or p == "<all_urls>")]
        d.declares_native_messaging = "nativeMessaging" in d.permissions
        d.homepage_url = mf.get("homepage_url", "") or ""
        d.manifest_version = mf.get("manifest_version", d.manifest_version)
        for cs in mf.get("content_scripts", []) or []:
            d.content_script_matches += [m for m in (cs.get("matches") or []) if isinstance(m, str)]
        d.content_script_matches = sorted(set(d.content_script_matches))
        ec = mf.get("externally_connectable")
        if isinstance(ec, dict):
            d.externally_connectable = ec

    extracted = paths.extracted_dir(ext_id, version)
    d.bundled_executables = _find_bundled_executables(
        extracted if extracted.is_dir() else code_dir)

    hits, call_sites, leads, keys = scan_code(code_dir)
    seen: dict[str, dict] = {}
    for h in hits:
        cur = seen.get(h.host)
        if cur is None:
            seen[h.host] = {
                "host": h.host, "confidence": h.confidence, "hits": 1,
                "first_seen": f"{h.file}:{h.line}", "api": h.api, "snippet": h.snippet,
            }
        else:
            cur["hits"] += 1
    d.hosts = list(seen.values())
    d.call_sites = call_sites[:60]
    d.message_keys = keys
    for u in (d.homepage_url, d.author_url):
        if u and u not in leads:
            leads.insert(0, u)
    d.acquisition_leads = leads

    if not d.hosts and d.declares_native_messaging:
        d.notes.append("declares nativeMessaging but no host name recovered — "
                       "likely computed at runtime; needs an agent read or a DA run")
    if not d.declares_native_messaging and d.hosts:
        d.notes.append("host names found without the nativeMessaging permission — "
                       "check optional_permissions / dead code")

    state = load_state(ext_id)
    state["discovery"] = d.__dict__
    save_state(ext_id, state)
    _write_brief(ext_id, d)

    if args.json:
        print(json.dumps(d.__dict__, indent=2, default=str))
    else:
        print(f"{ext_id}  {d.name or '?'}  v{d.version}  users={d.user_count}")
        print(f"  code: {d.code_dir}")
        print(f"  nativeMessaging perm: {d.declares_native_messaging}   "
              f"CS scope: {', '.join(d.content_script_matches[:4]) or '—'}")
        if d.hosts:
            for h in d.hosts:
                print(f"  HOST [{h['confidence']:>11}] {h['host']}  ({h['hits']} hits, {h['first_seen']})")
        else:
            print("  HOST  none recovered")
        for b in d.bundled_executables:
            print(f"  BUNDLED EXECUTABLE  {b['rel']}  ({b['file'][:60]})")
        print(f"  leads: {len(d.acquisition_leads)} URLs  -> {hunt_dir(ext_id)/'BRIEF.md'}")
        for n in d.notes:
            print(f"  note: {n}")
    return 0 if d.hosts else 2


def _write_brief(ext_id: str, d: Discovery) -> None:
    L = [f"# Native host brief — {d.name or ext_id}", "",
         f"- **Extension:** `{ext_id}` ({d.source})",
         f"- **Version:** {d.version}",
         f"- **Users:** {d.user_count:,}" if d.user_count else "- **Users:** unknown",
         f"- **Author:** {d.author} {d.author_url}",
         f"- **Code on disk:** `{d.code_dir}`",
         f"- **manifest_version:** {d.manifest_version}   **nativeMessaging:** {d.declares_native_messaging}",
         "",
         "## Reachability surface", "",
         f"- Content-script matches: `{', '.join(d.content_script_matches) or 'none'}`",
         f"- externally_connectable: `{json.dumps(d.externally_connectable) or 'none'}`",
         f"- Host permissions: `{', '.join(d.host_permissions[:12]) or 'none'}`",
         "", "## Native hosts", ""]
    if d.hosts:
        L += ["| host | confidence | hits | first seen |", "|---|---|---|---|"]
        L += [f"| `{h['host']}` | {h['confidence']} | {h['hits']} | `{h['first_seen']}` |" for h in d.hosts]
    else:
        L.append("_None recovered statically._")
    L += ["", "## Call sites", ""]
    for c in d.call_sites[:25]:
        L.append(f"- `{c['file']}:{c['line']}` — `{c['api']}({c['arg']})`"
                 + (f" → `{c['host']}`" if c["host"] else " → **unresolved**"))
    L += ["", "## Acquisition leads (URLs found in the extension)", ""]
    L += [f"- {u}" for u in d.acquisition_leads[:40]] or ["_none_"]
    if d.message_keys:
        L += ["", "## Message-key leads (candidate wire opcodes)", "",
              "`" + "`, `".join(d.message_keys) + "`"]
    if d.existing_claims:
        L += ["", "## Existing claims", ""]
        L += [f"- C#{c['id']} [{c['severity']}/{c['status']}] {c['cwe']} — {c['title']}"
              for c in d.existing_claims]
    if d.notes:
        L += ["", "## Notes", ""] + [f"- {n}" for n in d.notes]
    p = hunt_dir(ext_id)
    p.mkdir(parents=True, exist_ok=True)
    (p / "BRIEF.md").write_text("\n".join(L) + "\n")


# ---------------------------------------------------------------------------
# stage 2: fetch
# ---------------------------------------------------------------------------

def cmd_fetch(args) -> int:
    ext_id = args.ext_id
    dl = hunt_dir(ext_id) / "downloads"
    dl.mkdir(parents=True, exist_ok=True)
    url = args.url
    label = args.label or url.rstrip("/").split("/")[-1].split("?")[0] or "installer.bin"
    label = re.sub(r"[^\w.\-]", "_", label)[:120]
    dest = dl / label

    cmd = ["curl", "-fSL", "--max-time", str(args.timeout), "--retry", "2",
           "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
           "-o", str(dest), url]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not dest.exists():
        print(f"FAIL fetch {url}: {r.stderr.strip()[-300:]}")
        return 1

    size = dest.stat().st_size
    digest = sha256_file(dest)
    kind = subprocess.run(["file", "-b", str(dest)], capture_output=True, text=True).stdout.strip()
    rec = {"url": url, "path": str(dest), "size": size, "sha256": digest, "file": kind}

    state = load_state(ext_id)
    downloads = [d for d in state.get("downloads", []) if d.get("url") != url]
    downloads.append(rec)
    state["downloads"] = downloads
    save_state(ext_id, state)
    print(f"OK {dest}  {size:,} bytes  sha256={digest}\n   {kind}")
    return 0


# ---------------------------------------------------------------------------
# stage 3: unpack
# ---------------------------------------------------------------------------

def _tree_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


def _unpack_one(src: Path, dest: Path) -> tuple[bool, str]:
    """Try the right extractor for `src` into `dest`. Never executes anything."""
    dest.mkdir(parents=True, exist_ok=True)
    suffix = src.suffix.lower()

    if suffix == ".deb" and shutil.which("dpkg-deb"):
        r = subprocess.run(["dpkg-deb", "-x", str(src), str(dest)],
                           capture_output=True, text=True, timeout=900)
        if r.returncode == 0:
            return True, "dpkg-deb"

    if suffix in (".exe", ".bin") and shutil.which("innoextract"):
        r = subprocess.run(["innoextract", "-s", "-d", str(dest), str(src)],
                           capture_output=True, text=True, timeout=900)
        if r.returncode == 0 and any(dest.iterdir()):
            return True, "innoextract"

    if shutil.which("7z"):
        r = subprocess.run(["7z", "x", "-y", "-bd", f"-o{dest}", str(src)],
                           capture_output=True, text=True, timeout=1800)
        if r.returncode in (0, 1) and any(dest.iterdir()):
            return True, "7z"

    if suffix in (".tar", ".gz", ".tgz", ".xz", ".bz2"):
        r = subprocess.run(["tar", "xf", str(src), "-C", str(dest)],
                           capture_output=True, text=True, timeout=900)
        if r.returncode == 0:
            return True, "tar"

    if shutil.which("binwalk"):
        r = subprocess.run(["binwalk", "-e", "--run-as=root", "-C", str(dest), str(src)],
                           capture_output=True, text=True, timeout=1800)
        if r.returncode == 0 and any(dest.rglob("*")):
            return True, "binwalk"

    try:
        dest.rmdir()
    except OSError:
        pass
    return False, "no extractor succeeded"


def cmd_unpack(args) -> int:
    ext_id = args.ext_id
    state = load_state(ext_id)
    downloads = state.get("downloads", [])
    if not downloads:
        print("nothing downloaded yet — run fetch first")
        return 1

    unpack_root = hunt_dir(ext_id) / "unpacked"
    unpack_root.mkdir(parents=True, exist_ok=True)
    results = []

    queue: list[tuple[Path, int, str]] = [(Path(d["path"]), 0, "") for d in downloads]
    seen: set[str] = set()
    while queue:
        src, depth, parent = queue.pop(0)
        if depth > args.max_depth or not src.exists():
            continue
        try:
            digest = sha256_file(src)
        except OSError:
            continue
        if digest in seen:
            continue
        seen.add(digest)
        if _tree_bytes(unpack_root) > MAX_UNPACK_BYTES:
            results.append({"src": str(src), "ok": False, "how": "budget exceeded"})
            break

        out = unpack_root / f"d{depth}_{src.name}_{digest[:8]}"
        ok, how = _unpack_one(src, out)
        results.append({"src": str(src), "dest": str(out) if ok else "",
                        "ok": ok, "how": how, "depth": depth, "parent": parent})
        if not ok:
            continue
        for child in out.rglob("*"):
            if not child.is_file():
                continue
            if child.suffix.lower() in ARCHIVE_SUFFIXES and child.stat().st_size > 4096:
                queue.append((child, depth + 1, str(src)))

    state["unpacked"] = {"root": str(unpack_root), "results": results,
                         "bytes": _tree_bytes(unpack_root)}
    save_state(ext_id, state)
    ok_n = sum(1 for r in results if r["ok"])
    print(f"unpacked {ok_n}/{len(results)} archives → {unpack_root} "
          f"({state['unpacked']['bytes']:,} bytes)")
    for r in results:
        print(f"  [{'ok' if r['ok'] else '--'}] d{r.get('depth',0)} {Path(r['src']).name} ({r['how']})")
    return 0 if ok_n else 1


# ---------------------------------------------------------------------------
# stage 4: link — prove installer ↔ extension
# ---------------------------------------------------------------------------

def _find_nm_manifests(root: Path, ext_id: str, hosts: set[str]) -> list[dict]:
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or p.stat().st_size > 256 * 1024:
            continue
        if p.suffix.lower() not in (".json", ".txt", ""):
            continue
        try:
            raw = p.read_text(errors="ignore")
        except OSError:
            continue
        # UTF-8 BOM survives read_text() with the default encoding and makes
        # json.loads() choke on the very first character (some vendors ship
        # their NM manifest with a BOM and // comments).
        raw = raw.lstrip("﻿")
        if "allowed_origins" not in raw and "allowed_extensions" not in raw:
            continue
        try:
            mf = json.loads(raw)
        except json.JSONDecodeError:
            # Vendors ship NM manifests with // comments (JSONC). Strip and retry.
            stripped = re.sub(r"^\s*//.*$", "", raw, flags=re.M)
            try:
                mf = json.loads(stripped)
            except json.JSONDecodeError:
                continue
        if not isinstance(mf, dict):
            continue
        origins = mf.get("allowed_origins") or mf.get("allowed_extensions") or []
        origins = [o for o in origins if isinstance(o, str)]
        matches_ext = any(ext_id in o for o in origins)
        out.append({
            "manifest": str(p),
            "host_name": mf.get("name", ""),
            "type": mf.get("type", ""),
            "declared_path": mf.get("path", ""),
            "description": mf.get("description", ""),
            "allowed_origins": origins[:20],
            "matches_extension": matches_ext,
            "matches_known_host": mf.get("name", "") in hosts,
        })
    out.sort(key=lambda m: (not m["matches_extension"], not m["matches_known_host"]))
    return out


def _resolve_declared_path(declared: str, root: Path) -> list[str]:
    """The manifest's `path` is an install-time path; find that basename here."""
    if not declared:
        return []
    base = declared.replace("\\", "/").rstrip("/").split("/")[-1]
    if not base:
        return []
    hits = [str(p) for p in root.rglob(base) if p.is_file()]
    if not hits:
        # macOS/Windows manifests are written for case-insensitive filesystems,
        # so the declared basename may not match the extracted file's case.
        # MSI cabs go further and store *source* names, which differ from the
        # installed name by separator alone (`chrome_token_signing.exe` in the
        # cab vs `chrome-token-signing.exe` in the manifest) — normalise both
        # before concluding the binary isn't in the package.
        def norm(s: str) -> str:
            return s.lower().replace("_", "-").replace(" ", "-")
        want = norm(base)
        hits = [str(p) for p in root.rglob("*") if p.is_file() and norm(p.name) == want]
    return hits[:10]


def _grep_hosts(root: Path, hosts: set[str]) -> list[dict]:
    """Which files embed the host name? Catches binaries with no shipped manifest."""
    found: dict[str, set[str]] = {}
    if not hosts:
        return []
    for host in hosts:
        r = subprocess.run(["grep", "-rlIa", "--", host, str(root)],
                           capture_output=True, text=True, timeout=1200)
        for line in r.stdout.splitlines():
            found.setdefault(line, set()).add(host)
    out = []
    for path, hs in found.items():
        p = Path(path)
        try:
            size = p.stat().st_size
        except OSError:
            continue
        kind = subprocess.run(["file", "-b", path], capture_output=True, text=True).stdout.strip()
        out.append({"path": path, "size": size, "file": kind, "hosts": sorted(hs)})
    out.sort(key=lambda e: (0 if any(k in e["file"] for k in
                                     ("executable", "PE32", "Mach-O", "ELF")) else 1, -e["size"]))
    return out[:60]


def cmd_link(args) -> int:
    ext_id = args.ext_id
    state = load_state(ext_id)
    root = Path(state.get("unpacked", {}).get("root", hunt_dir(ext_id) / "unpacked"))
    if not root.is_dir():
        print("nothing unpacked — run unpack first")
        return 1
    hosts = {h["host"] for h in state.get("discovery", {}).get("hosts", [])}

    manifests = _find_nm_manifests(root, ext_id, hosts)
    for m in manifests:
        m["resolved_binaries"] = _resolve_declared_path(m["declared_path"], root)
    embeds = _grep_hosts(root, hosts)

    binaries: list[dict] = []
    seen = set()
    for m in manifests:
        if not (m["matches_extension"] or m["matches_known_host"]):
            continue
        for b in m["resolved_binaries"]:
            if b not in seen:
                seen.add(b)
                binaries.append({"path": b, "why": f"NM manifest path ({m['host_name']})",
                                 "host_name": m["host_name"]})
    for e in embeds:
        if e["path"] in seen:
            continue
        if any(k in e["file"] for k in ("executable", "PE32", "PE32+", "Mach-O", "ELF", "script")):
            seen.add(e["path"])
            binaries.append({"path": e["path"], "why": "embeds host name string",
                             "host_name": ", ".join(e["hosts"])})

    state["link"] = {"manifests": manifests, "embeds": embeds, "binaries": binaries}
    save_state(ext_id, state)

    confirmed = [m for m in manifests if m["matches_extension"]]
    print(f"NM manifests found: {len(manifests)}  (allowed_origins names this extension: {len(confirmed)})")
    for m in manifests[:10]:
        flag = "CONFIRMED" if m["matches_extension"] else ("host-match" if m["matches_known_host"] else "other")
        print(f"  [{flag}] {m['host_name'] or '?'} -> {m['declared_path'] or '?'}")
        print(f"      {m['manifest']}")
        for b in m["resolved_binaries"][:3]:
            print(f"      binary: {b}")
    print(f"\ncandidate native host binaries: {len(binaries)}")
    for b in binaries[:15]:
        print(f"  {b['path']}  ({b['why']})")
    return 0 if binaries else 2


# ---------------------------------------------------------------------------
# stage 5: triage
# ---------------------------------------------------------------------------

def _imported_symbols(path: Path, kind: str) -> set[str]:
    """Names the binary actually imports. Empty set = unknown, not 'none'."""
    syms: set[str] = set()
    try:
        if "PE32" in kind or "MS Windows" in kind:
            r = subprocess.run(["objdump", "-p", str(path)],
                               capture_output=True, text=True, timeout=300)
            for line in r.stdout.splitlines():
                m = re.match(r"\s+[0-9a-f]+\s+\d+\s+(\S+)", line)
                if m:
                    syms.add(m.group(1))
        elif "ELF" in kind or "Mach-O" in kind:
            r = subprocess.run(["objdump", "-T", str(path)],
                               capture_output=True, text=True, timeout=300)
            for line in r.stdout.splitlines():
                if "*UND*" in line:
                    syms.add(line.split()[-1].split("@")[0])
    except (OSError, subprocess.SubprocessError):
        pass
    return syms


def _binary_facts(path: Path, opcodes: list[str]) -> dict:
    kind = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True).stdout.strip()
    try:
        blob = path.read_bytes()
    except OSError:
        blob = b""
    r = subprocess.run(["strings", "-n", "6", str(path)], capture_output=True, text=True)
    strs = r.stdout.splitlines()
    sset = set(strs)

    # A sink in the import table means the binary can actually call it. A sink
    # in the string table might just be libc's "read only file system". Keep
    # them apart — the difference is "this host can exec" vs "this host contains
    # the word system", and conflating them sends a reverser down a dead end.
    imported = _imported_symbols(path, kind)
    sinks_imported = sorted({s for s in BINARY_SINKS
                             if any(sym == s or sym.startswith(s) for sym in imported)})
    sinks_strings = sorted({s for s in BINARY_SINKS
                            if s not in sinks_imported
                            and any(re.search(rf"\b{re.escape(s)}\b", x) for x in strs)})
    sinks = sinks_imported or sinks_strings
    seen_opcodes = sorted({o for o in opcodes if o in sset})[:25]

    tech = []
    if b"mscoree.dll" in blob or b"_CorExeMain" in blob or ".NET" in kind:
        tech.append(".NET  -> decompile with ILSpy/dnSpy")
    if b"electron.asar" in blob or b"node_modules" in blob[:2_000_000]:
        tech.append("Electron/Node -> unpack app.asar")
    if b"PyInstaller" in blob or b"Py_Initialize" in blob:
        tech.append("PyInstaller -> pyinstxtractor + uncompyle")
    if b"Go build ID" in blob:
        tech.append("Go -> ghidra + goretk")
    if b"UPX!" in blob:
        tech.append("UPX packed -> upx -d first")
    if "PE32+" in kind:
        tech.append("x64 PE -> ghidra / IDA")
    elif "PE32" in kind:
        tech.append("x86 PE -> ghidra / IDA")
    elif "Mach-O" in kind:
        tech.append("Mach-O -> ghidra; check codesign entitlements")
    elif "ELF" in kind:
        tech.append("ELF -> ghidra")

    interesting = [s for s in strs
                   if len(s) < 200 and re.search(r"(https?://|\\\\\.\\|cmd\.exe|powershell|"
                                                 r"/bin/sh|SELECT |INSERT |sqlite|token|password|"
                                                 r"registry|HKEY_)", s, re.I)][:60]
    return {
        "path": str(path),
        "size": path.stat().st_size if path.exists() else 0,
        "sha256": sha256_file(path) if path.exists() else "",
        "file": kind,
        "sinks": sinks,
        "opcodes_present": seen_opcodes,
        "tech": tech,
        "interesting_strings": interesting,
    }


def cmd_triage(args) -> int:
    ext_id = args.ext_id
    state = load_state(ext_id)
    binaries = state.get("link", {}).get("binaries", [])
    if not binaries:
        print("no candidate binaries — run link first")
        return 1
    opcodes = state.get("discovery", {}).get("message_keys", [])

    facts = []
    for b in binaries[:args.limit]:
        p = Path(b["path"])
        if not p.exists():
            continue
        f = _binary_facts(p, opcodes)
        f["why"] = b["why"]
        f["host_name"] = b.get("host_name", "")
        facts.append(f)

    facts.sort(key=lambda f: (-len(f["opcodes_present"]), -len(f["sinks"])))
    state["triage"] = facts
    save_state(ext_id, state)

    for f in facts:
        print(f"\n{f['path']}")
        print(f"  {f['file']}  {f['size']:,} bytes  sha256={f['sha256'][:16]}…")
        print(f"  why: {f['why']}  host: {f['host_name']}")
        if f["tech"]:
            print(f"  tech: {'; '.join(f['tech'])}")
        if f["opcodes_present"]:
            print(f"  extension opcodes present: {', '.join(f['opcodes_present'])}")
        if f["sinks"]:
            print(f"  sinks: {', '.join(f['sinks'])}")
    return 0


# ---------------------------------------------------------------------------
# report / status
# ---------------------------------------------------------------------------

def cmd_report(args) -> int:
    ext_id = args.ext_id
    state = load_state(ext_id)
    d = state.get("discovery", {})
    link = state.get("link", {})
    triage = state.get("triage", [])
    L = [f"# Native host research packet — {d.get('name') or ext_id}", "",
         f"`{ext_id}` · v{d.get('version')} · {d.get('user_count')} users · {d.get('source')}", ""]

    L += ["## 1. Browser side", "",
          f"- nativeMessaging: `{d.get('declares_native_messaging')}`",
          f"- CS scope: `{', '.join(d.get('content_script_matches', [])) or 'none'}`",
          f"- externally_connectable: `{json.dumps(d.get('externally_connectable', {}))}`", ""]
    for h in d.get("hosts", []):
        L.append(f"- host `{h['host']}` ({h['confidence']}, {h['hits']} hits, {h['first_seen']})")

    L += ["", "## 2. Acquisition", ""]
    for dl in state.get("downloads", []):
        L.append(f"- `{dl['url']}` → `{dl['path']}` ({dl['size']:,} B, sha256 `{dl['sha256'][:16]}…`)")
        L.append(f"  - {dl['file']}")
    if not state.get("downloads"):
        L.append("_installer not acquired_")

    L += ["", "## 3. Link proof", ""]
    conf = [m for m in link.get("manifests", []) if m.get("matches_extension")]
    if conf:
        for m in conf:
            L += [f"- **`{m['host_name']}`** — manifest `{m['manifest']}`",
                  f"  - declared path: `{m['declared_path']}`",
                  f"  - allowed_origins: `{', '.join(m['allowed_origins'])}`",
                  f"  - resolved: {', '.join(f'`{b}`' for b in m.get('resolved_binaries', [])) or '_not found in package_'}"]
    else:
        L.append("_no NM manifest in the package names this extension_ — "
                 "binaries below are matched by embedded host-name string only.")

    L += ["", "## 4. Native host binaries", ""]
    for f in triage:
        L += [f"### `{Path(f['path']).name}`", "",
              f"- path: `{f['path']}`",
              f"- {f['file']}",
              f"- {f['size']:,} bytes · sha256 `{f['sha256']}`",
              f"- matched because: {f['why']}",
              f"- tooling: {'; '.join(f['tech']) or 'unknown format'}"]
        if f["opcodes_present"]:
            L.append(f"- extension opcodes found in binary: `{'`, `'.join(f['opcodes_present'])}`")
        if f["sinks"]:
            L.append(f"- sinks: `{'`, `'.join(f['sinks'])}`")
        L.append("")
    if not triage:
        L.append("_no binaries triaged_")

    L += ["", "## 5. Next steps", "",
          "1. Load the host binary in the decompiler named above.",
          "2. Find the stdin read loop (4-byte little-endian length prefix, then JSON).",
          "3. Map each extension opcode to its handler; look for handlers that take a "
          "path/URL/command from the message.",
          "4. Walk back to the browser: can a web page reach that opcode "
          "(content-script relay or externally_connectable)?",
          "5. Submit a claim: `scripts/da claim add " + ext_id + " --json '{...}'`", ""]

    out = hunt_dir(ext_id) / "REPORT.md"
    # The generated packet is scaffolding; the value an agent adds is appended
    # below it. Re-running `report` (a second hunt, a re-triage) used to wipe
    # that. Carry the appended section forward, and keep a full backup either
    # way so a regeneration can never destroy prior analysis.
    ANALYST_MARKER = "# Analyst notes (appended)"
    carried = ""
    if out.exists():
        prev = out.read_text(errors="ignore")
        idx = prev.find(ANALYST_MARKER)
        if idx != -1:
            carried = prev[idx:]
        elif len(prev) > len("\n".join(L)) * 1.2:
            # Notes were appended without the marker — don't guess, keep it all.
            carried = ANALYST_MARKER + "\n\n(recovered from a previous run)\n\n" + prev
        n = 1
        while (bak := hunt_dir(ext_id) / f"REPORT.prev{n}.md").exists():
            n += 1
        bak.write_text(prev)

    body = "\n".join(L) + "\n"
    if carried:
        body += "\n---\n\n" + carried.rstrip() + "\n"
    out.write_text(body)
    print(f"wrote {out}" + ("  (preserved prior analyst notes)" if carried else ""))
    if args.cat:
        print("\n".join(L))
    return 0


def cmd_status(args) -> int:
    ext_id = args.ext_id
    state = load_state(ext_id)
    d = state.get("discovery", {})
    stages = [
        ("discover", bool(d), f"{len(d.get('hosts', []))} host(s)"),
        ("fetch", bool(state.get("downloads")), f"{len(state.get('downloads', []))} file(s)"),
        ("unpack", bool(state.get("unpacked")), f"{state.get('unpacked', {}).get('bytes', 0):,} B"),
        ("link", bool(state.get("link")), f"{len(state.get('link', {}).get('binaries', []))} binary candidate(s)"),
        ("triage", bool(state.get("triage")), f"{len(state.get('triage', []))} triaged"),
    ]
    print(f"{ext_id}  {d.get('name', '?')}")
    for name, done, detail in stages:
        print(f"  [{'x' if done else ' '}] {name:<9} {detail}")
    print(f"  dir: {hunt_dir(ext_id)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover"); p.add_argument("ext_id")
    p.add_argument("--version"); p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("fetch"); p.add_argument("ext_id")
    p.add_argument("--url", required=True); p.add_argument("--label")
    p.add_argument("--timeout", type=int, default=900)
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("unpack"); p.add_argument("ext_id")
    p.add_argument("--max-depth", type=int, default=4)
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("link"); p.add_argument("ext_id"); p.set_defaults(func=cmd_link)

    p = sub.add_parser("triage"); p.add_argument("ext_id")
    p.add_argument("--limit", type=int, default=12)
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("report"); p.add_argument("ext_id")
    p.add_argument("--cat", action="store_true"); p.set_defaults(func=cmd_report)

    p = sub.add_parser("status"); p.add_argument("ext_id"); p.set_defaults(func=cmd_status)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
