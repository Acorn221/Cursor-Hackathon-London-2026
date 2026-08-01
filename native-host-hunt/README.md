# native-host-hunt

**Browser extension ID in → native host binary out.**

A Chrome/Firefox extension that declares `nativeMessaging` talks to a native
*host*: a program installed on the user's machine, shipped inside some vendor's
desktop installer. If a web page can reach that bridge, the extension's
JavaScript is only half the story — the interesting code is the binary on the
other side, and nobody can review it until someone finds it.

Finding it is the annoying part. The extension names the host
(`com.vendor.something`) but never says where it comes from. The installer is
on a vendor site in another language, or behind a licence portal, or the link
404s. Then the "binary" turns out to be a `.bat` that launches something else.

This is an agentic pipeline for that problem. Deterministic tooling does the
plumbing; an LLM agent does the judgement — deciding which host matters, where
on the internet the installer actually lives, and whether a web page can reach
it.

## Split of labour

| | |
|---|---|
| `scripts/native_host_hunt.py` | the tool belt — resolve on disk, grep host names, fetch, unpack, link, triage, report |
| `prompts/native_host_hunt.md` | the hunter agent's instructions — the judgement half |
| `workflows/native-host-hunt.js` | fan-out, one hunter per extension, plus a roundup |
| `scripts/pick_runnable_installer.py` | picks the single runnable installer per extension out of the hunt tree |
| `skill/SKILL.md` | Claude Code skill wrapper (`/native-host-hunt`) |

**Stage 2 — find the bug in the binary you just acquired:**

| | |
|---|---|
| `scripts/ghidra_decompile.py` | routes by format, runs Ghidra headless, exports the surface |
| `scripts/ghidra_scripts/ExportNativeHostSurface.java` | the headless post-script: decompiled C, sink call graph, strings |
| `prompts/ghidra_rce_hunt.md` | the reverser agent's instructions |
| `workflows/ghidra-rce-hunt.js` | route → decompile → hunt → **refute** → roundup |

## The funnel

```
discover   ext id  ->  host names + call sites + acquisition leads   (local)
fetch      url     ->  installer in quarantine                        (net)
unpack     ---     ->  recursive extract, never execute               (local)
link       ---     ->  NM manifest whose allowed_origins == this ext  (local)
triage     ---     ->  format / imports / opcode correlation          (local)
report     ---     ->  research packet
```

State accumulates in `<root>/<ext_id>/hunt.json`; every stage is re-runnable and
only overwrites its own section. **Nothing is ever executed — unpack only.**

```bash
export NATIVE_HOST_ROOT=/big/disk/native-hosts   # quarantine, not your repo
export EXTENSION_ROOT=/path/to/extensions        # {id}/{version}/extension/extracted

python3 scripts/native_host_hunt.py discover <EXT_ID>
python3 scripts/native_host_hunt.py fetch    <EXT_ID> --url '<installer url>'
python3 scripts/native_host_hunt.py unpack   <EXT_ID>
python3 scripts/native_host_hunt.py link     <EXT_ID>
python3 scripts/native_host_hunt.py triage   <EXT_ID>
python3 scripts/native_host_hunt.py report   <EXT_ID>
```

Needs `7z`, `innoextract`, `dpkg-deb`, `binwalk`, `file`, `objdump`, `curl`.

## What the agent is for

Steps 0 and 3–5 are mechanical. **Step 2 — actually finding the installer — is
the part no script can do**, and it's where the hunt succeeds or fails. The
prompt encodes an acquisition ladder that came out of running this at scale:

- the extension's own "install our helper app" URLs
- the host name searched **verbatim in quotes** — highest-signal query available
- `"chrome-extension://<id>/"` verbatim, which finds NM manifests published anywhere
- the vendor's download page **in the vendor's language**, and the vendor's *other* hostnames
- package repos: winget, Chocolatey, Homebrew, GitHub Releases, npm, PyPI
- **downstream of a licensee** — public container images, npm re-publishes,
  partner repos, archive.org. For licence-gated enterprise software this is
  usually the winning rung, not a fallback
- the Internet Archive's `id_/` raw-bytes form

## Things that turned out to matter

Each of these came from a hunt going wrong first.

- **A stub is not the deliverable.** Registered hosts are routinely a `.bat`,
  a shell script, or an apphost shim. Report the stub *and* the real compiled
  executable behind it. If the host is a launcher, the attack surface is often
  the local service it starts, not the host itself.
- **"Can this host prompt the user?" is one command.** `objdump -p | grep "DLL Name"`
  — a host that imports no UI library cannot show a consent dialog before it
  signs or creates a key. For .NET read managed AssemblyRefs instead; `objdump`
  only ever shows `mscoree.dll`.
- **Vendor download links fail often** — roughly one in three. HTML
  interstitials saved as `.exe`, advertised MSIs that are megabytes of null
  bytes, links to repos that no longer exist. Check `file(1)` and the unpacked
  byte count, then re-ladder.
- **No NM manifest sometimes means no manifest exists**, because the installer
  generates it at install time. Prove the counterparty from the wire protocol
  instead, and enumerate the matching strings.
- **Extension count ≠ host count.** One host commonly serves many extensions —
  the shared host is the finding. Dedupe by host name before sizing any sweep.
- **Comments and dead code lie.** A host name in a commented-out assignment
  will send a hunter after a binary that was never built; a scary `FIXME` may
  sit above a check the vendor later implemented properly. Verify against the
  shipped build.

## Stage 2: hunting the chain

Stage 1 ends with a binary on disk. Stage 2 asks whether a **web page** can
reach code execution through it — the shape being:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H   = 9.6
page  ->  content script  ->  background  ->  native host  ->  OS
```

`S:C` is the load-bearing metric. The browser sandbox is the vulnerable
component and the OS is the impacted one; that scope change is what separates
this from an ordinary extension bug. A finding that stops inside the browser is
not this class, and the prompt says so explicitly rather than leaving room to
stretch the vector afterwards.

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra

python3 scripts/ghidra_decompile.py route   <BINARY>          # which tool?
python3 scripts/ghidra_decompile.py analyze <BINARY> --out X  # unmanaged only
python3 scripts/ghidra_decompile.py sinks   X                 # what to read first
```

`route` refuses to send managed binaries to Ghidra. A .NET host decompiles to
near-source in ILSpy and a jar in CFR; Ghidra would only show you the CLR stub
and waste an hour. In practice a large share of native hosts turn out to be
.NET, Java or Node — the ones that *are* unmanaged C++ are the minority that
actually needs a disassembler.

The headless export gives the agent three things: decompiled C for every
function within six calls of an OS sink, a sink call graph ranked by distance,
and the string table with cross-references. It reads C, not disassembly.

**The workflow makes claims argue for their life.** Every `rce` verdict goes to
three independent refuters — one on reachability, one on whether the sink is
real, one on the consent gate — each told to default to *refuted* when unsure.
Two refutations downgrade the verdict rather than deleting it, because the
chain is often still a genuine lower-impact finding. The roundup keeps a
"Downgraded" section on purpose: which lens killed which claim is the part
worth reading for calibration.

## Scope

Published as the *method*. Findings, target lists and vendor-specific results
are deliberately not included — those belong in coordinated disclosure, not a
public repo.

Use it only against software you're authorised to analyse.
