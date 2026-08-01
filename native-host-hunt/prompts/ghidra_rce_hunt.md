# Native Host RCE Hunt — Subagent Prompt Template

Stage 2. Stage 1 (`native_host_hunt.md`) put a native host binary on disk and
proved it is the counterparty of a specific browser extension. Your job is to
find whether a **web page** can reach code execution through it.

## The target shape

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H   = 9.6
```

Read that vector as a description of the bug you are looking for, not as a
score to justify afterwards:

| metric | what it means here |
|---|---|
| `AV:N` | the trigger is a web page the victim visits |
| `AC:L` | no race, no grooming, no per-target setup |
| `PR:N` | the attacker has no account and no local foothold |
| `UI:R` | the victim visits a page (or clicks once) — nothing more |
| `S:C` | **the scope change is the whole point**: the browser sandbox is the vulnerable component, the OS is the impacted one |
| `C:H/I:H/A:H` | arbitrary code as the logged-in user |

`S:C` is what separates this class from ordinary extension bugs. If your finding
stops at "the page can read data the extension holds", that is not this. The
claim is: *page → extension → native host → code execution outside the browser*.

Anything that needs the user to install something extra, accept a prompt they'd
recognise as dangerous, or already be authenticated to the attacker, is a lower
score. Say so plainly rather than stretching the vector.

## Inputs the caller gives you

- `EXT_ID` and the Stage 1 packet (`REPORT.md`, `BRIEF.md`) — read both first.
  The reachability trace and the wire protocol are already written down; do not
  re-derive them.
- `BINARY` — the host binary, and its format from Stage 1 triage.
- `DECOMP_DIR` — Ghidra headless output, if the binary is unmanaged.

## Step 0 — Route by format before opening a disassembler

Reversing a managed binary in Ghidra is wasted effort.

| format | tool | note |
|---|---|---|
| .NET (`mscoree.dll` import) | **ILSpy / dnSpy / `ilspycmd`** | near-source; check for shipped PDBs, they give original names |
| Java (`.jar`) | **CFR / procyon / `jd-cli`** | near-source |
| Electron / Node | unpack `app.asar` | it's just JavaScript |
| PyInstaller | `pyinstxtractor` + `decompyle3` | recovers `.py` |
| Go | Ghidra + a Go symbol restorer | |
| unmanaged C/C++ (PE/ELF/Mach-O) | **Ghidra headless** | what `ghidra_decompile.py` is for |
| packed (UPX) | unpack first | |

If the vendor shipped source, symbols, a PDB, or an unstripped sibling build for
another OS, **read that instead** and map it onto the shipped binary. A
cross-platform vendor often strips the Windows build and ships the Linux one
with full DWARF.

## Step 1 — Find the message loop

Native messaging has a fixed wire format: a **4-byte little-endian length
prefix** on stdin, then that many bytes of UTF-8 JSON. So the entry point is
always a function that reads 4 bytes from stdin/fd 0 and then reads N more.

In `DECOMP_DIR`, look for:

- reads of `stdin` / `GetStdHandle(STD_INPUT_HANDLE)` / `ReadFile` / `fread` / `read(0, …)`
- a length variable used as a `malloc`/`new` size immediately after a 4-byte read
- JSON library strings (`jsonxx`, `nlohmann`, `RapidJSON`, `JSON4J`, `Newtonsoft`)

`ghidra_decompile.py sinks` reports candidate entry functions; verify by reading
the decompilation, don't trust the heuristic.

## Step 2 — Recover the dispatcher and the opcode table

Immediately downstream of the loop there is a dispatcher: a string compare
chain, a hash switch, a map lookup, or a factory keyed on a `type`/`cmd`/
`method`/`action` field.

Cross-reference it against **the opcodes Stage 1 recovered from the extension**.
Those are the messages that are definitely sendable. Opcodes present in the
binary but absent from the extension are *more* interesting, not less: they are
reachable by anyone who can post to the host and were never meant to be driven
from a page.

Produce a table: opcode → handler function → what the handler does with each
field of the message.

## Step 3 — Taint, from message field to sink

For every handler, trace each attacker-controlled field to a sink. The sinks
that produce `C:H/I:H/A:H`:

**Direct execution** — `CreateProcess*`, `ShellExecute*`, `WinExec`, `system`,
`popen`, `_wsystem`, `execve`, `posix_spawn`, `.NET Process.Start`,
`Runtime.exec`, `child_process.exec`.

**Indirect execution** — a file write the attacker controls the *path* of
(startup folder, a DLL next to an exe the host later loads, a `.lnk`, a script
the app runs later); `LoadLibrary`/`dlopen` on an attacker-influenced path;
registry writes to a Run key or a shell-open verb; an installer/updater path
that fetches and runs code.

**Argument injection**, which is not the same as command injection: the program
is fixed but the attacker appends argv. Whether that reaches execution depends
entirely on what the target program does with its arguments — check, don't
assume. Note that `shell=False` with a *string* command line on Windows still
lets the attacker add arguments, but not metacharacters.

For each candidate, write down: the exact field, the transformation applied to
it (quoting? escaping? canonicalisation? a whitelist?), and why that
transformation is insufficient.

## Step 4 — Prove reachability, then check the gate

Two questions decide whether this is a 9.6 or a footnote:

1. **Can a page actually send this message?** Go back to the Stage 1
   reachability trace. `any web page` (a content script on a broad match
   pattern relaying without an origin check) is the 9.6 case. `listed origins
   only` means the attacker needs one of those origins — usually a lower score
   unless the list is absurd (a bare `localhost`, a `*://` pattern, a
   subdomain-takeover candidate).
2. **Is there a consent step on this path, and does it fire?** Check for it in
   the binary, not in the documentation:
   - does the host import a UI library at all? (a host that imports none cannot
     prompt — for .NET read managed AssemblyRefs, `objdump` shows only `mscoree`)
   - is the dialog on *this* code path, or only on a neighbouring one?
   - is the check present but dead — commented out, behind a build flag, an
     exception type absent from the shipped RTTI, or a per-process invariant in
     a host that is spawned fresh per message?
   - can the page suppress it (an `askPin: false`-style field, a cached consent,
     an origin allowlist the page's own origin satisfies)?

A prompt the *attacker's page* renders is not consent. A prompt that doesn't
name the requesting origin is weak consent — say so and score accordingly.

## Step 5 — Write the trigger

State the concrete message that reaches the sink:

```js
// on any page the content script matches
window.postMessage({ src: 'page.js', cmd: '<opcode>', args: [...] }, '*')
```

You are not required to run it — Stage 2 is static. But if you cannot write it
down, you have not finished the analysis. If a field's encoding is unclear
(base64? zip? UTF-16?), say which and why.

## Rules

- **Never execute the host or the installer.** Static analysis only. If a
  finding genuinely needs execution to confirm, say so and hand it to dynamic
  analysis.
- **Do not inflate.** A file write with no path control is not RCE. A signing
  oracle is not RCE. Both may still be serious — report them at what they are.
  A confirmed `S:U` high beats an imagined `S:C` critical.
- **Cite offsets and file:line.** `FUN_00401704` / `RequestHandler.cpp:161` /
  `worker.js:188`. A finding nobody can re-locate is not reviewable.
- **Say what you could not determine.** Obfuscated strings, an unresolved
  indirect call, a handler you ran out of time on — an explicit gap is useful;
  silence is not.

## Return

Return **only** this JSON object:

```json
{
  "ext_id": "...",
  "binary": "...",
  "verdict": "rce | code-exec-gated | lower-impact | none",
  "cvss": {
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "score": 9.6,
    "justification": "one sentence per metric that is not the obvious default"
  },
  "chain": [
    {"stage": "page",      "detail": "postMessage {...} on any http/https page"},
    {"stage": "extension", "detail": "content-script relay, file:line, origin check present/absent"},
    {"stage": "host",      "detail": "dispatcher FUN_xxx -> handler FUN_yyy"},
    {"stage": "sink",      "detail": "CreateProcessW at 0x... with argv from msg.field"}
  ],
  "gate": "none | dialog-not-on-path | dialog-suppressible-by-caller | dialog-fires",
  "trigger": "the literal message that reaches the sink",
  "confidence": "confirmed-static | plausible-needs-dynamic",
  "unknowns": ["..."],
  "writeup": "<path to the appended analysis>"
}
```

`verdict` values:

- `rce` — attacker-controlled input reaches an execution sink, the path is
  page-reachable, and no effective consent gate stands in the way.
- `code-exec-gated` — the sink is reachable but a real consent step fires, or
  the reachable origin set is narrow.
- `lower-impact` — file read/write, signing oracle, information disclosure. Say
  what it is and score it honestly.
- `none` — no attacker-controlled path to a sink was found. Say what you ruled
  out, so the next person doesn't repeat it.
