# Cursor Hackathon London 2026

## Finding the code nobody reviews

A browser extension that declares `nativeMessaging` is allowed to talk to a
program on your computer. The extension is JavaScript — anyone can read it,
and plenty of people do. The program on the other end is a compiled binary
that ships inside some vendor's desktop installer, and almost nobody reads
that, because finding it is tedious enough that people stop before they start.

That asymmetry is the whole problem. The browser sandbox exists to stop a web
page reaching your operating system. A native messaging host is a deliberate
hole through it. If a page can reach the bridge — and extensions relay page
messages far more often than they should — then the security of your machine
depends on a binary that has had far fewer eyes on it than the extension has.

The gap looks like this:

```
web page  ->  content script  ->  background  ->  native host  ->  OS
              └────────── reviewed ──────────┘   └── rarely reviewed ──┘
```

This repo automates crossing that line.

## What's here

**[`native-host-hunt/`](native-host-hunt/)** — a two-stage agentic pipeline.

**Stage 1: extension ID in, native host binary out.** Resolve the extension,
pull the host name out of its JavaScript, work out which vendor installer
contains the counterpart binary, acquire it, unpack it, and *prove* the link
by finding the native messaging manifest whose `allowed_origins` names that
exact extension.

**Stage 2: is it reachable?** Route the binary to the right decompiler, export
its attack surface, and hunt the chain from a page-controlled message field to
an OS execution sink — the shape that scores
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` = **9.6**.

## Why an agent, and where it actually earns its keep

Most of this is mechanical and belongs in a script: resolving paths, grepping
for `connectNative`, unpacking nested installers, diffing manifests, walking a
call graph. That's `native_host_hunt.py` and `ghidra_decompile.py`, and it's
deterministic on purpose — you don't want a language model deciding whether two
SHA-256s match.

One step is not mechanical: **finding the installer**. It is a research task
with no fixed procedure. The vendor's download page is in another language, or
the link 404s, or it 302s to a login, or the file is only distributed to
licensed customers. Every one of those has a way around it, and the way around
is different every time.

That's the step worth giving to an agent, and the acquisition ladder in the
prompt is the distilled result of running it at scale — including the finding
that for licence-gated enterprise software, the copy is almost never on the
vendor's site. It's in a public container image, an npm re-publish, a partner's
repo, or an archive.org upload, because software that ships to thousands of
customers leaks downstream of at least one of them.

## Design decisions that mattered

Each of these came from getting it wrong first.

**A stub is not a deliverable.** Registered native hosts are routinely a
`.bat`, a shell script, or an apphost shim. Reporting "found the host" and
handing over a batch file is useless; the pipeline insists on naming the real
compiled executable behind it, with a hash for each.

**Refuse to use the wrong tool.** A large share of native hosts turn out to be
.NET, Java or Node, which decompile to near-source. Stage 2 detects that and
*refuses* to run Ghidra on them, rather than producing worse output slowly.

**Make claims argue for their life.** Every claimed RCE faces three independent
refuters — reachability, sink-reality, consent-gate — each instructed to default
to *refuted* when unsure. Two refutations downgrade the finding rather than
deleting it, because the chain is often still a genuine lower-impact bug. The
roundup keeps the downgrades on purpose: which lens killed which claim is the
most useful calibration signal in the whole run.

**Blocked, reported honestly, beats a confident guess.** A wrong binary costs a
reverser a day. The status vocabulary is deliberately strict, and "I could not
get this, here are the eight things I tried" is a first-class outcome.

## Results

Run against a cohort of extensions that expose a native messaging bridge to
web-page-controlled input:

- **27 native host binaries acquired and linked** to their extensions by
  `allowed_origins` proof, embedded host-name strings, or enumerated protocol
  match — across desktop suites, PKI and e-signature clients, enterprise
  document and file-transfer tooling, and hardware-device helpers.
- **Roughly a third of vendor download links did not serve an installer** —
  HTML interstitials saved as `.exe`, an advertised MSI that was 30 MB of null
  bytes, extensions pointing at repos that no longer exist. Recovering from
  that is a first-class part of the pipeline, not an error path.
- **Several shared-code clusters surfaced**, where one upstream project or
  white-label rebuild propagated the same missing origin check into unrelated
  vendors' products in different countries. Extension count badly overstates
  host count; deduplicating by host name is the difference between hunting
  hundreds of binaries and hunting dozens.
- **Consent turned out to be answerable in one command.** A host that imports
  no UI library cannot show a dialog before it signs, creates a key, or
  installs a certificate — so `objdump -p | grep "DLL Name"` (or managed
  AssemblyRefs, for .NET) replaces a reversing session with a one-liner, and
  rules good news in as often as bad news out.

Specific findings, target lists and vendor names are **deliberately not in this
repo**. Several concern unpatched software in production use; they belong in
coordinated disclosure, not a public hackathon submission.

## Getting started

See [`native-host-hunt/README.md`](native-host-hunt/README.md) for the funnel,
the commands, and the environment variables.

Use it only against software you are authorised to analyse. Nothing in this
repo executes a downloaded installer or native host — every stage is
acquisition and static analysis only.
