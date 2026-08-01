# Native Host Hunt — Subagent Prompt Template

Goal: **extension ID in, native host binary out.** You are the acquisition half
of native-messaging research. Someone else reverses the binary; your job is to
put the right binary in front of them, prove it is the right one, and describe
the attack surface it exposes.

## Spawn prompt — caller inlines the ID, nothing else

```
Hunt the native host binary for extension `{EXT_ID}`{, host `{HOST_NAME}` if known}.
Read instructions at <repo>/prompts/native_host_hunt.md
Return ONLY the JSON result object described in Step 6.
```

---

## Ground rules

- **Authorised research only.** These are vendor-shipped, publicly downloadable
  desktop installers, acquired for vulnerability research and coordinated
  disclosure.
- **Never execute anything you download.** No installer, no `.exe`, no `.msi`,
  no post-install script, not even in a sandbox. Unpack only.
- **Everything lands in the quarantine tree**, never in the repo.
- **Report what you actually did.** A blocked hunt reported honestly is worth
  more than a plausible guess. Never claim you found a binary you didn't open.

---

## Step 0 — Recon card

```bash
python3 scripts/native_host_hunt.py discover {EXT_ID}
```

Resolves the extension on disk (downloading + deobfuscating if needed), pulls
the native host name out of the JS, and writes `BRIEF.md` with the host name(s)
and every `connectNative` / `sendNativeMessage` call site; the reachability
surface (content-script matches, `externally_connectable`, host permissions);
**acquisition leads** — every URL in the extension that smells like a download
page; candidate wire opcodes.

Read `BRIEF.md` in full before doing anything else.

The host name is a *lead*. `discover` reports a confidence: `literal` (string
at the call site — trust it), `resolved` (bound from a variable in the same
file — verify), `shaped` (host-shaped string in a file that does native
messaging — verify), `literal-odd` (call-site literal that doesn't look like a
host name — read the code).

## Step 1 — Confirm the host and map the reachable path

Open the call sites and answer three questions:

1. **What is the real host name?** If it's computed — assembled from parts, or
   taken from the *message* — say so. A caller-controlled host name is itself a
   finding: it makes the extension a proxy to any host registered on the machine.
2. **What can reach it?** Trace backwards from the native call to the outermost
   entry point: background handler ← `chrome.runtime.onMessage` ← content script
   ← `window.postMessage` / DOM CustomEvent / `onMessageExternal`. Note where
   origin checks exist and where they don't.
3. **What does the wire protocol look like?** The opcodes and message shape.
   You need these in Step 5 to identify handlers in the binary.

Read the actual code. Don't infer the protocol from the recon card's opcode
leads — those are grep noise until you've read the sending code.

## Step 2 — Find the installer

The host binary ships with the vendor's **desktop application**, not with the
extension.

**What you are looking for, precisely:** the vendor's own **installer package**
— a `.msi`, `.exe`, `.pkg`, `.dmg`, `.deb`, or official `.zip` — for
**Windows** unless the product isn't shipped for Windows. A repo of loose
scripts or a source tarball is a fallback to note, not the goal. If both an
installer and a source drop exist, take the installer: it carries the compiled
binary, the NM manifest, and the registry writes.

0. **Check the extension itself first.** If `discover` printed a
   `BUNDLED EXECUTABLE` line, the vendor shipped the host *inside the CRX*
   (it happens). Copy it out and skip to Step 4.
1. **The extension's own leads.** `BRIEF.md` URLs plus the store listing and
   homepage. Extensions needing a helper app almost always link to its download
   page. Fetch the page and pull the real file URL out of it.
2. **Search the host name verbatim**, in quotes. Highest-signal query in the
   whole hunt: it surfaces vendor support docs, admin/deployment guides, repos
   with the NM manifest committed, and threads naming the install path.
3. **Search the extension ID verbatim**: `"chrome-extension://{EXT_ID}/"`. Any
   NM manifest published anywhere contains exactly that string in
   `allowed_origins`.
4. **Vendor download page.** Many of these vendors are regional PKI,
   e-signature or banking suppliers — **search in the vendor's language**. The
   English page often doesn't exist; the local one has a direct link. Also try
   the vendor's *other* hostnames: a dead `downloads.` host does not mean the
   file is gone.
5. **Package repositories**, which give a versioned direct URL with no sign-up:
   winget (`microsoft/winget-pkgs` manifests), Chocolatey, Homebrew casks,
   GitHub Releases, Linux vendor `.deb`/`.rpm` repos, and **npm / PyPI** for
   hosts written in Node or Python. A `.deb` of the same product is worth
   grabbing even when targeting Windows: vendors routinely ship the Linux host
   as readable source.
6. **Downstream of a licensee.** For enterprise software behind a licence
   portal this is usually the winning rung, not a fallback:
   - **Public container images** — Docker Hub, GHCR, Quay. Licensed enterprise
     suites get published as images with the whole install tree inside; you can
     pull a single layer over HTTP.
   - **npm / PyPI re-publishes** — a licensee vendoring a product's asset tree,
     installer included.
   - **Partner and integrator repos** — resellers publish deployment bundles.
   - **archive.org uploads.**
   Check Authenticode/GPG signatures on anything from here: a valid vendor
   signature means the bytes are genuine even when the host isn't.
7. **Internet Archive**, when the vendor's URL is dead but was once live:
   `web.archive.org/web/<timestamp>id_/<original url>` returns raw bytes.
   Record that the copy is archival and note the version you got.
8. **Last resort:** third-party mirrors. Mark clearly as untrusted-origin.

**Blockers to recognise early:** login/licence-gated enterprise portals,
software behind a customer portal, region-locked or citizen-login downloads.
If two rungs in a row hit a wall, return `status: "blocked"` with what you
tried. Don't burn twenty tool calls on a gated vendor — but do try rung 6
before giving up, because that is where gated software usually leaks.

## Step 3 — Fetch and unpack

```bash
python3 scripts/native_host_hunt.py fetch  {EXT_ID} --url '<direct file url>'
python3 scripts/native_host_hunt.py unpack {EXT_ID}
```

**Always read the `file` type and the unpacked byte count before moving on.**
Roughly a third of vendor download links do not serve an installer:

- `HTML document` — an interstitial or login redirect.
- `data` / `unpack: 0 B` — one vendor's advertised MSI was 30 MB of null bytes.
- 404 — extensions pointing at repos that no longer exist.

None of these mean the tooling failed. **Go back to Step 2 and take the next
rung**, and say in the report which link was bad and how you routed round it.

## Step 4 — Prove the link

```bash
python3 scripts/native_host_hunt.py link {EXT_ID}
```

Looks for the **native messaging manifest** inside the unpacked tree — a small
JSON with `name`, `path`, `type: "stdio"`, `allowed_origins`. If
`allowed_origins` contains `chrome-extension://{EXT_ID}/`, you have proof this
package is the counterparty, and its `path` names the binary.

Fallbacks when no manifest ships (common — many installers write it at install
time or register it in the registry):

- `link` also greps the tree for the host-name string.
- Look for the manifest *template* (`.json.in`, files under `resources/`, or a
  string containing `allowed_origins` inside the installer script).
- Check registry keys an MSI writes:
  `SOFTWARE\Google\Chrome\NativeMessagingHosts\<host name>`.
- Look for an executable whose name matches the host.

**`protocol-match` — when no manifest exists to find.** Some vendors generate
the manifest at install time from a config key, so no package contains one and
`link` returns 0 *by design*. That is not a failed hunt: prove the counterparty
from the wire protocol instead — the binary contains the extension's exact
message envelope, opcode vocabulary, and field names. Enumerate the matching
strings in the report; "seems like the right vendor" is not evidence.

## Step 5 — Triage the binary

```bash
python3 scripts/native_host_hunt.py triage {EXT_ID}
```

Reports format/arch, sha256, packer/runtime, dangerous-sink imports, and which
of the extension's opcodes appear as strings in the binary. Opcode overlap is
strong confirmation you have the right file.

Then look yourself:

**Can this host prompt the user at all?** Run
`objdump -p <binary> | grep "DLL Name"` on every host binary. A native host
that imports no UI library cannot show a consent dialog before it signs,
creates a key, or installs a certificate — that turns "is the user asked?" into
a one-command test instead of a reversing session. It rules good news in as
well as bad news out.

*Caveat — managed binaries.* For .NET, `objdump -p` shows only `mscoree.dll`,
so the PE import table can't answer this. Read the **managed AssemblyRefs**
instead (ILSpy, `monodis --assemblyref`): no `System.Windows.Forms` /
`System.Drawing` means no UI is reachable. Same logic for Java
(`javax.swing`/`java.awt`) and Qt/GTK on Linux (`NEEDED` entries).

**A stub is never the deliverable on its own.** If the registered host `path`
is a `.bat`, `.sh`, `.cmd`, a shortcut, or an apphost shim, you have not
finished: name and ship the **real compiled executable** it invokes, with a
sha256 for each.

**If the host is a launcher, the host is not the attack surface.** When the
registered host is a stub whose body just starts a service, the real surface is
whatever it starts — find the listening port and the local API behind it. That
daemon is usually a loopback HTTP server, so note both whether it authenticates
*and* what CORS headers it sets: with no CORS a page still gets its request
executed, it just can't read the reply, which makes blind state-changing calls
the risk to chase rather than data theft.

**Windows is the analysis target.** When a vendor ships several platforms, the
Windows build is the required one — cite the Linux or macOS build only as a
*secondary* aid (unstripped symbols, shipped source), never a substitute. If
only a non-Windows build could be acquired, that's a `partial`, not a `found`.

Other things worth answering: is it managed (.NET / Java / Electron / Python)
and therefore decompilable rather than disassembly-only? Does it read stdin
with a 4-byte little-endian length prefix (that's the native messaging loop —
the dispatcher is next to it)? Which sinks does it reach, and which opcode
plausibly reaches each? Does it run elevated, as a service, or with a
privileged helper?

## Step 6 — Report and return

```bash
python3 scripts/native_host_hunt.py report {EXT_ID}
```

Then **append your own analysis** to `REPORT.md` — the generated file is
scaffolding; the value is your Step 1 reachability trace, the protocol
description, and your read of the binary. Be concrete: file:line for the
extension side, function/offset for the native side.

Return **only** this JSON object as your final message:

```json
{
  "ext_id": "...",
  "status": "found | partial | blocked",
  "host_names": ["com.vendor.host"],
  "host_confidence": "literal | resolved | computed-at-runtime",
  "reachable_from": "any web page | listed origins only | vendor pages only | extension UI only | unknown",
  "reachability_note": "one sentence: the path from a page to the native call",
  "installer": {"url": "...", "sha256": "...", "source": "vendor | winget | container | npm | mirror | none"},
  "link_proof": "nm-manifest-allowed-origins | host-string-embedded | registry-key | protocol-match | none",
  "binaries": [{"path": "...", "sha256": "...", "format": "PE32+ / .NET / Electron / ELF", "why": "..."}],
  "next_step": "what the reverser should open first",
  "blockers": ["..."],
  "report": "<path to REPORT.md>"
}
```

`reachable_from` — Chrome enforces `externally_connectable` regardless of what
the handler does, so a commented-out sender check inside `onMessageExternal` is
**`listed origins only`**, not `any web page`. Say `any web page` only when a
content script on a broad match pattern relays to the native call. Put the
nuance in `reachability_note` either way, but get the enum right — it's the
field people skim. A `*://` pattern or a `localhost` entry in the list is worth
calling out: both widen a "restricted" surface considerably.

`status` rules — be strict, the whole point is that the next person can trust it:

- `found` — a binary is on disk **and** linked to this extension by Step 4.
- `partial` — installer acquired but the link is unproven, or only a
  non-Windows build could be obtained.
- `blocked` — no publicly reachable installer. Fill `blockers` with the
  specific walls you hit.

Do not pad the JSON with prose and do not return the report body — the caller
reads the file.
