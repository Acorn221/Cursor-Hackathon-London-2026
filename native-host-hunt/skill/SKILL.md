---
name: native-host-hunt
description: Extension ID in, native host binary out — find the native messaging host name, acquire the vendor's desktop installer, unpack it, prove the extension↔binary link, and triage the binary for reversing. Use when the user says "/native-host-hunt", "find the native host", "get me the host binary", or names extensions for native-messaging RCE research.
---

# /native-host-hunt — acquire the other end of the native messaging bridge

A native-messaging finding is only half a finding until someone reads the host
binary. The extension side is cheap (it's JavaScript on disk); the native side
is the work — the binary ships inside a vendor desktop installer that has to be
found, downloaded, unpacked, and matched back to the extension. This skill does
that at batch scale.

**Inputs:** one or more extension IDs. With no argument, hunt everything in
`targets.txt` that has no packet yet.

## Split of labour

| | |
|---|---|
| `scripts/native_host_hunt.py` | the deterministic tool belt — resolve on disk, grep host names, fetch, unpack, link, triage, report |
| `scripts/prompts/native_host_hunt.md` | the hunter agent's instructions — the judgement half |
| `.claude/workflows/native-host-hunt.js` | fan-out, one hunter per extension, plus a roundup index |

Artifacts land in `<quarantine-root>/{ext_id}/` (storage1 is at 99%).
`BRIEF.md` is the recon card, `REPORT.md` is the research packet, `hunt.json`
is the machine state. Nothing downloaded is ever executed.

## Run it

**Step 1 — prime the local half for the whole batch.** Cheap, deterministic, and
it means every hunter agent starts from a cached recon card instead of racing to
download the same CRX:

```bash
cd <repo> && source venv/bin/activate
while read id; do python3 scripts/native_host_hunt.py discover "$id"; done \
  < <(grep -v '^#' targets.txt | grep -v '^$')
```

Read the output. Extensions reporting `HOST none recovered` compute the host
name at runtime — flag those for the agent, they need a code read, and a
caller-controlled host name is itself a finding.

**Step 2 — fan out the hunters.** One agent per extension, each following
`scripts/prompts/native_host_hunt.md`:

```
Workflow({scriptPath: ".claude/workflows/native-host-hunt.js",
          args: {ids: ["<ext_id>", ...], hosts: {"<ext_id>": "com.vendor.host"}}})
```

`hosts` is optional prior knowledge — the agent is told to verify it, not trust
it. Concurrency is the workflow cap (10 here); the hunts are independent, so
there are no barriers until the roundup.

For a handful of extensions, spawning subagents directly with the same prompt is
equivalent and easier to watch.

**Step 3 — read the roundup.** `<quarantine-root>/ROUNDUP.md` ranks the
batch. Reverse the `found` + "any web page reachable" ones first: those are the
full web→extension→native chains.

## Status vocabulary — hold the line on this

- `found` — binary on disk **and** linked to the extension by an NM manifest
  whose `allowed_origins` names it, or by an embedded host-name string.
- `partial` — installer acquired, link unproven.
- `blocked` — no publicly reachable installer (licence portal, dead vendor,
  region-locked, CD-only). Blocked reported honestly beats a guess; a wrong
  binary wastes a reverser's day.

## Where this fits

Output feeds normal claim submission: once the native side confirms a reachable
sink, file it with `scripts/da claim add <ext_id> --json '{...}'` per
`scripts/agent_prompt_template.md`. The reachability trace in the packet is what
makes the claim testable — it names the page-level entry point that reaches the
native call.
