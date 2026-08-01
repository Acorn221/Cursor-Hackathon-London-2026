export const meta = {
  name: 'ghidra-rce-hunt',
  description:
    'Stage 2: decompile each acquired native host (Ghidra for unmanaged, the right tool for managed) and hunt the page -> extension -> host -> code-execution chain that scores CVSS 9.6.',
  whenToUse:
    'After native-host-hunt has binaries on disk. Pass {items:[{ext_id, binary, format, report}]}. Optional: {model, requireSecondOpinion:true}. Each binary is independent — no barriers until the roundup.',
  phases: [
    { title: 'Route', detail: 'pick the decompiler per binary; Ghidra only for unmanaged' },
    { title: 'Decompile', detail: 'headless export: decomp C, sink call graph, strings' },
    { title: 'Hunt', detail: 'one reverser agent per binary, taint message field -> sink' },
    { title: 'Refute', detail: 'adversarial second pass on every claimed RCE' },
    { title: 'Roundup', detail: 'rank confirmed chains, write the index' },
  ],
}

const repo = process.env.NHH_REPO || '<repo>'
const parsedArgs = typeof args === 'string' ? JSON.parse(args) : args || {}
const items = parsedArgs.items || []
const model = parsedArgs.model || 'sonnet'
// An RCE claim is expensive to be wrong about — default to making someone argue against it.
const requireSecondOpinion = parsedArgs.requireSecondOpinion !== false

if (!items.length) {
  log('no binaries passed — pass {items:[{ext_id, binary, format, report}]}')
  return { hunted: 0 }
}

const HUNT_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['ext_id', 'binary', 'verdict'],
  properties: {
    ext_id: { type: 'string' },
    binary: { type: 'string' },
    verdict: { type: 'string', enum: ['rce', 'code-exec-gated', 'lower-impact', 'none'] },
    cvss: {
      type: 'object',
      additionalProperties: true,
      properties: {
        vector: { type: 'string' },
        score: { type: 'number' },
        justification: { type: 'string' },
      },
    },
    chain: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
        properties: { stage: { type: 'string' }, detail: { type: 'string' } },
      },
    },
    gate: { type: 'string' },
    trigger: { type: 'string' },
    confidence: { type: 'string' },
    unknowns: { type: 'array', items: { type: 'string' } },
    writeup: { type: 'string' },
  },
}

const REFUTE_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['refuted', 'reason'],
  properties: {
    refuted: { type: 'boolean' },
    reason: { type: 'string' },
    // Which link in the chain is weakest, so a survivor still says where to look.
    weakest_link: { type: 'string' },
    corrected_verdict: { type: 'string' },
  },
}

// Managed binaries decompile to near-source; sending them to Ghidra wastes an
// hour and produces worse output than ilspycmd or cfr.
const MANAGED = ['dotnet', 'jar', 'java', 'electron', 'pyinstaller', 'script']
const needsGhidra = (it) => !MANAGED.includes((it.format || '').toLowerCase())

phase('Route')
log(
  `${items.length} binaries: ` +
    `${items.filter(needsGhidra).length} to Ghidra, ` +
    `${items.filter((i) => !needsGhidra(i)).length} to a managed decompiler`,
)

const results = await pipeline(
  items,

  // --- Decompile ---------------------------------------------------------
  async (it) => {
    if (!needsGhidra(it)) {
      return { ...it, decompDir: null, note: `managed (${it.format}) — agent decompiles directly` }
    }
    const out = `${it.binary}.ghidra`
    const r = await agent(
      [
        `Run the Stage 2 decompile for \`${it.ext_id}\`.`,
        `cd ${repo} && python3 scripts/ghidra_decompile.py analyze '${it.binary}' --out '${out}'`,
        `Then: python3 scripts/ghidra_decompile.py sinks '${out}'`,
        `Do not analyse anything yet. Report only whether the export succeeded,`,
        `how many functions were decompiled, and the top sink rows.`,
        `If ghidra_decompile.py refuses because the binary is managed, say so —`,
        `that is a correct refusal, not a failure.`,
      ].join('\n'),
      { label: `decomp:${it.ext_id.slice(0, 10)}`, phase: 'Decompile', model },
    )
    return { ...it, decompDir: out, decompNote: r }
  },

  // --- Hunt --------------------------------------------------------------
  async (prev) => {
    if (!prev) return null
    const r = await agent(
      [
        `Hunt for a page-reachable RCE chain through the native host of extension \`${prev.ext_id}\`.`,
        `BINARY=${prev.binary}`,
        `FORMAT=${prev.format || 'unknown'}`,
        prev.decompDir ? `DECOMP_DIR=${prev.decompDir}` : `This binary is managed — decompile it with the right tool (see Step 0).`,
        prev.report ? `Stage 1 packet: ${prev.report} — read it first, do not re-derive the reachability trace.` : '',
        `Read and follow ${repo}/prompts/ghidra_rce_hunt.md verbatim.`,
        `Static analysis only. Never execute the host or its installer.`,
        `Return the Step 6 JSON.`,
      ]
        .filter(Boolean)
        .join('\n'),
      { label: `hunt:${prev.ext_id.slice(0, 10)}`, phase: 'Hunt', schema: HUNT_SCHEMA, model },
    )
    return r ? { ...r, format: prev.format, decompDir: prev.decompDir } : null
  },

  // --- Refute ------------------------------------------------------------
  // Only claimed RCE gets the adversarial pass; a "none" verdict costs nothing
  // to be wrong about in the pessimistic direction.
  async (hit) => {
    if (!hit) return null
    if (!requireSecondOpinion || hit.verdict !== 'rce') return hit

    const votes = await parallel(
      ['reachability', 'sink-reality', 'consent-gate'].map((lens) => () =>
        agent(
          [
            `Try to REFUTE this claimed RCE. Default to refuted=true if you are unsure.`,
            `Lens: ${lens}.`,
            lens === 'reachability'
              ? `Can a page actually deliver this message? Check externally_connectable, the content-script match patterns, and whether the relay really lacks an origin check. Chrome enforces externally_connectable regardless of what the handler does.`
              : lens === 'sink-reality'
                ? `Does attacker data actually reach an execution sink? Argument injection is not command injection; a file write with no path control is not RCE; a signing oracle is not RCE.`
                : `Is there a consent step on THIS path that actually fires? Check whether the host can even draw a dialog (imports / managed AssemblyRefs), and whether the page can suppress it.`,
            ``,
            `The claim:`,
            JSON.stringify(hit, null, 2),
            ``,
            `Binary: ${hit.binary}${hit.decompDir ? `  decomp: ${hit.decompDir}` : ''}`,
            `Read the code before answering. Cite what you checked.`,
          ].join('\n'),
          { label: `refute:${lens}:${hit.ext_id.slice(0, 8)}`, phase: 'Refute', schema: REFUTE_SCHEMA, model },
        ),
      ),
    )
    const real = votes.filter(Boolean)
    const refuted = real.filter((v) => v.refuted)
    return {
      ...hit,
      refutation: real,
      survived: refuted.length < 2,
      // A majority refutation downgrades the verdict rather than deleting it —
      // the chain may still be a real lower-impact finding.
      verdict: refuted.length >= 2 ? refuted[0].corrected_verdict || 'lower-impact' : hit.verdict,
    }
  },
)

const ok = results.filter(Boolean)
const rce = ok.filter((r) => r.verdict === 'rce')
const gated = ok.filter((r) => r.verdict === 'code-exec-gated')
log(
  `hunt complete: ${ok.length}/${items.length} returned — ` +
    `${rce.length} RCE (survived refutation), ${gated.length} gated, ` +
    `${ok.filter((r) => r.verdict === 'lower-impact').length} lower-impact, ` +
    `${ok.filter((r) => r.verdict === 'none').length} none`,
)

phase('Roundup')
const roundup = await agent(
  [
    `Write the Stage 2 roundup. Work from ${repo}.`,
    `Per-binary results as JSON:`,
    ``,
    JSON.stringify(ok, null, 2),
    ``,
    `Write RCE-ROUNDUP.md containing:`,
    `1) A table: extension, host binary, verdict, CVSS vector+score, gate, confidence.`,
    `2) "Confirmed chains" — each surviving rce verdict written as page -> extension -> host -> sink,`,
    `   with the literal trigger message and the file:line / offset citations.`,
    `3) "Downgraded" — claims a refuter killed, and which lens killed them. This section is the`,
    `   useful one for calibration; do not omit it.`,
    `4) "Open questions" — every unknowns[] entry, grouped, so the next pass has a work list.`,
    `Do not invent data not present in the JSON. Do not re-score anything.`,
    `Return one line: counts by verdict and the path you wrote.`,
  ].join('\n'),
  { label: 'roundup', phase: 'Roundup', model },
)

return {
  hunted: items.length,
  returned: ok.length,
  rce: rce.length,
  gated: gated.length,
  confirmed: rce.map((r) => ({ ext_id: r.ext_id, score: r.cvss?.score, trigger: r.trigger })),
  results: ok,
  roundup,
}
