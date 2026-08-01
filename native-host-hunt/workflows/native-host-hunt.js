export const meta = {
  name: 'native-host-hunt',
  description:
    'Extension ID in, native host binary out: one hunter agent per extension finds the host name, acquires the vendor installer, unpacks it, proves the extension↔binary link, and triages the binary for the reverser.',
  whenToUse:
    'Native-messaging RCE research. Pass {ids:["<ext_id>",...]} or {csv:"targets.csv"} (reads the id column). Optional: {model, limit, hosts:{ext_id:"com.vendor.host"}}. Each hunt is independent — no barriers, no shared state.',
  phases: [
    { title: 'Hunt', detail: 'one acquisition agent per extension' },
    { title: 'Roundup', detail: 'index every packet, rank what is ready to reverse' },
  ],
}

const repo = '<repo>'
const parsedArgs = typeof args === 'string' ? JSON.parse(args) : args || {}
const model = parsedArgs.model || 'sonnet'
const knownHosts = parsedArgs.hosts || {}

let ids = parsedArgs.ids || []
if (!ids.length && parsedArgs.csv) {
  // Caller passes rows it already read; the workflow sandbox has no filesystem.
  ids = (parsedArgs.rows || []).map((r) => (typeof r === 'string' ? r : r.id)).filter(Boolean)
}
if (parsedArgs.limit) ids = ids.slice(0, parsedArgs.limit)

if (!ids.length) {
  log('no extension ids passed — pass {ids:[...]}')
  return { hunted: 0 }
}

const HUNT_SCHEMA = {
  type: 'object',
  additionalProperties: true,
  required: ['ext_id', 'status'],
  properties: {
    ext_id: { type: 'string' },
    status: { type: 'string', enum: ['found', 'partial', 'blocked'] },
    host_names: { type: 'array', items: { type: 'string' } },
    host_confidence: { type: 'string' },
    reachable_from: { type: 'string' },
    reachability_note: { type: 'string' },
    installer: {
      type: 'object',
      additionalProperties: true,
      properties: {
        url: { type: 'string' },
        sha256: { type: 'string' },
        source: { type: 'string' },
      },
    },
    link_proof: { type: 'string' },
    binaries: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: true,
        properties: {
          path: { type: 'string' },
          sha256: { type: 'string' },
          format: { type: 'string' },
          why: { type: 'string' },
        },
      },
    },
    next_step: { type: 'string' },
    blockers: { type: 'array', items: { type: 'string' } },
    report: { type: 'string' },
  },
}

phase('Hunt')
const hunts = await parallel(
  ids.map((id) => () =>
    agent(
      [
        `Hunt the native host binary for extension \`${id}\`.`,
        knownHosts[id] ? `A previous pass recorded the host name as \`${knownHosts[id]}\` — verify it, don't assume it.` : '',
        `Read and follow the instructions at ${repo}/scripts/prompts/native_host_hunt.md verbatim.`,
        `Run from ${repo} with the venv active (\`source venv/bin/activate\`).`,
        `You have web search and fetch — Step 2 (finding the installer) is the part that actually needs you.`,
        `Never execute a downloaded installer. Unpack only.`,
        `Return the JSON result object from Step 6.`,
      ]
        .filter(Boolean)
        .join('\n'),
      { label: `hunt:${id.slice(0, 10)}`, phase: 'Hunt', schema: HUNT_SCHEMA, model },
    ),
  ),
)

const ok = hunts.filter(Boolean)
const found = ok.filter((h) => h.status === 'found')
const partial = ok.filter((h) => h.status === 'partial')
const blocked = ok.filter((h) => h.status === 'blocked')
log(
  `hunt complete: ${ok.length}/${ids.length} agents returned — ` +
    `${found.length} found, ${partial.length} partial, ${blocked.length} blocked`,
)

// A binary that any web page can reach is the one worth reversing first.
const rank = (h) =>
  (h.status === 'found' ? 0 : h.status === 'partial' ? 1 : 2) * 10 +
  (h.reachable_from === 'any web page' ? 0 : 1)
const ranked = [...ok].sort((a, b) => rank(a) - rank(b))

phase('Roundup')
const roundup = await agent(
  [
    `Write the roundup index for a native-host hunt batch. Work from ${repo}.`,
    `Here are the per-extension results as JSON:`,
    '',
    JSON.stringify(ranked, null, 2),
    '',
    `Write <quarantine-root>/ROUNDUP.md containing:`,
    `1) A table: extension id, host name, status, reachable_from, binary format, link proof.`,
    `2) A "reverse these first" section — the found+any-web-page-reachable ones, with the next_step for each.`,
    `3) A "blocked" section grouped by blocker type, so the pattern is visible (licence portals vs dead vendors vs region-locked).`,
    `Do not re-run any hunts. Do not invent data not present in the JSON.`,
    `Return one line: counts by status and the path you wrote.`,
  ].join('\n'),
  { label: 'roundup', phase: 'Roundup', model },
)

return {
  hunted: ids.length,
  agents_returned: ok.length,
  found: found.length,
  partial: partial.length,
  blocked: blocked.length,
  ready_to_reverse: found.filter((h) => h.reachable_from === 'any web page').map((h) => h.ext_id),
  results: ranked,
  roundup,
}
