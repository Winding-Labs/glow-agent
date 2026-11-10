// `npx @winding-labs/glow competitors <product> <file.json>`: send what a Find competitors run found (packages/core
// competitors.ts) to Glow with this computer's key (POST /api/v1/agent/competitors), onto that product. For a brief run
// by hand, in your own Claude Code. A run Glow started here can't use Glow's CLI (the runner denies it, and this refuses
// inside one): its last message carries the same JSON in a ```glow-competitors block, which the runner's report brings.
// The file is JSON (or text holding that block), at most 200 KB; Glow checks every key and URL itself.
import fs from 'node:fs';
import { api, printable, readConfig } from './core.mjs';
import { inRunnerSession } from './runner.mjs';

export const USAGE = 'npx @winding-labs/glow competitors <product id> <file.json>';
const MAX_BYTES = 200_000;
const BLOCK = /```[ \t]*glow-competitors[^\n]*\n([\s\S]*?)```/g;

/** The findings in a file's text: the JSON itself, or the last ```glow-competitors block in it. */
export function findingsIn(text) {
  const last = [...String(text).matchAll(BLOCK)].pop();
  try {
    const x = JSON.parse(last ? last[1] : text);
    return x && typeof x === 'object' && !Array.isArray(x) ? x : null;
  } catch {
    return null;
  }
}

/** Runs it; the exit code. */
export async function competitorsCommand(args, say = console.log, warn = console.error) {
  if (args.some((a) => a === '--help' || a === '-h')) {
    say(`${USAGE}\n\nSends what a Find competitors run found (its JSON) to Glow, onto that product. The product id is in the run's brief.`);
    return 0;
  }
  if (!args.length || args.length > 2) return warn(`Usage: ${USAGE}`), 1;
  const [product, file] = args.length === 2 ? args : [undefined, args[0]];
  if (inRunnerSession()) return warn('✗ Not from a run Glow started: end your last message with the ```glow-competitors block, and Glow reads it when the run ends.'), 1;
  const cfg = readConfig();
  if (!cfg) return warn('✗ This computer isn’t paired with Glow yet: run npx @winding-labs/glow first.'), 1;
  let body = null;
  try {
    const st = fs.statSync(file);
    if (st.isFile() && st.size <= MAX_BYTES) body = findingsIn(fs.readFileSync(file, 'utf8'));
  } catch {
    body = null;
  }
  if (!body) return warn(`✗ ${printable(file, 160)} isn’t a JSON file of findings (at most 200 KB).`), 1;
  if (product) body.product = product;
  if (typeof body.product !== 'string' || !body.product) return warn(`✗ Name the product: ${USAGE}`), 1;
  const r = await api(cfg, 'POST', '/api/v1/agent/competitors', body, 20_000);
  if (r.status === 200 && r.json) {
    const n = Number(r.json.competitors) || 0;
    const dropped = Array.isArray(r.json.dropped) && r.json.dropped.length ? ` (left out, not a site on its own domain: ${r.json.dropped.map((x) => printable(x, 40)).join(', ')})` : '';
    say(`✓ Glow has ${n} competitor${n === 1 ? '' : 's'} for this product now${dropped}.`);
    return 0;
  }
  warn(`✗ Glow didn’t take it${r.json?.error ? `: ${printable(r.json.error, 300)}` : r.status ? ` (${r.status})` : ': it couldn’t be reached'}.`);
  return 1;
}
