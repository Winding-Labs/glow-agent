// The browser a listing run drives: Playwright's MCP server (its command and arguments after this script's), behind
// this filter. Everything it answers passes through with every site password's shape masked first (sites.mjs
// maskShapes), so a page that shows one never puts it in front of the model: a password field's value in a snapshot
// (Playwright's snapshots print it: seen 2026-11-06), a request body, a "your password is" page. What the model sends
// is checked first (sites.mjs browserCall): one JSON message a line, no tool saving to a file the model names, and an
// upload only of the files brand_file wrote (GLOW_UPLOAD_MANIFEST), unchanged. MCP over stdio is one JSON message a
// line, and the shapes have nothing JSON escapes.
import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { browserCall, maskShapes } from './sites.mjs';

const [command, ...args] = process.argv.slice(2);
if (!command) {
  process.stderr.write('sites-browser: no browser server to run\n');
  process.exit(1);
}
const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'] });
child.on('error', () => process.exit(1));
child.stdin.on('error', () => undefined);
const manifest = process.env.GLOW_UPLOAD_MANIFEST ?? '';
readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  .on('line', (line) => {
    if (!line.trim()) return;
    const r = browserCall(line, manifest);
    if (r.forward) child.stdin.write(`${r.forward}\n`);
    else process.stdout.write(`${JSON.stringify(r.reply)}\n`);
  })
  .on('close', () => child.stdin.end());
readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on('line', (line) => process.stdout.write(`${maskShapes(line)}\n`));
child.on('exit', (code) => process.exit(code ?? 0));
for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(sig, () => child.kill(sig));
