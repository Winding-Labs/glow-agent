#!/usr/bin/env node
// npx @winding-labs/glow — pair this computer with Glow and hook the coding agents on it (Claude Code, Codex), so each
// session in a repo linked to a product posts what it did to that product's channel, and Glow can message it back.
//
//   npx @winding-labs/glow                 set up: find the agents, pair (approve in Glow, type the code it shows), add the hooks
//   npx @winding-labs/glow status          what's set up, and the repos that report
//   npx @winding-labs/glow off | on        stop / start sending from this computer
//   npx @winding-labs/glow messages off    stop messages from Glow reaching this computer's agents (on: again)
//   npx @winding-labs/glow uninstall       remove the hooks, revoke this computer's key, delete ~/.glow
import { execFile } from 'node:child_process';
import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AGENTS, detect, install, installed, shimPath, shq, uninstall } from '../lib/agents.mjs';
import { api, apiBase, apiOk, computerName, DEFAULT_API, dir, printable, readConfig, repoOf, VERSION, writeConfig } from '../lib/core.mjs';

const LIB = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'lib');
const tty = process.stdout.isTTY;
const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = (s) => c(1, s);
const dim = (s) => c(2, s);
const ok = (s) => console.log(`${c(32, '✓')} ${s}`);
const warn = (s) => console.log(`${c(33, '!')} ${s}`);
const fail = (s) => {
  console.error(`${c(31, '✗')} ${s}`);
  process.exit(1);
};

const HELP = `Glow ${VERSION}: send what your coding agents do to your Glow channels.

  npx @winding-labs/glow                 set up this computer (finds Claude Code and Codex, pairs with Glow, adds hooks)
  npx @winding-labs/glow status          what's set up and which repos report
  npx @winding-labs/glow off | on        stop or start sending from this computer
  npx @winding-labs/glow messages off    stop messages from Glow reaching your agents here (messages on: again)
  npx @winding-labs/glow uninstall       remove the hooks and revoke this computer's key

Options for setup:
  --claude, --codex   only these agents (default: every one found)
  --new               pair again, as a new computer
  --name <name>       what Glow calls this computer (default: its name)
  --no-open           don't open the browser; print the link
`;

function parse(argv) {
  const o = { cmd: 'install', agents: [], api: DEFAULT_API, dev: false, open: true, fresh: false, name: '', messages: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h' || a === 'help') o.cmd = 'help';
    else if (a === '--version' || a === '-v') o.cmd = 'version';
    else if (a === '--claude') o.agents.push('claude_code');
    else if (a === '--codex') o.agents.push('codex');
    else if (a === '--new') o.fresh = true;
    else if (a === '--no-open') o.open = false;
    else if (a === '--dev') o.dev = true;
    else if (a === '--api') o.api = argv[++i] ?? '';
    else if (a === '--name') o.name = argv[++i] ?? '';
    else if (a === 'messages' && ['on', 'off'].includes(argv[i + 1])) {
      o.cmd = 'messages';
      o.messages = argv[++i] === 'on';
    } else if (['install', 'setup', 'status', 'off', 'on', 'uninstall'].includes(a)) o.cmd = a === 'setup' ? 'install' : a;
    else fail(`Unknown option ${a}. Run npx @winding-labs/glow --help`);
  }
  if (!apiOk(o.api, o.dev)) fail(`${printable(o.api)} isn’t Glow. The API must be https://app.meetglow.ai (or localhost with --dev).`);
  return o;
}

async function main() {
  if (process.platform === 'win32') fail('Glow’s agent hook runs on macOS and Linux for now.');
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 18) fail(`Glow needs Node 18 or newer (this is ${process.version}).`);
  const o = parse(process.argv.slice(2));
  if (o.cmd === 'help') return console.log(HELP);
  if (o.cmd === 'version') return console.log(VERSION);
  if (o.cmd === 'status') return status();
  if (o.cmd === 'off' || o.cmd === 'on') return toggle(o.cmd === 'off');
  if (o.cmd === 'messages') return messages(o.messages);
  if (o.cmd === 'uninstall') return remove();
  return setup(o);
}

// ---------- set up ----------

async function setup(o) {
  console.log(`${bold('Glow')} ${dim(VERSION)}: your coding agents → your Glow channels\n`);
  const found = detect();
  const agents = o.agents.length ? o.agents : found;
  for (const a of o.agents) if (!found.includes(a)) warn(`${AGENTS[a].label} isn’t installed here; adding its hook anyway.`);
  if (!agents.length) fail('No coding agent found (Claude Code or Codex). Install one, then run this again.');
  console.log(`Found: ${agents.map((a) => AGENTS[a].label).join(', ')}`);

  let cfg = readConfig();
  if (cfg && (o.fresh || apiBase(cfg.api) !== apiBase(o.api))) {
    await api(cfg, 'DELETE', '/api/v1/agent/computer', undefined, 5_000);
    cfg = null;
  }
  let info = null;
  if (cfg) {
    const res = await api(cfg, 'GET', '/api/v1/agent/config', undefined, 10_000);
    if (res.status === 200) info = res.json;
    else if (res.status === 401) {
      warn('This computer’s key no longer works (it was removed in Glow). Pairing again.');
      cfg = null;
    } else if (res.status === 403) warn('This computer is paused in Glow. Resume it there (Connections › Coding agents).');
    else if (res.status === 0) fail(`Couldn’t reach ${apiBase(cfg.api)}. Check your connection and try again.`);
  }

  if (!cfg) {
    const paired = await pair(o, agents);
    cfg = { api: apiBase(o.api), ...(o.dev ? { dev: true } : {}), key: paired.key, computer: paired.computer, workspace: paired.workspace, repos: paired.repos, repos_at: Date.now(), agents, version: VERSION };
    writeConfig(cfg);
    info = { computer: { ...paired.computer, paused: false }, workspace: paired.workspace, repos: paired.repos };
    console.log('');
    ok(`Paired ${bold(printable(paired.computer.name))} with ${bold(printable(paired.workspace.name))}`);
  } else {
    ok(`Already paired: ${bold(printable(cfg.computer?.name) || 'this computer')} with ${bold(printable(info?.workspace?.name ?? cfg.workspace?.name) || 'your workspace')}`);
    writeConfig({ ...cfg, agents: [...new Set([...(cfg.agents ?? []), ...agents])], ...(info?.repos ? { repos: info.repos, repos_at: Date.now() } : {}), version: VERSION });
  }

  copyHook();
  for (const a of agents) {
    try {
      const file = install(a);
      ok(`${AGENTS[a].label}: hook added to ${tilde(file)}`);
    } catch (e) {
      warn(`${AGENTS[a].label}: couldn’t update ${tilde(path.join(os.homedir(), ...AGENTS[a].file))} (${e.message}). Fix it, then run this again.`);
    }
  }

  const repos = (info?.repos ?? []).map((r) => printable(r, 160));
  console.log('');
  console.log(repos.length ? `Repos that report to Glow: ${repos.join(', ')}` : 'No repos are linked to a product yet.');
  const here = repoOf(process.cwd());
  if (here && !repos.includes(here)) console.log(`This repo (${here}) isn’t linked. Link it to a product: ${apiBase(cfg.api)}/app/pair?repo=${encodeURIComponent(here)}`);
  console.log('');
  if (agents.includes('claude_code')) console.log(`${bold('Claude Code')}: new sessions in those repos post to Glow when they finish a reply. Restart open sessions to pick it up.`);
  if (agents.includes('codex')) console.log(`${bold('Codex')}: open Codex and run ${bold('/hooks')} once to trust the Glow hook (Codex asks before running any new hook).`);
  console.log(`Messages you send a session from its post in Glow reach that agent${readConfig()?.messages === false ? ' (off here: npx @winding-labs/glow messages on)' : ' (npx @winding-labs/glow messages off to stop that)'}.`);
  console.log(dim('\nOnly sessions in linked repos send anything, and only to Glow. Off: npx @winding-labs/glow off · Remove: npx @winding-labs/glow uninstall'));
}

/** The device flow: show a code, open Glow to approve it, then type the confirmation Glow shows to get the key. */
async function pair(o, agents) {
  const name = (o.name || computerName()).slice(0, 60);
  const repo = repoOf(process.cwd());
  const start = await api({ api: o.api, dev: o.dev }, 'POST', '/api/v1/agent/pairings', { name, agents, ...(repo ? { repo } : {}) }, 15_000);
  if (start.status === 429) fail('Too many pairings from this network. Wait 10 minutes and try again.');
  if (start.status !== 201 || !/^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(start.json?.code ?? '') || typeof start.json?.secret !== 'string') {
    fail(start.status ? `Glow didn’t start the pairing (${start.status}). Try again in a minute.` : `Couldn’t reach ${apiBase(o.api)}. Check your connection and try again.`);
  }
  const { code, secret } = start.json;
  const url = `${apiBase(o.api)}/app/pair?code=${code}`;
  console.log(`\nPair ${bold(name)} with Glow:`);
  console.log(`  1. Open ${c(36, url)}`);
  console.log(`  2. Check it shows ${bold(code)}`);
  console.log('  3. Pick the workspace and approve');
  console.log('  4. Type the 6-digit code Glow then shows you here\n');
  if (o.open) openUrl(url);
  process.stdout.write(dim('Waiting for you to approve in Glow… (Ctrl-C to cancel)'));
  const until = Date.now() + 10 * 60_000;
  const every = Math.min(10, Math.max(2, Number(start.json.interval_s) || 3)) * 1000;
  const claim = (confirm) => api({ api: o.api, dev: o.dev }, 'POST', '/api/v1/agent/pairings/claim', { secret, ...(confirm ? { confirm } : {}) }, 15_000);
  for (;;) {
    if (Date.now() > until) {
      process.stdout.write('\n');
      fail('The code expired. Run npx @winding-labs/glow again for a new one.');
    }
    await new Promise((r) => setTimeout(r, every));
    const res = await claim();
    if (res.status === 202 && res.json?.status === 'confirm') break;
    if (res.status === 404) {
      process.stdout.write('\n');
      fail('The code expired or was turned down. Run npx @winding-labs/glow again for a new one.');
    }
    if (tty) process.stdout.write('.');
  }
  process.stdout.write('\n\n');
  // Only the person who approved sees the confirmation, so a code someone else approved goes nowhere.
  console.log(`Approved in Glow. It now shows a ${bold('6-digit code')}: type it here.`);
  console.log(dim('Didn’t approve it yourself just now? Press Ctrl-C: someone else may have used your code.'));
  // Lines are queued as they come (typed, or piped), so none is lost between one question and the next.
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
  const lines = rl[Symbol.asyncIterator]();
  const ask = async (q) => {
    process.stdout.write(q);
    const r = await lines.next();
    return r.done ? null : String(r.value);
  };
  try {
    for (let asked = 0; asked < 8; asked++) {
      const a = await ask('Code: ');
      if (a === null) fail('No code typed. Run npx @winding-labs/glow again.');
      const digits = a.replace(/\s/g, '');
      if (!/^\d{6}$/.test(digits)) {
        warn('Six digits, as Glow shows them.');
        continue;
      }
      const res = await claim(digits);
      if (res.status === 200 && res.json?.status === 'approved' && typeof res.json.key === 'string') return res.json;
      if (res.status === 400) {
        warn(printable(res.json?.error, 120) || 'That isn’t the code Glow showed.');
        continue;
      }
      if (res.status === 404) fail('Too many wrong codes, or it expired. Run npx @winding-labs/glow again for a new one.');
      if (res.status === 403 || res.status === 409) fail(printable(res.json?.error, 160) || `Glow refused (${res.status}).`);
      fail(`Couldn’t reach ${apiBase(o.api)} (${res.status}). Run npx @winding-labs/glow again.`);
    }
    return fail('No valid code. Run npx @winding-labs/glow again.');
  } finally {
    rl.close();
  }
}


/** ~/.glow/{core,hook}.mjs and the shim the agents run, which uses the Node that ran this (or the one on PATH). */
function copyHook() {
  fs.mkdirSync(dir(), { recursive: true, mode: 0o700 });
  fs.chmodSync(dir(), 0o700);
  for (const f of ['core.mjs', 'hook.mjs']) fs.copyFileSync(path.join(LIB, f), path.join(dir(), f));
  for (const f of ['core.mjs', 'hook.mjs']) fs.chmodSync(path.join(dir(), f), 0o600);
  // An empty environment but HOME and PATH: no NODE_OPTIONS, proxy, TLS or GIT_* variable from the agent's settings
  // can change where the hook sends or what it runs. (GLOW_POLL_MS only speeds up the tests.)
  const shim = `#!/bin/sh
# Glow agent hook (npx @winding-labs/glow ${VERSION}). Sends coding agent replies in linked repos to Glow.
NODE=${shq(process.execPath)}
[ -x "$NODE" ] || NODE=$(command -v node) || exit 0
exec env -i HOME="$HOME" PATH="$PATH" \${GLOW_POLL_MS:+GLOW_POLL_MS="$GLOW_POLL_MS"} "$NODE" ${shq(path.join(dir(), 'hook.mjs'))} "$@"
`;
  fs.writeFileSync(shimPath(), shim, { mode: 0o700 });
  fs.chmodSync(shimPath(), 0o700);
}

function openUrl(url) {
  const cmd = process.platform === 'darwin' ? 'open' : 'xdg-open';
  try {
    execFile(cmd, [url], { stdio: 'ignore' }, () => undefined).unref();
  } catch {
    // the link is printed anyway
  }
}

const tilde = (p) => (p.startsWith(os.homedir()) ? `~${p.slice(os.homedir().length)}` : p);

// ---------- status, off/on, uninstall ----------

async function status() {
  const cfg = readConfig();
  if (!cfg) return console.log('Not set up. Run npx @winding-labs/glow');
  const res = await api(cfg, 'GET', '/api/v1/agent/config', undefined, 10_000);
  console.log(`${bold('Glow')} ${dim(VERSION)} · ${apiBase(cfg.api)}`);
  console.log(`Computer: ${printable(cfg.computer?.name) || '?'} · workspace: ${printable(res.json?.workspace?.name ?? cfg.workspace?.name) || '?'}`);
  console.log(`Key: ${res.status === 200 ? 'works' : res.status === 401 ? 'revoked (run setup again)' : res.status === 403 ? 'paused in Glow' : `unreachable (${res.status})`}${cfg.off ? ' · sending is OFF here' : ''}`);
  console.log(`Messages from Glow: ${cfg.messages === false ? 'off' : 'on'}`);
  for (const a of Object.keys(AGENTS)) console.log(`${AGENTS[a].label}: ${installed(a) ? 'hooked' : 'not hooked'}`);
  const repos = (res.json?.repos ?? cfg.repos ?? []).map((r) => printable(r, 160));
  console.log(`Repos that report: ${repos.length ? repos.join(', ') : 'none yet'}`);
}

function toggle(off) {
  const cfg = readConfig();
  if (!cfg) fail('Not set up. Run npx @winding-labs/glow');
  writeConfig({ ...cfg, off });
  ok(off ? 'Off: nothing is sent from this computer until you run npx @winding-labs/glow on' : 'On: sessions in linked repos report to Glow again');
}

function messages(on) {
  const cfg = readConfig();
  if (!cfg) fail('Not set up. Run npx @winding-labs/glow');
  writeConfig({ ...cfg, messages: on });
  ok(on ? 'Messages on: what you send a session from Glow reaches its agent' : 'Messages off: Glow holds nothing for this computer’s agents (npx @winding-labs/glow messages on to undo)');
}

async function remove() {
  const cfg = readConfig();
  for (const a of Object.keys(AGENTS)) {
    try {
      const file = uninstall(a);
      if (file) ok(`${AGENTS[a].label}: hook removed from ${tilde(file)}`);
    } catch (e) {
      warn(`${AGENTS[a].label}: couldn’t update its settings (${e.message}); remove the Glow hook by hand.`);
    }
  }
  if (cfg) {
    const res = await api(cfg, 'DELETE', '/api/v1/agent/computer', undefined, 10_000);
    if (res.status === 204 || res.status === 401) ok('This computer’s key is revoked');
    else warn(`Couldn’t reach Glow to revoke the key (${res.status}). Remove the computer in Glow › Connections.`);
  }
  fs.rmSync(dir(), { recursive: true, force: true });
  ok(`Deleted ${tilde(dir())}`);
}

main().catch((e) => fail(e?.message ?? String(e)));
