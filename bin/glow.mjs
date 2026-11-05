#!/usr/bin/env node
// npx @winding-labs/glow — pair this computer with Glow and hook the coding agents on it (Claude Code, Codex), so each
// session in a repo linked to a product posts what it did to that product's channel, and Glow can message it back.
//
//   npx @winding-labs/glow                 set up: find the agents, pair (approve in Glow, type the code it shows), add the hooks
//   npx @winding-labs/glow status          what's set up, what this folder sends, and the repos that report
//   npx @winding-labs/glow ignore [repo]   never send from this repo (or a folder / owner/name) on this computer
//   npx @winding-labs/glow unignore [repo] undo that
//   npx @winding-labs/glow off | on        stop / start sending from this computer
//   npx @winding-labs/glow messages off    stop messages from Glow reaching this computer's agents (on: again)
//   npx @winding-labs/glow recipes off     stop sending the request each reply answers (Glow learns recipes from it)
//   npx @winding-labs/glow run [folder…]   let Glow start Claude Code sessions here, in the linked repos under these
//                                          folders (default: this one), while it runs (--background; run stop)
//   npx @winding-labs/glow phone           the Glow phone this computer trusts (what it signs runs here), and Glow's word
//   npx @winding-labs/glow phone trust     trust the phone Glow names now instead (after you made a new one yours)
//   npx @winding-labs/glow uninstall       remove the hooks and plugins, revoke this computer's key, delete ~/.glow
//
// Setup copies this package to ~/.glow (bin, lib, marketplace) with two shims: ~/.glow/hook, which the agents' Stop
// hooks run, and ~/.glow/glow, this CLI, which the /glow:status, /glow:ignore, /glow:unignore and /glow:run plugin
// commands run.
import { execFile, spawn } from 'node:child_process';
import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addPlugin, AGENTS, detect, install, installed, removePlugin, shimPath, shq, uninstall } from '../lib/agents.mjs';
import { api, apiBase, apiOk, computerName, DEFAULT_API, dir, fingerprintText, ignoredOf, phoneOf, pinPhone, printable, readConfig, REPO_RE, repoOf, VERSION, writeConfig } from '../lib/core.mjs';
import { inRunnerSession, logPath, runnerState, SESSION_ENV, startRunner } from '../lib/runner.mjs';

const PKG = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
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
  npx @winding-labs/glow status          what's set up, what this folder sends, which repos report
  npx @winding-labs/glow ignore [repo]   never send from this repo on this computer (or a folder, or owner/name)
  npx @winding-labs/glow unignore [repo] let it send again
  npx @winding-labs/glow off | on        stop or start sending from this computer
  npx @winding-labs/glow messages off    stop messages from Glow reaching your agents here (messages on: again)
  npx @winding-labs/glow recipes off     don't send your requests, so Glow learns no recipes from them (recipes on: again)
  npx @winding-labs/glow run [folder…]   let Glow start Claude Code sessions here (Agents tab, your queue), in the linked
                                         repos checked out under these folders (default: this one), while it runs. Each
                                         runs like your own claude --dangerously-skip-permissions, with your Claude Code
                                         model and effort, in a git worktree of its own
      --background                       keep it running after this terminal closes (log: ~/.glow/runner.log)
      --repo owner/name[=path]           only this repo (repeat for more); =path picks its checkout
  npx @winding-labs/glow run stop        stop it, and the sessions it runs
  npx @winding-labs/glow phone           the Glow phone this computer trusts: only what it signs (after Face ID) runs here
  npx @winding-labs/glow phone trust     trust the phone Glow names now instead (once you've made a new phone yours)
  npx @winding-labs/glow uninstall       remove the hooks and revoke this computer's key

In Claude Code: /glow:status, /glow:ignore, /glow:unignore, /glow:run (in Codex: $glow:status, $glow:ignore, …)

Options for setup:
  --claude, --codex   only these agents (default: every one found)
  --new               pair again, as a new computer
  --name <name>       what Glow calls this computer (default: its name)
  --no-open           don't open the browser; print the link
`;

function parse(argv) {
  const o = { cmd: 'install', agents: [], api: DEFAULT_API, dev: false, open: true, fresh: false, name: '', messages: null, recipes: null, target: '', roots: [], background: false, runStop: false, allow: new Map() };
  // One command per call: `glow ignore x run …` must not become `run` (a skill allowed to run `glow ignore` can't
  // reach any other command).
  let named = '', asked = '';
  const command = (c) => {
    if (named) fail(`One command at a time (${named}, then ${c}).`);
    named = c;
    o.cmd = c;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h' || a === 'help') asked = 'help';
    else if (a === '--version' || a === '-v') asked = 'version';
    else if (a === '--claude') o.agents.push('claude_code');
    else if (a === '--codex') o.agents.push('codex');
    else if (a === '--new') o.fresh = true;
    else if (a === '--no-open') o.open = false;
    else if (a === '--dev') o.dev = true;
    else if (a === '--api') o.api = argv[++i] ?? '';
    else if (a === '--name') o.name = argv[++i] ?? '';
    else if (a === 'messages' && ['on', 'off'].includes(argv[i + 1])) {
      command('messages');
      o.messages = argv[++i] === 'on';
    } else if (a === 'recipes' && ['on', 'off'].includes(argv[i + 1])) {
      command('recipes');
      o.recipes = argv[++i] === 'on';
    } else if (a === 'ignore' || a === 'unignore') {
      command(a);
      if (argv[i + 1] !== undefined && !argv[i + 1].startsWith('-')) o.target = argv[++i];
    } else if (a === 'phone') {
      command('phone');
      if (argv[i + 1] === 'trust') o.trust = !!argv[++i];
    } else if (a === 'run') {
      command('run');
      while (argv[i + 1] !== undefined && !argv[i + 1].startsWith('-')) {
        const x = argv[++i];
        if (x === 'stop' && !o.roots.length) o.runStop = true;
        else o.roots.push(x);
      }
    } else if (a === '--background' && o.cmd === 'run') o.background = true;
    else if (a === '--repo' && o.cmd === 'run') {
      const [name, at] = String(argv[++i] ?? '').split(/=(.*)/s);
      const repo = name.toLowerCase();
      if (!REPO_RE.test(repo)) fail('--repo is owner/name, or owner/name=path to pick its checkout.');
      o.allow.set(repo, at ? path.resolve(at.replace(/^~(?=$|\/)/, os.homedir())) : null);
    }
    else if (['install', 'setup', 'status', 'off', 'on', 'uninstall'].includes(a)) command(a === 'setup' ? 'install' : a);
    else fail(`Unknown option ${a}. Run npx @winding-labs/glow --help`);
  }
  if (asked) o.cmd = asked; // help and version win, whatever else is there
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
  if (o.cmd === 'phone' && !o.trust) return phone(false);
  // A session Glow started here can't change how Glow reaches this computer (stop the runner, turn sending off, …).
  if (inRunnerSession()) fail('Not from a session Glow started: run it yourself, in a terminal.');
  if (o.cmd === 'off' || o.cmd === 'on') return toggle(o.cmd === 'off');
  if (o.cmd === 'messages') return messages(o.messages);
  if (o.cmd === 'recipes') return recipes(o.recipes);
  if (o.cmd === 'ignore' || o.cmd === 'unignore') return ignore(o.target, o.cmd === 'ignore');
  if (o.cmd === 'run') return run(o);
  if (o.cmd === 'phone') return phone(true);
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
    if (res.status === 200) {
      info = res.json;
      cfg = pinPhone(cfg, res.json?.phone, ok);
    } else if (res.status === 401) {
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

  copyFiles();
  for (const a of agents) {
    try {
      const file = install(a);
      ok(`${AGENTS[a].label}: hook added to ${tilde(file)}`);
    } catch (e) {
      warn(`${AGENTS[a].label}: couldn’t update ${tilde(path.join(os.homedir(), ...AGENTS[a].file))} (${e.message}). Fix it, then run this again.`);
    }
    try {
      addPlugin(a);
      const x = a === 'codex' ? '$' : '/';
      ok(`${AGENTS[a].label}: ${x}glow:status, ${x}glow:ignore, ${x}glow:unignore and ${x}glow:run added`);
    } catch (e) {
      warn(`${AGENTS[a].label}: couldn’t add the /glow commands (${printable(e.message, 160)}). The hook works without them.`);
    }
  }

  const ignored = ignoredOf(readConfig());
  const repos = (info?.repos ?? []).filter((r) => !ignored.includes(r)).map((r) => printable(r, 160));
  console.log('');
  console.log(repos.length ? `Repos that report to Glow: ${repos.join(', ')}` : 'No repos are linked to a product yet.');
  if (ignored.length) console.log(`Ignored on this computer: ${ignored.join(', ')}`);
  const here = repoOf(process.cwd());
  if (here && !repos.includes(here) && !ignored.includes(here)) console.log(`This repo (${here}) isn’t linked. Link it to a product: ${linkUrl(cfg, here)}`);
  console.log('');
  if (agents.includes('claude_code')) console.log(`${bold('Claude Code')}: new sessions in those repos post to Glow when they finish a reply. Restart open sessions to pick it up (and the /glow commands).`);
  if (agents.includes('codex')) console.log(`${bold('Codex')}: open Codex and run ${bold('/hooks')} once to trust the Glow hook (Codex asks before running any new hook).`);
  console.log(`Messages you send a session from its post in Glow reach that agent${readConfig()?.messages === false ? ' (off here: npx @winding-labs/glow messages on)' : ' (npx @winding-labs/glow messages off to stop that)'}.`);
  if (agents.includes('claude_code')) console.log(`To start Claude Code sessions here from Glow (Agents tab): ${bold('npx @winding-labs/glow run')} in your code folder.`);
  console.log(dim('\nOnly sessions in linked repos send anything, and only to Glow. A repo you never want sent: /glow:ignore in it.'));
  console.log(dim('Off: npx @winding-labs/glow off · Remove: npx @winding-labs/glow uninstall'));
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


/**
 * This package's code to ~/.glow (bin, lib, marketplace) and the two shims: ~/.glow/hook (the agents' Stop hooks) and
 * ~/.glow/glow (this CLI, for the /glow commands). Both run the Node that ran this (or the one on PATH) with an empty
 * environment but HOME and PATH: no NODE_OPTIONS, proxy, TLS or GIT_* variable from the agent's settings can change
 * where they send or what they run. (GLOW_POLL_MS only speeds up the tests.)
 */
function copyFiles() {
  const home = dir();
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  // Copied over in place (never removed first), so a hook that starts meanwhile still finds its files.
  if (fs.realpathSync(PKG) !== fs.realpathSync(home)) {
    for (const d of ['bin', 'lib', 'marketplace']) fs.cpSync(path.join(PKG, d), path.join(home, d), { recursive: true, force: true });
  }
  // 0.1.0–0.1.1 kept the hook at ~/.glow/hook.mjs and ~/.glow/core.mjs.
  for (const f of ['core.mjs', 'hook.mjs']) fs.rmSync(path.join(home, f), { force: true });
  const shim = (what, script, extra = '') => `#!/bin/sh
# ${what} (npx @winding-labs/glow ${VERSION})
NODE=${shq(process.execPath)}
[ -x "$NODE" ] || NODE=$(command -v node) || { echo "Glow needs Node 18 or newer: https://nodejs.org" >&2; exit 0; }
exec env -i HOME="$HOME" PATH="$PATH" ${extra}"$NODE" ${shq(path.join(home, script))} "$@"
`;
  writeShim(shimPath(), shim('Glow agent hook: sends coding agent replies in linked repos to Glow', path.join('lib', 'hook.mjs'), '${GLOW_POLL_MS:+GLOW_POLL_MS="$GLOW_POLL_MS"} '));
  // The session marker goes through (env -i drops the rest): glow refuses to change anything from a runner's session.
  writeShim(cliPath(), shim('Glow: status, ignore, unignore, run and the rest of npx @winding-labs/glow, for the /glow commands', path.join('bin', 'glow.mjs'), `\${${SESSION_ENV}:+${SESSION_ENV}="$${SESSION_ENV}"} `));
}

const cliPath = () => path.join(dir(), 'glow');

function writeShim(file, text) {
  fs.writeFileSync(file, text, { mode: 0o700 });
  fs.chmodSync(file, 0o700);
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
const linkUrl = (cfg, repo) => `${apiBase(cfg.api)}/app/pair?repo=${encodeURIComponent(repo)}`;

// ---------- status, off/on, uninstall ----------

/** What's set up here, what this folder sends (and why not), and the repos that report or are ignored. */
/** The Glow phone this computer trusts, and Glow's word on it; `trust`: pin the one Glow names now, once its owner,
 *  at this terminal, says it's theirs (its fingerprint, as the app shows it). */
async function phone(trust) {
  const cfg = readConfig();
  if (!cfg) fail('Glow isn’t set up on this computer. Set it up: npx @winding-labs/glow');
  const res = await api(cfg, 'GET', '/api/v1/agent/config', undefined, 10_000);
  if (res.status !== 200) fail(res.status === 401 ? 'This computer’s key no longer works. Pair again: npx @winding-labs/glow' : `Couldn’t ask Glow (${res.status || 'offline'}).`);
  const named = phoneOf(res.json?.phone);
  const line = (p) => `${bold(printable(p.name, 60))} ${dim(fingerprintText(p.fingerprint))}`;
  if (!trust) {
    console.log(cfg.phone?.fingerprint ? `Trusted here: ${line(cfg.phone)}. Only what it signs (after Face ID) runs on this computer.` : 'No Glow phone is trusted here yet: make your phone your Glow phone in the app (Settings › Glow phone).');
    if (named && named.fingerprint !== cfg.phone?.fingerprint) console.log(`Glow names ${line(named)}. To trust it instead: npx @winding-labs/glow phone trust`);
    if (!named) console.log(dim('Glow names no Glow phone for you right now.'));
    return;
  }
  if (!named) fail('Glow names no Glow phone for you. Make your phone your Glow phone in the app first (Settings › Glow phone).');
  if (named.fingerprint === cfg.phone?.fingerprint) return ok(`Already trusted: ${line(named)}`);
  // Glow's word alone never swaps the key: the person at this terminal checks the fingerprint against their phone.
  if (!process.stdin.isTTY || !tty) fail('Run it yourself, in a terminal: it asks you to check the fingerprint against your phone.');
  console.log(`Glow says your Glow phone is now ${line(named)}.`);
  console.log(`Open the app on that phone, Settings › Glow phone: it shows ${bold(fingerprintText(named.fingerprint))}. Not the same, or not your doing? Answer no.`);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((r) => rl.question('Trust it on this computer? (yes/no) ', r));
  rl.close();
  if (String(answer).trim().toLowerCase() !== 'yes') return warn('Nothing changed.');
  writeConfig({ ...(readConfig() ?? cfg), phone: { ...named, pinned_at: new Date().toISOString() } });
  ok(`Trusted: ${line(named)}. What it signs runs here; what ${cfg.phone?.name ? printable(cfg.phone.name, 60) : 'any other phone'} signs doesn’t.`);
}

async function status() {
  const cfg = readConfig();
  if (!cfg) return console.log('Glow isn’t set up on this computer, so nothing is sent from it. Set it up: npx @winding-labs/glow');
  const res = await api(cfg, 'GET', '/api/v1/agent/config', undefined, 10_000);
  const ok200 = res.status === 200 && Array.isArray(res.json?.repos);
  try {
    if (ok200) writeConfig({ ...(readConfig() ?? cfg), repos: res.json.repos.filter((r) => typeof r === 'string').slice(0, 200), repos_at: Date.now() });
  } catch {
    // a sandbox that can't write ~/.glow: the hook refreshes the list itself
  }
  const linkedRepos = (ok200 ? res.json.repos : Array.isArray(cfg.repos) ? cfg.repos : []).filter((r) => typeof r === 'string').map((r) => printable(r, 160));
  const ignored = ignoredOf(cfg);
  const key = res.status === 200 ? 'key works' : res.status === 401 ? 'key revoked: run npx @winding-labs/glow to pair again' : res.status === 403 ? 'paused in Glow (Connections › Coding agents)' : `Glow unreachable (${res.status || 'offline'})`;

  const here = repoOf(process.cwd());
  let folder;
  if (!here) folder = 'not a GitHub repo: sends nothing';
  else if (ignored.includes(here)) folder = `${here}: ignored here, sends nothing (undo: /glow:unignore)`;
  else if (!linkedRepos.includes(here)) folder = `${here}: not linked to a product, sends nothing. Link it: ${linkUrl(cfg, here)}`;
  else if (cfg.off) folder = `${here}: linked, but sending is off on this computer`;
  else if (res.status === 401 || res.status === 403) folder = `${here}: linked, but this computer can’t send (see Computer)`;
  else folder = `${here}: reports to Glow`;

  const agents = Object.keys(AGENTS).map((a) => `${AGENTS[a].label} ${installed(a) ? 'hooked' : 'not hooked'}`).join(' · ');
  const reporting = linkedRepos.filter((r) => !ignored.includes(r));
  const rs = runnerState();
  const rows = [
    ['This folder', folder],
    ['Computer', `${printable(cfg.computer?.name) || '?'} · workspace ${printable(res.json?.workspace?.name ?? cfg.workspace?.name) || '?'} · ${key}`],
    ['Sending', `${cfg.off ? 'off (npx @winding-labs/glow on)' : 'on'} · messages from Glow ${cfg.messages === false ? 'off' : 'on'} · requests for recipes ${cfg.recipes === false ? 'off' : 'on'}`],
    ['Agents', agents],
    ['Reporting', reporting.length ? reporting.join(', ') : 'no repo yet'],
    ['Ignored here', ignored.length ? ignored.join(', ') : 'none'],
    ['Glow phone', cfg.phone?.fingerprint
      ? `${printable(cfg.phone.name, 60)} (${fingerprintText(cfg.phone.fingerprint)}): only what it signs runs here${phoneOf(res.json?.phone) && phoneOf(res.json.phone).fingerprint !== cfg.phone.fingerprint ? ` · Glow names another: npx @winding-labs/glow phone trust` : ''}`
      : 'none trusted yet: make your phone your Glow phone in the app (Settings › Glow phone)'],
    ['Runner', rs
      ? `on since ${new Date(rs.started_at).toLocaleString()} (pid ${rs.pid}) in ${(rs.roots ?? []).map((r) => printable(r, 160)).join(', ')}: Glow can start Claude Code sessions here · stop: npx @winding-labs/glow run stop`
      : 'off: Glow can’t start sessions here (to let it: npx @winding-labs/glow run, in your code folder)'],
  ];
  console.log(`${bold('Glow')} ${dim(VERSION)} · ${apiBase(cfg.api)}\n`);
  for (const [k, v] of rows) console.log(`${dim(k.padEnd(14))}${v}`);
}

/** The repo a folder is in (default: this one), or an owner/name typed out (or its GitHub URL). */
function repoArg(target) {
  if (!target) return { repo: repoOf(process.cwd()), where: 'This folder' };
  const p = path.resolve(target.replace(/^~(?=$|\/)/, os.homedir()));
  if (fs.existsSync(p)) return { repo: repoOf(p), where: tilde(p) };
  const r = target.trim().toLowerCase().replace(/^(?:https:\/\/)?github\.com\//, '').replace(/(?:\.git)?\/?$/, '');
  return { repo: REPO_RE.test(r) ? r : null, where: printable(target, 160) };
}

/** Ignore (or stop ignoring) a repo on this computer. Local only: the hook checks it before sending anything. */
function ignore(target, on) {
  const { repo, where } = repoArg(target);
  if (!repo) return console.log(`${where} isn’t a GitHub repo, so Glow sends nothing from it.`);
  const cfg = readConfig();
  if (!cfg) return console.log(`Glow isn’t set up on this computer, so nothing is sent from ${repo} (or any repo).`);
  const list = ignoredOf(cfg);
  const linked = Array.isArray(cfg.repos) && cfg.repos.includes(repo);
  if (on) {
    if (list.includes(repo)) return ok(`${repo} is already ignored here: nothing is sent from it.`);
    writeConfig({ ...cfg, ignored: [...list, repo].sort() });
    ok(`Ignored ${repo}: Claude Code and Codex sessions in it send nothing to Glow from this computer.`);
    console.log(dim(`${linked ? 'It’s linked to a product in Glow; other computers still report from it. ' : ''}Undo: /glow:unignore ($glow:unignore in Codex, or npx @winding-labs/glow unignore${target ? ` ${repo}` : ''})`));
    return;
  }
  if (!list.includes(repo)) return console.log(`${repo} isn’t ignored here. ${linked ? 'Sessions in it report to Glow.' : 'It isn’t linked to a product, so it sends nothing.'}`);
  writeConfig({ ...cfg, ignored: list.filter((r) => r !== repo) });
  ok(`${repo} isn’t ignored anymore.`);
  console.log(linked ? 'Sessions in it report to Glow again.' : `It isn’t linked to a product, so it still sends nothing. Link it: ${linkUrl(cfg, repo)}`);
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

function recipes(on) {
  const cfg = readConfig();
  if (!cfg) fail('Not set up. Run npx @winding-labs/glow');
  writeConfig({ ...cfg, recipes: on });
  ok(on ? 'Recipes on: each report carries the request it answers, and Glow learns the recipes you run' : 'Recipes off: reports carry the agent’s reply only (npx @winding-labs/glow recipes on to undo)');
}

async function remove() {
  const cfg = readConfig();
  const rs = runnerState();
  if (rs) {
    try {
      process.kill(rs.pid, 'SIGTERM');
      for (let n = 0; n < 100 && runnerState(); n++) await sleep(100);
      ok('Runner stopped');
    } catch {
      warn(`Couldn’t stop the runner (pid ${rs.pid}). Stop it yourself: kill ${rs.pid}`);
    }
  }
  for (const a of Object.keys(AGENTS)) {
    try {
      const file = uninstall(a);
      if (file) ok(`${AGENTS[a].label}: hook removed from ${tilde(file)}`);
    } catch (e) {
      warn(`${AGENTS[a].label}: couldn’t update its settings (${e.message}); remove the Glow hook by hand.`);
    }
    if (detect().includes(a) && removePlugin(a)) ok(`${AGENTS[a].label}: /glow commands removed`);
  }
  if (cfg) {
    const res = await api(cfg, 'DELETE', '/api/v1/agent/computer', undefined, 10_000);
    if (res.status === 204 || res.status === 401) ok('This computer’s key is revoked');
    else warn(`Couldn’t reach Glow to revoke the key (${res.status}). Remove the computer in Glow › Connections.`);
  }
  fs.rmSync(dir(), { recursive: true, force: true });
  ok(`Deleted ${tilde(dir())}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- run: sessions Glow starts here ----------

/**
 * `glow run [folder…]`: Glow can start Claude Code sessions here while this runs (lib/runner.mjs). In the foreground
 * (Ctrl-C stops it and its sessions), or with --background as its own process logging to ~/.glow/runner.log. One per
 * computer. `glow run stop` ends it.
 */
async function run(o) {
  const cfg = readConfig();
  if (!cfg) fail('Glow isn’t set up on this computer. Set it up first: npx @winding-labs/glow');
  const on = runnerState();
  if (o.runStop) {
    if (!on) return console.log('The runner isn’t on here, so Glow can’t start sessions on this computer.');
    process.kill(on.pid, 'SIGTERM');
    for (let n = 0; n < 120 && runnerState(); n++) await sleep(100);
    return runnerState() ? warn(`Asked the runner (pid ${on.pid}) to stop; it’s still finishing.`) : ok('Runner stopped: Glow can’t start sessions here until you run it again.');
  }
  if (cfg.off) fail('Sending is off on this computer. Turn it on first: npx @winding-labs/glow on');
  if (on) fail(`The runner is already on here (pid ${on.pid}, in ${(on.roots ?? []).map((r) => printable(r, 160)).join(', ')}). Stop it first: npx @winding-labs/glow run stop`);
  const roots = (o.roots.length ? o.roots : [process.cwd()]).map((r) => path.resolve(r.replace(/^~(?=$|\/)/, os.homedir())));
  for (const r of roots) if (!fs.existsSync(r) || !fs.statSync(r).isDirectory()) fail(`${printable(r, 160)} isn’t a folder.`);
  // From 0.1.4 the hook leaves the sessions the runner starts to the runner (one report each): bring an older copy up.
  let hookVersion;
  try {
    hookVersion = /VERSION = '([\d.]+)'/.exec(fs.readFileSync(path.join(dir(), 'lib', 'core.mjs'), 'utf8'))?.[1];
  } catch {
    hookVersion = undefined;
  }
  const older = (a, b) => {
    const [x, y] = [a, b].map((v) => v.split('.').map(Number));
    for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0);
    return false;
  };
  let shimNow = '';
  try {
    shimNow = fs.readFileSync(cliPath(), 'utf8');
  } catch {
    shimNow = '';
  }
  // Older, or a ~/.glow/glow that drops the session marker (an early 0.1.4): bring it up.
  if (hookVersion && /^\d+\.\d+\.\d+$/.test(VERSION) && (older(hookVersion, VERSION) || (shimNow && !shimNow.includes(SESSION_ENV)))) {
    copyFiles();
    console.log(dim(older(hookVersion, VERSION) ? `Updated Glow’s hook on this computer from ${hookVersion} to ${VERSION}.` : 'Updated Glow’s files on this computer.'));
  }
  if (o.background) {
    const log = logPath();
    fs.mkdirSync(dir(), { recursive: true, mode: 0o700 });
    try {
      if (fs.statSync(log).size > 1_000_000) fs.rmSync(log, { force: true });
    } catch {
      // no log yet
    }
    const fd = fs.openSync(log, 'a', 0o600);
    fs.chmodSync(log, 0o600);
    const flags = [...o.allow].flatMap(([r, at]) => ['--repo', at ? `${r}=${at}` : r]);
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), 'run', ...roots, ...flags], { detached: true, stdio: ['ignore', fd, fd], env: process.env, cwd: roots[0] });
    child.unref();
    for (let n = 0; n < 80 && runnerState()?.pid !== child.pid; n++) await sleep(100);
    if (runnerState()?.pid !== child.pid) fail(`The runner didn’t start. See ${tilde(log)}`);
    ok(`Runner on in the background (pid ${child.pid}): it runs what your Glow phone signs, 3 at a time, in the linked repos under ${roots.map(tilde).join(', ')} (pause this computer in Glow to hold it).`);
    console.log(dim(`Log: ${tilde(log)} · Stop: npx @winding-labs/glow run stop`));
    return;
  }
  for (const [r, at] of o.allow) if (at && (!fs.existsSync(at) || !fs.statSync(at).isDirectory())) fail(`${printable(at, 160)} (for ${r}) isn’t a folder.`);
  const r = startRunner({ roots, say: (line) => console.log(line), allow: o.allow });
  const quit = () => {
    console.log(dim('\nStopping the runner and its sessions…'));
    void r.stop();
  };
  process.once('SIGINT', quit);
  process.once('SIGTERM', quit);
  process.once('SIGHUP', quit); // the terminal closed
  process.exit(await r.done);
}

main().catch((e) => fail(e?.message ?? String(e)));
