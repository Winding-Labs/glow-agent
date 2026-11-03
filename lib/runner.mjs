// The runner: `npx @winding-labs/glow run` (docs/security/review-2026-11-02-computer-sessions.md). Opt-in: only while it
// runs can the person who paired this computer start Claude Code sessions on it from Glow's Agents tab.
//
//  - Every 5 s (10 s once nothing has run for 10 minutes) it asks Glow for work with the computer's key, saying which
//    linked repos it can run in (owner/name only, never a path) and which sessions it runs.
//  - It doesn't take Glow's word for everything: a mode above --max-mode (read by default), a repo outside --repo (when
//    given), a folder Claude Code hasn't been trusted in, a repo checked out twice (unless pinned with --repo
//    owner/name=path) and a session id it has seen before are refused here, whatever Glow says.
//  - A repo with worktrees runs in its main checkout (the one whose .git is a folder); two main checkouts of one repo
//    are still refused.
//  - A session runs as `claude -p` in that repo's checkout: arguments as a list (no shell), the prompt on stdin (never
//    an argument, so no prompt can pass for a flag), in a mode that never skips permission checks (read: plan, edit:
//    acceptEdits, auto: auto) with nobody there to approve anything else (--permission-prompts none), and never Glow's
//    own CLI or files (--disallowedTools DENY: it can't turn Glow off, stop the runner or read the computer's key).
//    The model and effort Glow names go to --model and --effort only if they're on the lists below (medium if none).
//  - Inside a session `glow` refuses to change anything (GLOW_RUN_SESSION in its environment, a session's Claude Code
//    among its parents, or a session's process group: inRunnerSession).
//  - Its stream says what it's doing: the last tool or command goes to Glow, short and masked (core activityOf), at
//    most every few seconds; then done, failed or stopped, and its reply becomes the session's post (masked, as the
//    hook sends it).
//  - Stop in Glow, pausing the computer, `glow off`, a revoked key or Ctrl-C end its sessions: SIGTERM to every process
//    group under its Claude Code (its Bash tool and hooks start each command in a group of its own), then SIGKILL.
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { activityOf, api, dir, gitContext, ignoredOf, mask, prIn, printable, readConfig, repoOf, runMarker, tools, VERSION, writeConfig, writeFileAtomic } from './core.mjs';

// GLOW_RUN_POLL_MS only speeds up the tests (timing, never where anything is sent or what runs).
const POLL_MS = Math.max(50, Number(process.env.GLOW_RUN_POLL_MS) || 5000);
const UPDATE_MS = Math.min(POLL_MS, 4000);
const REPOS_EVERY_MS = 5 * 60_000;
const MAX_MS = 3 * 3600_000;
const AT_ONCE = 3;
const KILL_AFTER_MS = 5000;
const MESSAGE_MAX = 20_000;
const IDLE_AFTER_MS = 10 * 60_000;
/** The modes, least to most it may do on its own (--max-mode, read unless widened). */
export const MODES = ['read', 'edit', 'auto'];
/** The --model and --effort values a session may ask for (core SESSION_MODELS, SESSION_EFFORTS). */
export const MODELS = ['opus', 'sonnet', 'haiku', 'fable'];
export const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'];
/** In every session's environment (and passed through ~/.glow/glow): glow changes nothing from inside one. */
export const SESSION_ENV = 'GLOW_RUN_SESSION';
/**
 * What a session may never use, whatever its mode or any allow rule (the plugin's included; a deny rule wins): Glow's
 * CLI however it's spelled (~/.glow/glow, $HOME/.glow/…, npx/bunx @winding-labs/glow, node …/glow.mjs) and its files
 * (the computer's key). Claude Code 2.1 matches `*` anywhere in a Bash rule, and each part of `a && b`.
 */
export const DENY = ['Bash(*.glow*)', 'Bash(*@winding-labs/glow*)', 'Bash(*glow.mjs*)', 'Read(~/.glow/**)', 'Edit(~/.glow/**)'];
/** Folders never searched for checkouts (besides hidden ones). */
const SKIP = new Set(['node_modules', 'Library', 'Applications', 'Pictures', 'Movies', 'Music', 'vendor', 'dist', 'build', 'target', 'Pods', 'DerivedData']);

export const statePath = () => path.join(dir(), 'runner.json');
export const logPath = () => path.join(dir(), 'runner.log');

/** The runner on this computer, if one is on: { pid, started_at, roots, sessions }. Only if that pid is alive and is
 *  still `glow … run` (a pid the system reused for something else is never signalled). */
export function runnerState() {
  let s;
  try {
    s = JSON.parse(fs.readFileSync(statePath(), 'utf8'));
  } catch {
    return null;
  }
  if (!Number.isInteger(s?.pid) || s.pid <= 1) return null;
  try {
    const cmd = execFileSync('ps', ['-o', 'command=', '-p', String(s.pid)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
    return /glow(\.mjs)?\b.*\brun\b/.test(cmd) ? s : null;
  } catch {
    return null; // not running
  }
}

/** Every process now: pid → { ppid, pgid }, from one `ps`. */
export function processes() {
  const all = new Map();
  const out = execFileSync('ps', ['-A', '-o', 'pid=,ppid=,pgid='], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000, maxBuffer: 16 * 1024 * 1024 });
  for (const line of out.split('\n')) {
    const [pid, ppid, pgid] = line.trim().split(/\s+/).map(Number);
    if (pid > 0) all.set(pid, { ppid, pgid });
  }
  return all;
}

/** Every process group under this pid: its own, and each one its descendants run in (Claude Code's Bash tool and hooks
 *  start each command detached, in a group of its own). Never this process's group, init's or the kernel's. */
export function groupsUnder(root) {
  let all;
  try {
    all = processes();
  } catch {
    return new Set([root]);
  }
  const kids = new Map();
  for (const [pid, p] of all) kids.set(p.ppid, [...(kids.get(p.ppid) ?? []), pid]);
  const groups = new Set([root]);
  const seen = new Set();
  for (const todo = [root]; todo.length; ) {
    const p = todo.pop();
    if (seen.has(p)) continue;
    seen.add(p);
    if (all.get(p)?.pgid) groups.add(all.get(p).pgid);
    todo.push(...(kids.get(p) ?? []));
  }
  const mine = all.get(process.pid)?.pgid;
  for (const g of groups) if (g <= 1 || g === mine) groups.delete(g);
  return groups;
}

/** Signal each of these process groups (gone ones are skipped). */
function signalGroups(groups, sig) {
  for (const g of groups) {
    try {
      process.kill(-g, sig);
    } catch {
      // gone
    }
  }
}

/** This process runs inside a session the runner started: the session's marker in its environment, one of the
 *  sessions' Claude Code among its parents, or its process group one of theirs. Any one is enough (a command can drop
 *  an environment variable, or start a group of its own). */
export function inRunnerSession(env = process.env, pid = process.pid) {
  if (env[SESSION_ENV]) return true;
  const s = runnerState();
  const claudes = Array.isArray(s?.sessions) ? s.sessions.filter((x) => Number.isInteger(x) && x > 1) : [];
  if (!claudes.length) return false;
  let all;
  try {
    all = processes();
  } catch {
    return false;
  }
  if (claudes.includes(all.get(pid)?.pgid)) return true;
  for (let p = pid, n = 0; p > 1 && n < 200; p = all.get(p)?.ppid ?? 0, n++) if (claudes.includes(p)) return true;
  return false;
}

/** The folder holding .git above (or at) this one. */
function topOf(folder) {
  for (let f = path.resolve(folder); ; f = path.dirname(f)) {
    if (fs.existsSync(path.join(f, '.git'))) return f;
    if (path.dirname(f) === f) return null;
  }
}

/**
 * The linked repos checked out under these folders (a folder inside a checkout counts as that checkout): repo → every
 * main checkout of it found, shallowest first (its worktrees, whose .git is a file, only when there's no main one).
 * Hidden folders, symlinks and a checkout's own folders aren't searched; 3 levels, 4,000 folders.
 */
export function findRepos(roots, linked, ignored = [], depth = 3, limit = 4000) {
  const want = new Set(linked);
  const found = new Map();
  const keep = (folder) => {
    const repo = repoOf(folder);
    if (!repo || !want.has(repo) || ignored.includes(repo)) return;
    const real = fs.realpathSync(folder);
    const all = found.get(repo) ?? [];
    if (!all.includes(real)) found.set(repo, [...all, real]);
  };
  let seen = 0;
  let level = [];
  for (const r of roots) {
    const top = topOf(r);
    if (top) keep(top);
    else level.push(path.resolve(r));
  }
  for (let d = 0; d <= depth && level.length; d++) {
    const next = [];
    for (const folder of level) {
      if (++seen > limit) return mainsOf(found);
      if (fs.existsSync(path.join(folder, '.git'))) {
        keep(folder);
        continue;
      }
      if (d === depth) continue;
      let entries = [];
      try {
        entries = fs.readdirSync(folder, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) if (e.isDirectory() && !e.name.startsWith('.') && !SKIP.has(e.name)) next.push(path.join(folder, e.name));
    }
    level = next;
  }
  return mainsOf(found);
}

/** Each repo's main checkouts, if it has any (a worktree of it is the same repo, not a second copy). */
function mainsOf(found) {
  for (const [repo, all] of found) {
    const mains = all.filter((p) => isDir(path.join(p, '.git')));
    if (mains.length) found.set(repo, mains);
  }
  return found;
}

/**
 * Has Claude Code been trusted in this folder (its "Do you trust the files in this folder?" accepted, here or in a folder
 * above it, not the home folder itself)? `claude -p` skips that question, so a repo's own .claude settings and hooks
 * would apply in a folder nobody looked at: the runner only runs where it was answered.
 */
export function trusted(folder, env = process.env) {
  let projects = {};
  try {
    const file = env.CLAUDE_CONFIG_DIR ? path.join(env.CLAUDE_CONFIG_DIR, '.claude.json') : path.join(os.homedir(), '.claude.json');
    projects = JSON.parse(fs.readFileSync(file, 'utf8'))?.projects ?? {};
  } catch {
    return false;
  }
  let f;
  try {
    f = fs.realpathSync(folder);
  } catch {
    return false;
  }
  const home = os.homedir();
  for (; f !== path.dirname(f); f = path.dirname(f)) {
    if (f !== folder && f === home) break;
    if (projects[f]?.hasTrustDialogAccepted === true) return true;
  }
  return false;
}

/** Claude Code on this computer: on PATH, or where its installer puts it. */
export function findClaude(env = process.env) {
  const home = os.homedir();
  const dirs = [...String(env.PATH ?? '').split(path.delimiter).filter(Boolean), path.join(home, '.local', 'bin'), path.join(home, '.claude', 'local'), '/opt/homebrew/bin', '/usr/local/bin'];
  for (const d of dirs) {
    const p = path.join(d, 'claude');
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {
      // not here
    }
  }
  return null;
}

/** What this Claude Code can do, from its --help: plan mode, the name of its plain permission mode, auto mode, the flags. */
export function claudeFlags(help) {
  const h = String(help);
  return {
    plan: /"plan"/.test(h), manual: /"manual"/.test(h) ? 'manual' : 'default', auto: /"auto"/.test(h), prompts: h.includes('--permission-prompts'), sessionId: h.includes('--session-id'), name: /--name\b/.test(h),
    model: /--model\b/.test(h), effort: /--effort\b/.test(h),
  };
}

/** claude's arguments for a session: print mode, stream-json, its session id, its mode's permissions (Look only: plan
 *  mode, which changes nothing), a name to find it by in `claude --resume`, its model and effort (medium unless Glow
 *  names another on the list). Never a flag that skips permission checks; the prompt goes on stdin. */
export function argsFor(mode, f, sessionId, title, model, effort) {
  const perm = mode === 'auto' ? 'auto' : mode === 'edit' ? 'acceptEdits' : f.plan ? 'plan' : f.manual;
  const name = `Glow: ${String(title).replace(/[^\p{L}\p{N} ’'.,:_-]+/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, 60)}`;
  return [
    '-p', '--output-format', 'stream-json', '--verbose', ...(f.sessionId ? ['--session-id', sessionId] : []), '--permission-mode', perm,
    ...(f.prompts ? ['--permission-prompts', 'none'] : []), '--disallowedTools', ...DENY, ...(f.name ? ['--name', name] : []),
    ...(f.model && MODELS.includes(model) ? ['--model', model] : []), ...(f.effort ? ['--effort', EFFORTS.includes(effort) ? effort : 'medium'] : []),
  ];
}

/** The environment a session gets: this one, minus a parent Claude Code's own markers and Glow's test knobs, with the
 *  basics a shell needs (the runner may have been started with only HOME and PATH, from /glow:run). */
function childEnv() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SSE_PORT'].includes(k) || k.startsWith('GLOW_')) delete env[k];
  env[SESSION_ENV] = '1';
  let u = null;
  try {
    u = os.userInfo();
  } catch {
    u = null;
  }
  env.HOME ??= os.homedir();
  env.SHELL ??= u?.shell || '/bin/sh';
  if (u?.username) env.USER ??= u.username;
  env.LANG ??= 'en_US.UTF-8';
  return env;
}

const clock = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const MODE_LABEL = { read: 'look only', edit: 'edit files', auto: 'auto' };

/**
 * Run until told to stop. `say` prints a line (the terminal, or ~/.glow/runner.log in the background). Resolves with
 * the exit code. `stop()` on the returned handle ends it (Ctrl-C): its sessions are stopped and Glow is told.
 *   maxMode  the most a session may do on its own here (read | edit | auto); Glow can't ask for more
 *   allow    repo → pinned checkout (or null): only these repos run here; empty: any linked repo found under `roots`
 */
export function startRunner({ roots, say = console.log, maxMode = 'read', allow = new Map() }) {
  const sessions = new Map();
  /** Every session id handed over while this runner runs: one sent again never runs twice. */
  const seen = new Set();
  let cfg = readConfig();
  let repos = new Map();
  /** Why a repo can't run here: repo → error code (not_trusted, repo_twice, no_checkout). */
  let why = new Map();
  let reposAt = 0;
  let activeAt = Date.now();
  let claude = null;
  let flags = null;
  let ending = null;
  let paused = false;
  let offline = false;
  let wake = null;
  const sleep = (ms) => new Promise((r) => {
    const t = setTimeout(r, ms);
    wake = () => {
      clearTimeout(t);
      r();
    };
  });

  const refreshRepos = async () => {
    const res = await api(cfg, 'GET', '/api/v1/agent/config', undefined, 10_000);
    if (res.status === 200 && Array.isArray(res.json?.repos)) {
      try {
        writeConfig({ ...(readConfig() ?? cfg), repos: res.json.repos.filter((r) => typeof r === 'string').slice(0, 200), repos_at: Date.now() });
      } catch {
        // read-only home: the list is still used below
      }
      cfg = { ...cfg, repos: res.json.repos };
    }
    const linked = (Array.isArray(cfg.repos) ? cfg.repos : []).filter((r) => !allow.size || allow.has(r));
    const found = findRepos(roots, linked, ignoredOf(cfg));
    const next = new Map();
    const not = new Map();
    const notes = [];
    for (const repo of linked) {
      const pin = allow.get(repo);
      let at = found.get(repo) ?? [];
      if (pin) {
        if (repoOf(pin) !== repo) {
          notes.push(`${repo}: ${tilde(pin)} isn’t a checkout of it`);
          continue;
        }
        try {
          at = [fs.realpathSync(pin)];
        } catch {
          continue; // gone since
        }
      }
      if (!at.length) continue;
      if (ignoredOf(cfg).includes(repo)) continue;
      if (at.length > 1) {
        not.set(repo, 'repo_twice');
        notes.push(`${repo} is checked out ${at.length} times (${at.map(tilde).join(', ')}): pick one with --repo ${repo}=PATH`);
      } else if (!trusted(at[0])) {
        not.set(repo, 'not_trusted');
        notes.push(`${repo} (${tilde(at[0])}): Claude Code hasn’t been trusted in this folder. Open claude there once and say yes.`);
      } else next.set(repo, at[0]);
    }
    const before = [...repos].join(',') + [...why].join(',');
    repos = next;
    why = not;
    reposAt = Date.now();
    if ([...repos].join(',') + [...why].join(',') !== before) {
      say(repos.size ? `Sessions can run here in: ${[...repos].map(([r, p]) => `${r} (${tilde(p)})`).join(', ')}` : 'No linked repo can run here yet.');
      for (const n of notes) say(`  ! ${n}`);
    }
  };

  /** runner.json: who runs (`run stop` signals only this pid) and its sessions' process groups (whose commands may not
   *  turn Glow off or stop the runner: lib/runner inRunnerSession). */
  const writeState = () => {
    const mine = { pid: process.pid, started_at: startedAt, roots: roots.map(tilde), version: VERSION, max_mode: maxMode, sessions: [...sessions.values()].map((x) => x.child.pid).filter(Boolean) };
    try {
      writeFileAtomic(statePath(), `${JSON.stringify(mine)}\n`, 0o600);
    } catch {
      // a read-only home: run stop can't find it, Ctrl-C still works
    }
  };
  const startedAt = new Date().toISOString();

  /** Tell Glow how a session goes. The answer may say to stop it. */
  const send = async (x, body) => {
    const res = await api(cfg, 'POST', `/api/v1/agent/sessions/${encodeURIComponent(x.id)}`, body, 10_000);
    if (res.status === 200 && res.json?.stop === true && body.status === 'running') stop(x, 'stopped');
    return res;
  };
  const progress = (x) => {
    if (!x.dirty || x.sending || x.done) return;
    x.dirty = false;
    x.sending = true;
    void send(x, { status: 'running', ...(x.sessionId ? { session_id: x.sessionId } : {}), ...(x.activity ? { activity: x.activity } : {}), turns: x.turns }).finally(() => {
      x.sending = false;
    });
  };

  const fail = async (s, error, why) => {
    say(`${clock()} ✗ ${s.repo} · ${printable(s.title, 80)}: ${why}`);
    await api(cfg, 'POST', `/api/v1/agent/sessions/${encodeURIComponent(s.id)}`, { status: 'failed', error }, 10_000);
  };

  const launch = async (s) => {
    // Handed over once: an id seen before (Glow sending it again, or anyone who could) never runs a second time.
    if (seen.has(s.id)) return;
    seen.add(s.id);
    activeAt = Date.now();
    if (allow.size && !allow.has(s.repo)) return fail(s, 'not_allowed', `${s.repo} isn’t one of this runner’s --repo`);
    if (!MODES.includes(s.mode) || MODES.indexOf(s.mode) > MODES.indexOf(maxMode)) return fail(s, 'not_allowed', `this runner allows up to ${maxMode} (--max-mode)`);
    if (why.has(s.repo)) return fail(s, why.get(s.repo), why.get(s.repo) === 'repo_twice' ? 'checked out more than once here' : 'Claude Code isn’t trusted in that folder');
    let cwd = repos.get(s.repo);
    try {
      cwd = cwd && fs.realpathSync(cwd);
    } catch {
      cwd = undefined;
    }
    if (!cwd || repoOf(cwd) !== s.repo || ignoredOf(readConfig() ?? cfg).includes(s.repo)) return fail(s, 'no_checkout', 'not checked out in these folders');
    if (!trusted(cwd)) return fail(s, 'not_trusted', 'Claude Code isn’t trusted in that folder');
    if (!claude) claude = findClaude();
    if (!claude) return fail(s, 'claude_missing', 'Claude Code isn’t installed here (or not on PATH)');
    if (!flags) {
      try {
        flags = claudeFlags(execFileSync(claude, ['--help'], { encoding: 'utf8', timeout: 15_000, stdio: ['ignore', 'pipe', 'ignore'], env: childEnv(), maxBuffer: 1024 * 1024 }));
      } catch {
        flags = claudeFlags('');
      }
    }
    if ((s.mode === 'auto' && !flags.auto) || (s.mode === 'read' && !flags.plan)) return fail(s, 'mode_unsupported', `this Claude Code can’t run in ${s.mode} mode (update it: claude update)`);
    const sessionId = randomUUID();
    const marker = runMarker(sessionId);
    fs.mkdirSync(path.dirname(marker), { recursive: true, mode: 0o700 });
    fs.writeFileSync(marker, s.id, { mode: 0o600 });
    const child = spawn(claude, argsFor(s.mode, flags, sessionId, s.title, s.model, s.effort), { cwd, env: childEnv(), stdio: ['pipe', 'pipe', 'pipe'], detached: true });
    const x = { ...s, cwd, child, sessionId: flags.sessionId ? sessionId : null, marker, activity: '', turns: 0, dirty: false, sending: false, done: false, stopWhy: null, result: null, err: '' };
    sessions.set(s.id, x);
    writeState();
    say(`${clock()} ▶ ${s.repo} · ${printable(s.title, 80)} (${[MODE_LABEL[s.mode], MODELS.includes(s.model) ? s.model : '', EFFORTS.includes(s.effort) ? s.effort : 'medium'].filter(Boolean).join(', ')})`);
    child.on('error', () => undefined);
    child.stdin.on('error', () => undefined);
    child.stdin.end(s.prompt);
    child.stderr.on('data', (d) => {
      x.err = `${x.err}${d}`.slice(-2000);
    });
    readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on('line', (line) => {
      try {
        onEvent(x, line);
      } catch {
        // a line it can't make sense of changes nothing
      }
    });
    x.tick = setInterval(() => progress(x), UPDATE_MS);
    x.limit = setTimeout(() => stop(x, 'timeout'), MAX_MS);
    child.on('close', (code) => void ended(x, code));
  };

  const onEvent = (x, line) => {
    let e;
    try {
      e = JSON.parse(line);
    } catch {
      return;
    }
    if (!e || typeof e !== 'object') return;
    if (e.type === 'system' && e.subtype === 'init') {
      if (!x.sessionId && typeof e.session_id === 'string') {
        x.sessionId = e.session_id;
        fs.writeFileSync(runMarker(e.session_id), x.id, { mode: 0o600 });
      }
      x.dirty = true;
      progress(x);
    } else if (e.type === 'assistant' && Array.isArray(e.message?.content)) {
      // One event per content block; a turn is one message (its id), or each event when there's no id.
      const mid = typeof e.message.id === 'string' ? e.message.id : null;
      if (!mid || mid !== x.lastMessage) x.turns += 1;
      x.lastMessage = mid;
      const uses = e.message.content.filter((c) => c?.type === 'tool_use');
      const last = uses[uses.length - 1];
      if (last) {
        x.activity = activityOf(last.name, last.input, x.cwd);
        say(`${clock()}   ${x.activity}`);
      }
      x.dirty = true;
    } else if (e.type === 'result') {
      x.result = {
        error: e.is_error === true || (typeof e.subtype === 'string' && e.subtype.startsWith('error')),
        text: typeof e.result === 'string' ? e.result : '',
        turns: Number.isInteger(e.num_turns) ? e.num_turns : x.turns,
        cost: Number.isFinite(e.total_cost_usd) ? e.total_cost_usd : undefined,
        denied: Array.isArray(e.permission_denials) ? e.permission_denials.length : 0,
      };
    }
  };

  /** Ends a session: SIGTERM to every process group under its Claude Code (seen while it's still their parent), SIGKILL
   *  to them 5 s later, even if Claude Code is gone by then (a command it started may not be). */
  function stop(x, why) {
    if (x.done || x.stopWhy) return;
    x.stopWhy = why;
    const live = () => x.child.exitCode === null && x.child.signalCode === null;
    x.groups = live() ? groupsUnder(x.child.pid) : new Set([x.child.pid]);
    signalGroups(x.groups, 'SIGTERM');
    killing.add(x);
    x.killer = setTimeout(() => {
      if (live()) for (const g of groupsUnder(x.child.pid)) x.groups.add(g);
      signalGroups(x.groups, 'SIGKILL');
      killing.delete(x);
    }, KILL_AFTER_MS);
  }
  /** Stopped sessions whose SIGKILL is still to come. */
  const killing = new Set();

  const ended = async (x, code) => {
    x.done = true;
    clearInterval(x.tick);
    clearTimeout(x.limit);
    const r = x.result;
    let status = 'done';
    let error;
    if (x.stopWhy === 'timeout') [status, error] = ['failed', 'timeout'];
    else if (x.stopWhy) [status, error] = ['stopped', x.stopWhy];
    else if (!r || r.error) [status, error] = ['failed', 'claude_failed'];
    const quiet = x.stopWhy === 'paused' || x.stopWhy === 'revoked'; // Glow already knows (and won't take a word)
    if (!quiet) {
      await send(x, {
        status, ...(error ? { error } : {}), ...(x.sessionId ? { session_id: x.sessionId } : {}), ...(x.activity ? { activity: x.activity } : {}),
        turns: r?.turns ?? x.turns, ...(r?.cost !== undefined ? { cost_usd: r.cost } : {}), ...(r ? { denied: r.denied } : {}),
      });
    }
    const tail = status === 'failed' && !r && x.err.trim() ? ` (${printable(mask(x.err.trim().split('\n').pop()), 160)})` : '';
    say(`${clock()} ${status === 'done' ? '✓' : status === 'stopped' ? '■' : '✗'} ${x.repo} · ${printable(x.title, 80)}: ${status}${error && error !== status ? ` (${error})` : ''}${r ? ` · ${r.turns} turns` : ''}${r?.cost !== undefined ? ` · $${r.cost.toFixed(2)}` : ''}${r?.denied ? ` · ${r.denied} turned down` : ''}${tail}${code !== null && code !== 0 && !x.stopWhy ? ` · exit ${code}` : ''}`);
    // The reply becomes the session's post in Glow, masked, like a hooked session's.
    if (!quiet && r?.text?.trim() && x.sessionId) {
      const now = readConfig() ?? cfg;
      const ctx = gitContext(x.cwd);
      const pr = prIn(r.text, x.repo);
      await api(cfg, 'POST', '/api/v1/agent/reports', {
        agent: 'claude_code', session_id: x.sessionId, repo: x.repo, ...(ctx.branch ? { branch: ctx.branch } : {}), message: mask(r.text).slice(0, MESSAGE_MAX), commits: ctx.commits,
        ...(pr ? { pr_url: pr } : {}), inbox: now.messages !== false, tools: tools(), run_id: x.id,
      }, 15_000);
    }
    sessions.delete(x.id);
    activeAt = Date.now();
    writeState();
  };

  // However it ends (even a crash), no session outlives it: on the way out, every group under a running session gets
  // SIGTERM, and those of stopped ones still waiting for theirs get SIGKILL.
  const killAll = () => {
    for (const x of sessions.values()) if (!x.stopWhy) signalGroups(groupsUnder(x.child.pid), 'SIGTERM');
    for (const x of killing) signalGroups(x.groups, 'SIGKILL');
  };
  process.once('exit', killAll);

  const loop = async () => {
    if (!cfg) return 1;
    fs.mkdirSync(dir(), { recursive: true, mode: 0o700 });
    writeState();
    say(`Glow runner ${VERSION} · ${printable(cfg.computer?.name) || 'this computer'} · ${printable(cfg.workspace?.name) || 'your workspace'} · up to ${MODE_LABEL[maxMode]}`);
    say(allow.size ? `Only for ${[...allow.keys()].join(', ')}` : `Looking for linked repos in ${roots.map(tilde).join(', ')}`);
    await refreshRepos();
    say('Start a session from Glow (Agents tab). Ctrl-C stops the runner and its sessions.');
    try {
      while (!ending) {
        const now = readConfig();
        if (!now || now.off) {
          say(now ? 'Sending is off on this computer (npx @winding-labs/glow on), so the runner stops.' : 'Glow isn’t set up here any more, so the runner stops.');
          await shutdown('runner_stopped');
          return 1;
        }
        cfg = { ...now, repos: cfg.repos };
        if (Date.now() - reposAt > REPOS_EVERY_MS) await refreshRepos();
        const res = await api(cfg, 'POST', '/api/v1/agent/runner', { repos: [...repos.keys()], running: [...sessions.keys()], version: VERSION, max_mode: maxMode }, 15_000);
        if (res.status === 401) {
          say('This computer’s key no longer works (removed in Glow). Pair again: npx @winding-labs/glow');
          await shutdown('revoked');
          return 1;
        }
        if (res.status === 403) {
          if (!paused) say(`Paused in Glow${sessions.size ? `: stopping ${sessions.size} session${sessions.size === 1 ? '' : 's'}` : ''}. Waiting to be resumed.`);
          paused = true;
          for (const x of sessions.values()) stop(x, 'paused');
          await sleep(Math.max(POLL_MS, 30_000));
          continue;
        }
        if (paused) say('Resumed in Glow.');
        paused = false;
        if (res.status !== 200) {
          if (!offline) say(`Can’t reach Glow (${res.status || 'offline'}). Trying again…`);
          offline = true;
          await sleep(res.status === 429 ? 30_000 : Math.max(POLL_MS, 15_000));
          continue;
        }
        if (offline) say('Glow is back.');
        offline = false;
        for (const id of Array.isArray(res.json?.stop) ? res.json.stop : []) {
          const x = sessions.get(id);
          if (x) {
            say(`${clock()} ■ Stop from Glow: ${x.repo} · ${printable(x.title, 80)}`);
            stop(x, 'stopped');
          }
        }
        for (const s of Array.isArray(res.json?.sessions) ? res.json.sessions : []) {
          if (sessions.size >= AT_ONCE) break;
          if (!s || typeof s.id !== 'string' || typeof s.repo !== 'string' || typeof s.prompt !== 'string' || typeof s.title !== 'string') continue;
          try {
            await launch(s);
          } catch (e) {
            sessions.delete(s.id);
            await fail(s, 'claude_failed', `couldn’t start it (${printable(e?.message, 120)})`);
          }
        }
        // Quiet for 10 minutes: ask half as often (a session started then waits a few seconds more).
        await sleep(sessions.size || Date.now() - activeAt < IDLE_AFTER_MS ? POLL_MS : POLL_MS * 2);
      }
      await shutdown(ending);
      return 0;
    } finally {
      try {
        if (JSON.parse(fs.readFileSync(statePath(), 'utf8')).pid === process.pid) fs.rmSync(statePath(), { force: true });
      } catch {
        // someone else's, or gone
      }
    }
  };

  /** Stop every session (and say so to Glow), waiting up to 8 s for them to end. */
  async function shutdown(why) {
    for (const x of sessions.values()) stop(x, why);
    // Until Claude Code and everything it started are gone (or the SIGKILL is due): then whatever is left gets it now.
    const alive = (g) => {
      try {
        process.kill(-g, 0);
        return true;
      } catch (e) {
        return e?.code === 'EPERM';
      }
    };
    const until = Date.now() + KILL_AFTER_MS + 3000;
    while ((sessions.size || [...killing].some((x) => [...x.groups].some(alive))) && Date.now() < until) await new Promise((r) => setTimeout(r, 100));
    for (const x of killing) {
      clearTimeout(x.killer);
      signalGroups(x.groups, 'SIGKILL');
    }
    killing.clear();
  }

  const done = loop();
  return {
    done,
    /** Ctrl-C: end the loop; it stops its sessions (and tells Glow) before `done` resolves. */
    stop() {
      ending ??= 'runner_stopped';
      wake?.();
      return done;
    },
  };
}

const isDir = (p) => {
  try {
    return fs.lstatSync(p).isDirectory();
  } catch {
    return false;
  }
};

const tilde = (p) => {
  const h = os.homedir();
  return p.startsWith(h) ? `~${p.slice(h.length)}` : p;
};
