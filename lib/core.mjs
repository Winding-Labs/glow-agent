// Shared by the CLI (bin/glow.mjs), the hook (lib/hook.mjs) and the runner (lib/runner.mjs), all copied to ~/.glow.
// Plain Node 18+, no dependencies.
//
// Safety (docs/security/review-2026-11-02-agent-reports.md):
//  - The only host this ever talks to is Glow's API: https://app.meetglow.ai (or staging.meetglow.ai), read from
//    ~/.glow/config.json (written at install, mode 0600) and checked again on every use. Never from an environment
//    variable (the hook runs with an empty environment but HOME and PATH). A local API (http://localhost) only when
//    installed with --dev. Redirects are refused, so the key never follows one.
//  - The key (glowc_…) can only report sessions, read the linked repo names, and fetch messages for this computer.
//  - Nothing is sent from a repo that isn't linked to a product in Glow, or that's ignored on this computer (`glow
//    ignore`: checked before any request); the reply is masked for keys before it leaves.
//  - git runs without a shell, with hooks, fsmonitor and signature checks off and none of the caller's GIT_* variables,
//    so a repo (or its .git/config) can't make it run anything.
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const VERSION = '0.1.13';
export const DEFAULT_API = 'https://app.meetglow.ai';
export const dir = () => path.join(os.homedir(), '.glow');
export const configPath = () => path.join(dir(), 'config.json');

export const KEY_RE = /^glowc_[A-Za-z0-9_-]{43}$/;
export const SESSION_RE = /^[A-Za-z0-9._:-]{1,100}$/;
export const REPO_RE = /^[a-z0-9](?:[a-z0-9-]{0,38})\/[a-z0-9._-]{1,100}$/;

const HOSTS = new Set(['app.meetglow.ai', 'staging.meetglow.ai']);

/** Glow's API only: https on app.meetglow.ai (or staging), no port, path, query or credentials; localhost with --dev. */
export function apiOk(url, allowLocal = false) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) return false;
  if (u.protocol === 'https:' && !u.port && HOSTS.has(u.hostname)) return true;
  return allowLocal && u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
}
export const apiBase = (url) => new URL(url).origin;

// ---------- config ----------

/** ~/.glow/config.json, or null when missing, unreadable or not well-formed (then nothing is sent). */
export function readConfig() {
  try {
    const c = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    if (!c || typeof c !== 'object' || !KEY_RE.test(c.key ?? '') || !apiOk(c.api, c.dev === true)) return null;
    return c;
  } catch {
    return null;
  }
}

/** Atomic, owner-only. */
/** The repos ignored on this computer (`glow ignore`): nothing is sent from them, linked or not. */
export const ignoredOf = (c) => (Array.isArray(c?.ignored) ? c.ignored.filter((r) => typeof r === 'string' && REPO_RE.test(r)) : []);

export function writeConfig(c) {
  fs.mkdirSync(dir(), { recursive: true, mode: 0o700 });
  fs.chmodSync(dir(), 0o700);
  writeFileAtomic(configPath(), `${JSON.stringify(c, null, 2)}\n`, 0o600);
}

export function writeFileAtomic(file, text, mode) {
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, text, { mode });
  fs.renameSync(tmp, file);
}

// ---------- the API ----------

/** One call to Glow's API with the computer's key. Never throws: { status, json } (status 0 when unreachable). */
export async function api(c, method, p, body, timeoutMs = 10_000) {
  if (!apiOk(c.api, c.dev === true)) return { status: 0, json: null };
  try {
    const res = await fetch(`${apiBase(c.api)}${p}`, {
      method,
      redirect: 'error',
      headers: {
        ...(c.key ? { authorization: `Bearer ${c.key}` } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        'x-glow-client': `glow-cli/${VERSION}`,
        'user-agent': `glow-cli/${VERSION} (${process.platform})`,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { status: res.status, json };
  } catch {
    return { status: 0, json: null };
  }
}

// ---------- git ----------

/** Every git run here: no hooks, fsmonitor, signature checks or pager, so nothing of the repo's own runs. */
export const GIT_SAFE = ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'log.showSignature=false', '-c', 'core.pager=cat'];

function git(cwd, args) {
  try {
    return execFileSync('git', ['-C', cwd, ...GIT_SAFE, ...args], {
      encoding: 'utf8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'ignore'],
      // Not the caller's GIT_* (GIT_CONFIG_PARAMETERS and friends can set any config, GIT_DIR another repo).
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: os.homedir(), GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', GIT_CONFIG_NOSYSTEM: '1' },
      maxBuffer: 256 * 1024,
    }).trim();
  } catch {
    return '';
  }
}

/** A GitHub remote URL → "owner/name" (lower-case), else null. */
export function parseRemote(url) {
  const m = /^(?:git@github\.com:|ssh:\/\/git@github\.com(?::22)?\/|https:\/\/(?:[^@/\s]+@)?github\.com\/)([A-Za-z0-9-]+\/[A-Za-z0-9._-]+?)(?:\.git)?\/?$/.exec(String(url).trim());
  const r = m?.[1]?.toLowerCase();
  return r && REPO_RE.test(r) && !r.endsWith('/.') && !r.endsWith('/..') ? r : null;
}

/** The GitHub repo a directory is in (its origin), or null. */
export const repoOf = (cwd) => (cwd && fs.existsSync(cwd) ? parseRemote(git(cwd, ['config', '--get', 'remote.origin.url'])) : null);

/** Branch and the commits on it that aren't on the default branch yet (newest first, ≤ 5). */
export function gitContext(cwd) {
  const branch = git(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const base = git(cwd, ['symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD']) || 'origin/main';
  const out = { ...(branch && branch !== 'HEAD' && branch.length <= 200 ? { branch } : {}), commits: [] };
  if (!branch || `origin/${branch}` === base) return out;
  for (const line of git(cwd, ['log', '--no-show-signature', '-n', '5', '--format=%H%x1f%s', `${base}..HEAD`]).split('\n')) {
    const [sha, title] = line.split('\x1f');
    if (sha && /^[0-9a-f]{40}$/.test(sha) && title) out.commits.push({ sha: sha.slice(0, 12), title: mask(title).slice(0, 300) });
  }
  return out;
}

/** A pull request link on this repo, from the reply (the last one wins). */
export function prIn(text, repo) {
  let found;
  for (const m of String(text).matchAll(/https:\/\/github\.com\/([A-Za-z0-9-]+\/[A-Za-z0-9._-]+)\/pull\/(\d{1,7})\b/g)) {
    if (m[1].toLowerCase() === repo) found = `https://github.com/${m[1]}/pull/${m[2]}`;
  }
  return found;
}

/** Text from the server, safe to print in a terminal: no control characters (escape sequences), one line, clipped. */
export const printable = (s, max = 80) => String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g, '').slice(0, max);

// ---------- masking ----------

const KEY_SHAPES = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{8,}/g,
  /\bwhsec_[0-9A-Za-z+/=]{16,}/g,
  /\bsk-or-v1-[0-9a-f]{16,}/g,
  /\bsk-(?:ant-|proj-)?[0-9A-Za-z_-]{20,}/g,
  /\bgithub_pat_[0-9A-Za-z_]{20,}/g,
  /\bgh[pousr]_[0-9A-Za-z]{20,}/g,
  /\bglpat-[0-9A-Za-z_-]{20,}/g,
  /\bphx_[0-9A-Za-z]{20,}/g,
  /\bGOCSPX-[0-9A-Za-z_-]{20,}/g,
  /\bAIza[0-9A-Za-z_-]{30,}/g,
  /\bya29\.[0-9A-Za-z_.-]{20,}/g,
  /\bEAA[0-9A-Za-z]{40,}/g,
  /\bxox[abposr]-[0-9A-Za-z-]{10,}/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}/g,
  /\bnpm_[0-9A-Za-z]{30,}/g,
  /\bshp(?:at|ss|ca|pa)_[0-9a-fA-F]{20,}/g,
  /\beyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}/g,
  /\bglowc?_[0-9A-Za-z_-]{40,}/g,
];
/** A label may follow `_` or `-` too (refresh_token, DB_PASSWORD, x-auth-token: `\b` never matches there). */
const LABELLED = /((?<![A-Za-z0-9])(?:api[_ -]?key|secret|token|password|passwd|pwd|access[_ -]?key|client[_ -]?secret|private[_ -]?key|auth(?:orization)?)["']?\s*[:=]\s*["']?(?:bearer\s+|basic\s+)?)([^\s"',;&#[\]<>]{8,})/gi;
const BEARER = /\b(bearer\s+)([0-9A-Za-z._~+/-]{16,}=*)/gi;
/** user:password@ in a URL of any scheme (https, postgres, redis, mongodb+srv…), and curl's -u user:password. */
const URL_CREDS = /\b([a-z][a-z0-9+.-]{1,20}:\/\/)[^\s/@:]*:[^\s/@]+@/gi;
const USER_PASS = /((?:^|\s)(?:-u|--user)[=\s]+["']?[^\s"':]+:)[^\s"']+/g;

/** Keys, tokens, passwords and credentials in URLs → [masked]. The server scrubs again before any model sees it. */
export function mask(text) {
  let s = String(text);
  for (const re of KEY_SHAPES) s = s.replace(re, '[masked]');
  return s.replace(LABELLED, '$1[masked]').replace(BEARER, '$1[masked]').replace(URL_CREDS, '$1[masked]@').replace(USER_PASS, '$1[masked]');
}

// ---------- the request a reply answers ----------

const PROMPT_MAX = 4_000;
const TAIL_BYTES = 2 * 1024 * 1024;

/**
 * The person's latest request in the agent's own transcript, masked, ≤ 4,000 characters; '' when there is none. Only a
 * .jsonl under ~/.claude/projects (Claude Code) or ~/.codex/sessions (Codex) is read, and only its last 2 MB.
 */
export function promptIn(file, home = os.homedir()) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || !file.endsWith('.jsonl')) return '';
  const real = (p) => {
    try {
      return fs.realpathSync(p);
    } catch {
      return '';
    }
  };
  const at = real(file);
  const roots = [path.join(home, '.claude', 'projects'), path.join(home, '.codex', 'sessions')].map(real).filter(Boolean);
  if (!at || !roots.some((r) => at.startsWith(r + path.sep))) return '';
  let text = '';
  try {
    const fd = fs.openSync(at, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const n = Math.min(size, TAIL_BYTES);
      const buf = Buffer.alloc(n);
      fs.readSync(fd, buf, 0, n, size - n);
      text = buf.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
  const lines = text.split('\n');
  for (let k = lines.length - 1; k >= 0; k--) {
    if (!lines[k].includes('"user')) continue;
    let e;
    try {
      e = JSON.parse(lines[k]);
    } catch {
      continue;
    }
    const p = userText(e);
    if (p) return mask(p).slice(0, PROMPT_MAX);
  }
  return '';
}

/** A typed request: Codex's user_message event, or a Claude Code user turn that isn't a tool result, meta or a command. */
function userText(e) {
  if (e?.type === 'event_msg' && e.payload?.type === 'user_message') return typeof e.payload.message === 'string' ? e.payload.message.trim() : '';
  if (e?.type !== 'user' || e.isMeta || e.isSidechain || e.message?.role !== 'user') return '';
  const c = e.message.content;
  const t = typeof c === 'string' ? c : Array.isArray(c) && !c.some((x) => x?.type === 'tool_result') ? c.filter((x) => x?.type === 'text').map((x) => x.text).join('\n') : '';
  const s = String(t ?? '').trim();
  return /^<(command-|local-command|system-reminder|task-notification|bash-)/.test(s) ? '' : s;
}

// ---------- this computer ----------

/** "Ilya’s MacBook Pro": the computer's own name (macOS), else the host name. Letters, digits, spaces, ’'._- only. */
export function computerName() {
  let name = '';
  if (process.platform === 'darwin') {
    try {
      name = execFileSync('scutil', ['--get', 'ComputerName'], { encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      name = '';
    }
  }
  if (!name) name = os.hostname().replace(/\.(local|lan|home)$/i, '').replace(/[-_]+/g, ' ');
  return name.normalize('NFC').replace(/[^\p{L}\p{N} ’'._-]+/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, 60) || 'My computer';
}

export const sha = (s) => createHash('sha256').update(s).digest('hex');

/**
 * What else this computer can reach, for the green tags beside it in Glow: GitHub (gh signed in), Chrome, Docker, Xcode.
 * File checks only (no process is started), so the hook can run it on every report. Never a token, an account or a path:
 * only which of these four are there.
 */
export function tools(home = os.homedir(), env = process.env, platform = process.platform) {
  const dirs = String(env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const has = (p) => {
    try {
      return fs.existsSync(p);
    } catch {
      return false;
    }
  };
  const onPath = (bin) => dirs.some((d) => has(path.join(d, bin)));
  const ghConfig = env.GH_CONFIG_DIR || path.join(env.XDG_CONFIG_HOME || path.join(home, '.config'), 'gh');
  const out = [];
  if (onPath('gh') && has(path.join(ghConfig, 'hosts.yml'))) out.push('github');
  if (platform === 'darwin' ? has('/Applications/Google Chrome.app') || has(path.join(home, 'Applications', 'Google Chrome.app')) : onPath('google-chrome') || onPath('chrome') || onPath('chromium')) out.push('chrome');
  if (onPath('docker')) out.push('docker');
  if (platform === 'darwin' && has('/Applications/Xcode.app')) out.push('xcode');
  return out;
}

// ---------- sessions Glow starts here (`glow run`) ----------

/** The file that marks a session the runner started (by its Claude Code session id): the runner sends its reply to
 *  Glow itself, so the Stop hook leaves it alone. In ~/.glow/sessions, tidied after a day like the hook's locks. */
export const runMarker = (session) => path.join(dir(), 'sessions', `${sha(`run:${session}`).slice(0, 24)}.run`);

const clip = (s, n) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

/**
 * A command as a session's status shows it: the program and its subcommand only ("$ git status", "$ psql …"), never its
 * arguments, options or environment, which is where passwords go. Leading `VAR=…`, `export`, `cd` and wrappers like
 * `sudo` are skipped. (The same as @glow/core commandHead, which Glow applies again.)
 */
export function commandHead(command) {
  const parts = String(command ?? '').split(/&&|\|\||;|\||\n/).map((x) => x.trim().split(/\s+/).filter(Boolean));
  const SKIP = new Set(['sudo', 'env', 'time', 'nohup', 'command', 'exec', 'nice']);
  const SETUP = new Set(['export', 'cd', 'set', 'unset', 'source', '.', 'pushd', 'popd']);
  let fallback = '';
  for (const words of parts) {
    let k = 0;
    while (k < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k]) || SKIP.has(words[k]) || words[k].startsWith('-'))) k++; // VAR=x, sudo -E, env, …
    const prog = (words[k] ?? '').split('/').pop().replace(/[^\w.+-]/g, '').slice(0, 40);
    if (!prog) continue;
    // A subcommand is a plain lower-case word (`git status`, `npm run`): never what echo or printf print, nor a word
    // with digits or capitals (a password piped to `sudo -S` looks like one).
    const sub = words[k + 1] && !['echo', 'printf'].includes(prog) && /^[a-z][a-z_-]{0,30}$/.test(words[k + 1]) ? words[k + 1] : '';
    const more = words.length > k + (sub ? 2 : 1) || parts.length > 1;
    const head = `$ ${prog}${sub ? ` ${sub}` : ''}${more ? ' …' : ''}`;
    if (!SETUP.has(prog)) return head;
    fallback ||= head;
  }
  return fallback || '$ (a command)';
}

/**
 * What a session is doing, from the tool it just called, for its row in Glow: "$ bun test …", "Edit src/app.ts",
 * "Grep useSession". Short, one line, paths inside the repo relative and the home folder as ~, keys masked before
 * anything is cut. A command by its program only; never what's written or fetched; an MCP tool by its name only.
 */
export function activityOf(name, input, cwd = '') {
  const i = input && typeof input === 'object' ? input : {};
  const home = os.homedir();
  const where = (p) => {
    const s = String(p ?? '');
    if (cwd && s.startsWith(`${cwd}/`)) return s.slice(cwd.length + 1);
    return home && s.startsWith(`${home}/`) ? `~/${s.slice(home.length + 1)}` : s;
  };
  // Masked whole, then cut: a key cut in half can't be told from text any more.
  const safe = (v, n) => clip(mask(String(v ?? '').replace(/\s+/g, ' ')), n);
  const tool = String(name ?? '').replace(/[^\w.:-]/g, '').slice(0, 60) || 'A tool';
  let line;
  if (tool === 'Bash') line = commandHead(i.command);
  else if (['Read', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit'].includes(tool)) line = `${tool} ${safe(where(i.file_path ?? i.notebook_path), 140)}`;
  else if (tool === 'Glob' || tool === 'Grep') line = `${tool} ${safe(i.pattern, 100)}`;
  else if (tool === 'WebFetch') {
    let host = '';
    try {
      host = new URL(String(i.url)).host;
    } catch {
      host = '';
    }
    line = `WebFetch ${host}`;
  } else if (tool === 'WebSearch') line = `WebSearch ${safe(i.query, 100)}`;
  else if (tool === 'Task' || tool === 'Agent') line = `Agent: ${safe(i.description, 100)}`;
  else if (tool === 'TodoWrite') line = 'Updating its to-do list';
  else line = tool;
  return printable(line, 160).trim();
}

// ---------- your Glow phone (packages/core src/phone.ts; docs/security/review-2026-11-03-signed-runs.md) ----------
// Glow hands this computer a session or a message only with the signature of its starter's Glow phone: a P-256 key in
// that phone's Secure Enclave or Keystore, used only after Face ID (or a fingerprint), over exactly what will run. Here
// it's checked against the phone key this computer pinned (config.phone: the first one Glow named, or the one `glow
// phone trust` was told to trust) before anything runs or reaches an agent, so Glow's servers alone can neither start
// anything here nor swap the key. Each signature is used once (~/.glow/seen).

export const RUN_SIGN_V = 'glow-run-v1';
export const MESSAGE_SIGN_V = 'glow-message-v1';
/** How far a signature's time may be from this computer's clock, and how long a signed session may wait (core). */
export const SIGN_SKEW_S = 300;
export const SIGNED_RUN_TTL_S = 6 * 3600;
export const SIGNED_MESSAGE_TTL_S = 24 * 3600;

/** What the phone signed: one field a line, no trailing newline (pinned against core in test/cli.test.ts). */
export const runPayload = (r) => [RUN_SIGN_V, r.session, r.computer, r.repo, r.prompt_sha256, String(r.issued_at)].join('\n');
export const messagePayload = (m) => [MESSAGE_SIGN_V, m.message, m.computer, m.session_key, m.body_sha256, String(m.issued_at)].join('\n');
/** "3F9A 1C22 7B0E 44D1": what the app shows under Settings › Glow phone. */
export const fingerprintText = (hex) => String(hex ?? '').slice(0, 16).toUpperCase().replace(/(.{4})(?!$)/g, '$1 ');

/** An uncompressed P-256 point's SubjectPublicKeyInfo, up to the point. */
const P256_SPKI = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex');

/** A phone key (SPKI DER, base64) as bytes: exactly a P-256 key, else null. */
export function phoneKey(b64) {
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]{122}={0,2}$/.test(b64)) return null;
  const b = Buffer.from(b64, 'base64');
  return b.length === P256_SPKI.length + 64 && b.subarray(0, P256_SPKI.length).equals(P256_SPKI) ? b : null;
}
/** SHA-256 of the key's DER, hex: what both ends pin and show. */
export const phoneFingerprint = (b64) => {
  const k = phoneKey(b64);
  return k ? createHash('sha256').update(k).digest('hex') : null;
};

/** A phone Glow names (GET /api/v1/agent/config's `phone`), checked: its fingerprint is its key's. Else null. */
export function phoneOf(p) {
  if (!p || typeof p !== 'object') return null;
  const fingerprint = phoneFingerprint(p.key);
  if (!fingerprint || fingerprint !== p.fingerprint) return null;
  return { key: p.key, fingerprint, name: printable(p.name, 60) || 'your phone' };
}

/**
 * Glow's word on the phone (the config answer): only reported, never trusted, the first time too. Only
 * `glow phone trust`, at this computer's terminal, pins one, after its owner checks the fingerprint against their phone
 * (docs/security/review-2026-11-05-server-queue.md): Glow, or anyone who could speak for it, can't pick the key that
 * signs runs here. Returns the config as it now is.
 */
export function pinPhone(cfg, glowPhone, say = () => undefined) {
  const p = phoneOf(glowPhone);
  if (!p) return cfg;
  if (!cfg.phone?.fingerprint) {
    if (cfg.phone?.offered === p.fingerprint) return cfg;
    try {
      writeConfig({ ...(readConfig() ?? cfg), phone: { offered: p.fingerprint } });
    } catch {
      // said again next time
    }
    say(`Your Glow phone is ${p.name} (${fingerprintText(p.fingerprint)}). To let what it signs run here, run in a terminal on this computer: npx @winding-labs/glow phone trust`);
    return cfg;
  }
  if (cfg.phone.fingerprint !== p.fingerprint && cfg.phone.offered !== p.fingerprint) {
    try {
      writeConfig({ ...(readConfig() ?? cfg), phone: { ...cfg.phone, offered: p.fingerprint } });
    } catch {
      // said again next time
    }
    say(`Glow says your Glow phone is now ${p.name} (${fingerprintText(p.fingerprint)}). This computer still trusts ${printable(cfg.phone.name, 60)} (${fingerprintText(cfg.phone.fingerprint)}) until you run here: npx @winding-labs/glow phone trust`);
  }
  return cfg;
}

/** Each signed thing once: a file named after what was signed (the payload, which names the session or message) in
 *  ~/.glow/seen, made only if it isn't there. Not after the signature's text: base64 has many spellings of one signature
 *  (padding, whitespace, the URL alphabet) and ECDSA a second valid one, so that let a resent copy through. Old ones
 *  are cleared. */
function once(signedText) {
  const seen = path.join(dir(), 'seen');
  try {
    fs.mkdirSync(seen, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(seen, createHash('sha256').update(signedText).digest('hex').slice(0, 40)), '', { flag: 'wx', mode: 0o600 });
  } catch (e) {
    return false; // seen before, or no way to remember it (a read-only home): either way it doesn't run
  }
  if (Math.random() < 0.05) {
    const old = Date.now() - (SIGNED_MESSAGE_TTL_S + SIGN_SKEW_S + 3600) * 1000;
    try {
      for (const f of fs.readdirSync(seen)) {
        const at = path.join(seen, f);
        if (fs.statSync(at).mtimeMs < old) fs.rmSync(at, { force: true });
      }
    } catch {
      // next time
    }
  }
  return true;
}

/** A phone's signature as Glow takes it from the phone (core SIGNATURE_RE): plain base64 of a DER ECDSA signature. */
const SIGNATURE = /^[A-Za-z0-9+/]{80,100}={0,2}$/;

/**
 * Did this computer's Glow phone sign exactly this, recently, for the first time? null when it did, else why not:
 * `untrusted_phone` (none pinned, or another phone), `not_signed` (no signature, or too old or too new), `bad_signature`
 * (it doesn't check out, or it was used before). `payload` is built from what will actually run, never from Glow's
 * word on what was signed.
 */
export function checkSigned(cfg, signed, payloadAt, ttlS, now = Date.now() / 1000) {
  const pinned = cfg?.phone;
  const key = phoneKey(pinned?.key);
  if (!key || phoneFingerprint(pinned.key) !== pinned.fingerprint) return 'untrusted_phone';
  if (!signed || typeof signed !== 'object' || typeof signed.sig !== 'string' || !Number.isSafeInteger(signed.at)) return 'not_signed';
  if (signed.phone !== pinned.fingerprint) return 'untrusted_phone';
  if (signed.at > now + SIGN_SKEW_S || signed.at < now - ttlS - SIGN_SKEW_S) return 'not_signed';
  const payload = payloadAt(signed.at);
  let ok = false;
  try {
    ok = SIGNATURE.test(signed.sig) && verify('sha256', Buffer.from(payload, 'utf8'), { key: createPublicKey({ key, format: 'der', type: 'spki' }), dsaEncoding: 'der' }, Buffer.from(signed.sig, 'base64'));
  } catch {
    ok = false;
  }
  if (!ok) return 'bad_signature';
  return once(payload) ? null : 'bad_signature';
}
