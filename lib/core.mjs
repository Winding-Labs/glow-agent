// Shared by the installer (bin/glow.mjs) and the hook (~/.glow/hook.mjs). Plain Node 18+, no dependencies.
//
// Safety (docs/security/review-2026-11-02-agent-reports.md):
//  - The only host this ever talks to is Glow's API: https://app.meetglow.ai (or staging.meetglow.ai), read from
//    ~/.glow/config.json (written at install, mode 0600) and checked again on every use. Never from an environment
//    variable (the hook runs with an empty environment but HOME and PATH). A local API (http://localhost) only when
//    installed with --dev. Redirects are refused, so the key never follows one.
//  - The key (glowc_…) can only report sessions, read the linked repo names, and fetch messages for this computer.
//  - Nothing is sent from a repo that isn't linked to a product in Glow; the reply is masked for keys before it leaves.
//  - git runs without a shell, with hooks, fsmonitor and signature checks off and none of the caller's GIT_* variables,
//    so a repo (or its .git/config) can't make it run anything.
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const VERSION = '0.1.1';
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

function git(cwd, args) {
  try {
    const opts = ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'log.showSignature=false', '-c', 'core.pager=cat'];
    return execFileSync('git', ['-C', cwd, ...opts, ...args], {
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
const LABELLED = /(\b(?:api[_ -]?key|secret|token|password|passwd|pwd|access[_ -]?key|client[_ -]?secret|private[_ -]?key|auth(?:orization)?)["']?\s*[:=]\s*["']?(?:bearer\s+|basic\s+)?)([^\s"',;&#[\]<>]{8,})/gi;
const BEARER = /\b(bearer\s+)([0-9A-Za-z._~+/-]{16,}=*)/gi;
const URL_CREDS = /\b(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi;

/** Keys, tokens, passwords and credentials in URLs → [masked]. The server scrubs again before any model sees it. */
export function mask(text) {
  let s = String(text);
  for (const re of KEY_SHAPES) s = s.replace(re, '[masked]');
  return s.replace(LABELLED, '$1[masked]').replace(BEARER, '$1[masked]').replace(URL_CREDS, '$1[masked]@');
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
