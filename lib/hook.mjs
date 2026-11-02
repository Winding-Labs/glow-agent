// The Glow hook, run by the coding agent when it finishes a reply (installed to ~/.glow by `npx @winding-labs/glow`).
//
//   claude-stop  Claude Code's Stop hook, run in the background (asyncRewake). Reports the reply, then listens for a
//                message from Glow for up to 25 minutes while the session is idle. A message wakes Claude: it is printed
//                to stderr and the hook exits 2. A newer reply in the same session takes over the listening.
//   codex-stop   Codex's Stop hook (runs before the turn ends; ~1 s). Reports the reply; a waiting message comes back as
//                {"decision":"block","reason":…}, which Codex takes as the next prompt.
//
// `npx @winding-labs/glow messages off` stops both: Glow then holds no message for this computer's sessions.
//
// Quiet by design: whatever goes wrong, it exits 0 and the agent carries on. Nothing is written to a log.
import fs from 'node:fs';
import path from 'node:path';
import { api, dir, gitContext, mask, prIn, printable, readConfig, repoOf, SESSION_RE, sha, writeConfig } from './core.mjs';

const LISTEN_MS = 25 * 60_000;
// GLOW_POLL_MS only speeds up the tests (timing, never where anything is sent).
const POLL_MS = Math.max(50, Number(process.env.GLOW_POLL_MS) || 15_000);
const REPOS_FRESH_MS = 2 * 60_000;
const MESSAGE_MAX = 20_000;

const mode = process.argv[2];
const agent = mode === 'codex-stop' ? 'codex' : mode === 'claude-stop' ? 'claude_code' : null;

main().then(
  (code) => process.exit(code ?? 0),
  () => process.exit(0),
);

async function main() {
  if (!agent) return 0;
  const input = await stdinJson();
  const cfg = readConfig();
  if (!cfg || cfg.off) return 0;
  const session = typeof input.session_id === 'string' ? input.session_id : '';
  if (!SESSION_RE.test(session)) return 0;
  const cwd = typeof input.cwd === 'string' && path.isAbsolute(input.cwd) ? input.cwd : process.cwd();
  const repo = repoOf(cwd);
  if (!repo || !(await linked(cfg, repo))) return 0;

  const reply = typeof input.last_assistant_message === 'string' ? input.last_assistant_message : '';
  const inbox = cfg.messages !== false;
  let messages = [];
  if (reply.trim()) {
    const ctx = gitContext(cwd);
    const pr = prIn(reply, repo);
    const res = await api(cfg, 'POST', '/api/v1/agent/reports', {
      agent, session_id: session, repo, ...(ctx.branch ? { branch: ctx.branch } : {}), message: mask(reply).slice(0, MESSAGE_MAX), commits: ctx.commits, ...(pr ? { pr_url: pr } : {}), inbox,
    }, agent === 'codex' ? 6_000 : 10_000);
    if (res.status === 401 || res.status === 403) return 0;
    if (res.json?.skipped === 'repo_not_linked' && Array.isArray(res.json.repos)) saveRepos(cfg, res.json.repos);
    messages = inbox && Array.isArray(res.json?.messages) ? res.json.messages : [];
  }
  if (messages.length) return deliver(messages);
  if (agent === 'claude_code' && inbox) return listen(cfg, session);
  return 0;
}

/** Is this repo linked to a product? The list is cached in the config, refreshed when a repo isn't on it (≤ every 2 min). */
async function linked(cfg, repo) {
  const repos = Array.isArray(cfg.repos) ? cfg.repos : [];
  if (repos.includes(repo)) return true;
  if (Date.now() - Number(cfg.repos_at ?? 0) < REPOS_FRESH_MS) return false;
  const res = await api(cfg, 'GET', '/api/v1/agent/config', undefined, 5_000);
  if (res.status !== 200 || !Array.isArray(res.json?.repos)) return false;
  saveRepos(cfg, res.json.repos);
  return res.json.repos.includes(repo);
}

function saveRepos(cfg, repos) {
  try {
    const fresh = readConfig() ?? cfg;
    writeConfig({ ...fresh, repos: repos.filter((r) => typeof r === 'string').slice(0, 200), repos_at: Date.now() });
  } catch {
    // a read-only home: the next run asks again
  }
}

/** The messages, as the person who sent them, for the agent. Claude: stderr + exit 2. Codex: a block decision. */
function deliver(messages) {
  const text = messages
    .filter((m) => m && typeof m.body === 'string')
    .map((m) => `Message from ${printable(m.from) || 'a teammate'} in Glow (sent to this session at ${timeOf(m.sent_at)}):\n\n${m.body}`)
    .join('\n\n---\n\n');
  if (!text) return 0;
  if (agent === 'codex') {
    process.stdout.write(`${JSON.stringify({ decision: 'block', reason: text })}\n`);
    return 0;
  }
  process.stderr.write(`${text}\n`);
  return 2;
}

const timeOf = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(+d) ? 'just now' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

/**
 * Claude Code, idle: ask Glow for a message every 15 s for up to 25 minutes. One listener per session: a newer reply
 * writes its own token to the lock and this one stops. Stops too when Claude Code itself has gone.
 */
async function listen(cfg, session) {
  const locks = path.join(dir(), 'sessions');
  fs.mkdirSync(locks, { recursive: true, mode: 0o700 });
  const lock = path.join(locks, `${sha(`${agent}:${session}`).slice(0, 24)}.lock`);
  const token = `${process.pid}:${Date.now()}`;
  fs.writeFileSync(lock, token, { mode: 0o600 });
  tidy(locks);
  const parent = process.ppid;
  const until = Date.now() + LISTEN_MS;
  const q = `/api/v1/agent/inbox?agent=${agent}&session=${encodeURIComponent(session)}`;
  try {
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, POLL_MS));
      if (!mine(lock, token) || !alive(parent)) return 0;
      const now = readConfig();
      if (!now || now.off || now.messages === false) return 0;
      const res = await api(now, 'GET', q, undefined, 10_000);
      if (res.status === 401 || res.status === 403 || res.status === 404) return 0;
      const messages = Array.isArray(res.json?.messages) ? res.json.messages : [];
      if (messages.length) return deliver(messages);
    }
    return 0;
  } finally {
    if (mine(lock, token)) fs.rmSync(lock, { force: true });
  }
}

const mine = (lock, token) => {
  try {
    return fs.readFileSync(lock, 'utf8') === token;
  } catch {
    return false;
  }
};
const alive = (pid) => {
  if (process.ppid !== pid || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e?.code === 'EPERM';
  }
};
/** Locks older than a day go. */
function tidy(locks) {
  try {
    for (const f of fs.readdirSync(locks)) {
      const p = path.join(locks, f);
      if (Date.now() - fs.statSync(p).mtimeMs > 86_400_000) fs.rmSync(p, { force: true });
    }
  } catch {
    // best effort
  }
}

/** The hook's input (≤ 4 MB of JSON on stdin), or {}. */
async function stdinJson() {
  const chunks = [];
  let n = 0;
  for await (const c of process.stdin) {
    n += c.length;
    if (n > 4 * 1024 * 1024) return {};
    chunks.push(c);
  }
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}
