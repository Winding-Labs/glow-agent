// The installer and the hook, run as the agents run them (node, a temp HOME, a git repo) against a fake Glow API.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
// @ts-expect-error plain JS
import { apiOk, mask, parseRemote, prIn, VERSION } from '../lib/core.mjs';
// @ts-expect-error plain JS
import { hookEntry, isOurs, withHook, withoutHook, writeJson } from '../lib/agents.mjs';

const ROOT = path.join(import.meta.dir, '..');
type Req = { method: string; path: string; auth: string | null; body: any }; // eslint-disable-line @typescript-eslint/no-explicit-any

describe('shapes', () => {
  test('GitHub remotes only, lower-cased', () => {
    expect(parseRemote('git@github.com:Winding-Labs/Zest.git')).toBe('winding-labs/zest');
    expect(parseRemote('https://github.com/winding-labs/zest')).toBe('winding-labs/zest');
    expect(parseRemote('https://x-access-token:abc@github.com/winding-labs/zest.git')).toBe('winding-labs/zest');
    expect(parseRemote('ssh://git@github.com/winding-labs/zest.git')).toBe('winding-labs/zest');
    for (const bad of ['git@gitlab.com:a/b.git', 'https://github.com.evil.com/a/b', 'https://github.com/a/b/c', '', 'https://github.com/a/..']) expect([bad, parseRemote(bad)]).toEqual([bad, null]);
  });

  test('only Glow’s API: https app.meetglow.ai (or staging); localhost only with --dev', () => {
    for (const good of ['https://app.meetglow.ai', 'https://app.meetglow.ai/', 'https://staging.meetglow.ai']) expect([good, apiOk(good)]).toEqual([good, true]);
    for (const bad of ['https://meetglow.ai', 'https://www.meetglow.ai', 'https://old.meetglow.ai', 'http://app.meetglow.ai', 'https://app.meetglow.ai.evil.com', 'https://evilmeetglow.ai', 'https://app.meetglow.ai:8443', 'https://u:p@app.meetglow.ai', 'https://app.meetglow.ai/x', 'http://localhost:8787', 'file:///etc/passwd']) {
      expect([bad, apiOk(bad)]).toEqual([bad, false]);
    }
    expect(apiOk('http://localhost:8787', true)).toBe(true);
    expect(apiOk('http://127.0.0.1:1', true)).toBe(true);
    expect(apiOk('http://10.0.0.1:1', true)).toBe(false);
  });

  test('keys, tokens and URL credentials are masked; a PR link on the same repo only', () => {
    const s = mask(`ANTHROPIC sk-ant-api03-${'a'.repeat(40)} gh ghp_${'b'.repeat(36)} password: hunter2hunter2 https://me:pw@host/x Bearer ${'c'.repeat(30)} glowc_${'d'.repeat(43)}`);
    expect(s).not.toMatch(/sk-ant-api03-a|ghp_b|hunter2|me:pw|cccc|glowc_d/);
    expect(s).toContain('[masked]');
    expect(mask('fixed 14 pages, commit 3f2a9c1')).toBe('fixed 14 pages, commit 3f2a9c1');
    expect(prIn('PR: https://github.com/Winding-Labs/Zest/pull/12 and https://github.com/evil/x/pull/3', 'winding-labs/zest')).toBe('https://github.com/Winding-Labs/Zest/pull/12');
    expect(prIn('https://github.com/evil/x/pull/3', 'winding-labs/zest')).toBeUndefined();
  });

  test('settings: our Stop hook is added once, everything else is kept, and removal leaves the rest', () => {
    const theirs = { model: 'opus', hooks: { Stop: [{ hooks: [{ type: 'command', command: 'say done' }] }], PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'x' }] }] } };
    const entry = hookEntry('claude_code', "/Users/o'neil/.glow/hook");
    expect(entry).toEqual({ type: 'command', command: `'/Users/o'\\''neil/.glow/hook' claude-stop`, asyncRewake: true, timeout: 1800 });
    expect(hookEntry('codex', '/h/.glow/hook')).toEqual({ type: 'command', command: `'/h/.glow/hook' codex-stop`, timeout: 15 });
    const once = withHook(theirs, entry);
    const twice = withHook(once, entry);
    expect(twice).toEqual(once);
    expect(once.model).toBe('opus');
    expect(once.hooks.PreToolUse).toEqual(theirs.hooks.PreToolUse);
    expect(once.hooks.Stop).toEqual([{ hooks: [{ type: 'command', command: 'say done' }] }, { hooks: [entry] }]);
    expect(isOurs({ command: 'say done' })).toBe(false);
    expect(withoutHook(once)).toEqual(theirs);
    expect(withoutHook(withHook({}, entry))).toEqual({});
    expect(() => withHook({ hooks: [] }, entry)).toThrow();
    expect(() => withHook({ hooks: { Stop: {} } }, entry)).toThrow();
  });
});

/** A child process, without blocking this one (the fake API answers from here). */
function exec(cmd: string, args: string[], o: { cwd?: string; env: Record<string, string>; input?: string }) {
  return new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
    const p = spawn(cmd, args, { cwd: o.cwd, env: o.env });
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (d) => (stdout += d));
    p.stderr.on('data', (d) => (stderr += d));
    p.on('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
    p.stdin.end(o.input ?? '');
  });
}

test('the version it prints is the published one', () => {
  expect(VERSION).toBe(JSON.parse(fs.readFileSync(path.join(import.meta.dir, '..', 'package.json'), 'utf8')).version);
});

test('the .before-glow backup is always the file as it was before Glow', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glow-backup-'));
  const fresh = path.join(dir, 'hooks.json'); // no file yet: nothing to back up, then or on a re-run
  writeJson(fresh, withHook({}, hookEntry('codex', '/h/.glow/hook')));
  writeJson(fresh, withHook(JSON.parse(fs.readFileSync(fresh, 'utf8')), hookEntry('codex', '/h/.glow/hook')));
  expect(fs.existsSync(`${fresh}.before-glow`)).toBe(false);
  const mine = path.join(dir, 'settings.json');
  fs.writeFileSync(mine, '{"model":"opus"}\n');
  writeJson(mine, withHook({ model: 'opus' }, hookEntry('claude_code', '/h/.glow/hook')));
  writeJson(mine, withoutHook(JSON.parse(fs.readFileSync(mine, 'utf8'))));
  writeJson(mine, withHook({ model: 'opus' }, hookEntry('claude_code', '/h/.glow/hook')));
  expect(fs.readFileSync(`${mine}.before-glow`, 'utf8')).toBe('{"model":"opus"}\n');
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('the hook and the installer against a fake Glow', () => {
  let server: ReturnType<typeof Bun.serve>;
  const reqs: Req[] = [];
  let reply: (r: Req) => { status: number; body?: unknown } = () => ({ status: 404 });
  let home = '';
  let repo = '';
  let other = '';
  const KEY = `glowc_${'k'.repeat(43)}`;

  beforeAll(() => {
    server = Bun.serve({
      hostname: '127.0.0.1', port: 0,
      async fetch(req) {
        const u = new URL(req.url);
        const text = await req.text();
        const r: Req = { method: req.method, path: u.pathname + u.search, auth: req.headers.get('authorization'), body: text ? JSON.parse(text) : null };
        reqs.push(r);
        const out = reply(r);
        return out.body === undefined ? new Response(null, { status: out.status }) : Response.json(out.body, { status: out.status });
      },
    });
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'glow-cli-'));
    const git = (cwd: string, ...a: string[]) => execFileSync('git', ['-C', cwd, ...a], { stdio: 'ignore', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } });
    repo = path.join(home, 'zest');
    other = path.join(home, 'private');
    for (const [d, remote] of [[repo, 'git@github.com:Winding-Labs/Zest.git'], [other, 'git@github.com:winding-labs/private.git']] as const) {
      fs.mkdirSync(d);
      git(d, 'init', '-q', '-b', 'main');
      git(d, 'remote', 'add', 'origin', remote);
      git(d, 'commit', '-q', '--allow-empty', '-m', 'base');
      git(d, 'update-ref', 'refs/remotes/origin/main', 'HEAD');
      git(d, 'symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
      git(d, 'checkout', '-q', '-b', 'seo-titles');
      git(d, 'commit', '-q', '--allow-empty', '-m', 'New recipe titles');
    }
  });
  afterAll(() => {
    server.stop(true);
    fs.rmSync(home, { recursive: true, force: true });
  });

  const api = () => `http://127.0.0.1:${server.port}`;
  const writeCfg = (extra: Record<string, unknown> = {}) => {
    fs.mkdirSync(path.join(home, '.glow'), { recursive: true });
    fs.writeFileSync(path.join(home, '.glow', 'config.json'), JSON.stringify({ api: api(), dev: true, key: KEY, repos: ['winding-labs/zest'], repos_at: Date.now(), ...extra }));
  };
  const hook = (mode: string, input: unknown, env: Record<string, string> = {}) =>
    exec(process.env.NODE ?? 'node', [path.join(ROOT, 'lib', 'hook.mjs'), mode], { env: { PATH: process.env.PATH!, HOME: home, ...env }, input: JSON.stringify(input) });

  test('codex: a linked repo reports (masked, with branch and commits); a waiting message continues the turn', async () => {
    writeCfg();
    reqs.length = 0;
    reply = (r) => (r.path === '/api/v1/agent/reports' ? { status: 202, body: { messages: [{ id: 'm1', from: 'Ed', body: 'Also do the blog', sent_at: '2026-11-02T10:00:00Z' }] } } : { status: 404 });
    const out = await hook('codex-stop', { session_id: 'sess-1', cwd: repo, last_assistant_message: `Done. Opened https://github.com/winding-labs/zest/pull/7 key sk-ant-api03-${'z'.repeat(40)}`, turn_id: 't1', stop_hook_active: false });
    expect(out.code).toBe(0);
    expect(reqs.map((r) => [r.method, r.path, r.auth])).toEqual([['POST', '/api/v1/agent/reports', `Bearer ${KEY}`]]);
    const b = reqs[0]!.body;
    expect(b).toMatchObject({ agent: 'codex', session_id: 'sess-1', repo: 'winding-labs/zest', branch: 'seo-titles', pr_url: 'https://github.com/winding-labs/zest/pull/7' });
    expect(b.commits.map((x: { title: string }) => x.title)).toEqual(['New recipe titles']);
    expect(b.message).not.toContain('sk-ant-api03-z');
    const decision = JSON.parse(out.stdout);
    expect(decision.decision).toBe('block');
    expect(decision.reason).toContain('Message from Ed in Glow');
    expect(decision.reason).toContain('Also do the blog');
  });

  test('an unlinked repo sends nothing (one config refresh at most); off sends nothing; no config sends nothing', async () => {
    writeCfg({ repos_at: 0 });
    reqs.length = 0;
    reply = (r) => (r.path === '/api/v1/agent/config' ? { status: 200, body: { repos: ['winding-labs/zest'] } } : { status: 500 });
    expect((await hook('codex-stop', { session_id: 's', cwd: other, last_assistant_message: 'secret plans' })).code).toBe(0);
    expect((await hook('codex-stop', { session_id: 's', cwd: other, last_assistant_message: 'secret plans' })).code).toBe(0);
    expect(reqs.map((r) => r.path)).toEqual(['/api/v1/agent/config']);
    writeCfg({ off: true });
    reqs.length = 0;
    await hook('codex-stop', { session_id: 's', cwd: repo, last_assistant_message: 'x' });
    fs.rmSync(path.join(home, '.glow', 'config.json'));
    await hook('codex-stop', { session_id: 's', cwd: repo, last_assistant_message: 'x' });
    expect(reqs).toEqual([]);
  });

  test('the API address comes from the config only, never the environment; a non-Glow address sends nothing', async () => {
    writeCfg({ api: 'https://evil.example', dev: false });
    reqs.length = 0;
    await hook('codex-stop', { session_id: 's', cwd: repo, last_assistant_message: 'x' }, { GLOW_API: api(), GLOW_URL: api() });
    expect(reqs).toEqual([]);
  });

  test('claude: no message waiting → it listens, and a message from Glow wakes the session (stderr, exit 2)', async () => {
    writeCfg();
    reqs.length = 0;
    let polls = 0;
    reply = (r) => {
      if (r.path === '/api/v1/agent/reports') return { status: 202, body: { messages: [] } };
      if (r.path.startsWith('/api/v1/agent/inbox')) return ++polls < 2 ? { status: 200, body: { messages: [] } } : { status: 200, body: { messages: [{ id: 'm2', from: 'Ed', body: 'Ship it', sent_at: '2026-11-02T10:00:00Z' }] } };
      return { status: 404 };
    };
    const out = await hook('claude-stop', { session_id: 'abc-123', cwd: repo, last_assistant_message: 'Fixed the titles.', stop_hook_active: false }, { GLOW_POLL_MS: '100' });
    expect(out.code).toBe(2);
    expect(out.stderr).toContain('Message from Ed in Glow');
    expect(out.stderr).toContain('Ship it');
    expect(reqs.map((r) => r.path)).toEqual(['/api/v1/agent/reports', '/api/v1/agent/inbox?agent=claude_code&session=abc-123', '/api/v1/agent/inbox?agent=claude_code&session=abc-123']);
  });

  test('messages off here: the report says so (Glow takes nothing for it) and Claude Code doesn’t listen', async () => {
    writeCfg({ messages: false });
    reqs.length = 0;
    reply = (r) => (r.path === '/api/v1/agent/reports' ? { status: 202, body: { messages: [{ id: 'm1', from: 'Ed', body: 'Ignored', sent_at: '2026-11-02T10:00:00Z' }] } } : { status: 200, body: { messages: [] } });
    const out = await hook('claude-stop', { session_id: 'abc-125', cwd: repo, last_assistant_message: 'Done.' }, { GLOW_POLL_MS: '50' });
    expect([out.code, out.stderr]).toEqual([0, '']);
    expect(reqs.map((r) => [r.path, (r.body as { inbox?: boolean } | null)?.inbox])).toEqual([['/api/v1/agent/reports', false]]);
  });

  // L1 (review-2026-11-02-agent-reports.md): a repo's own .git/config (log.showSignature + gpg.program) used to make
  // the hook's `git log` run a program. Control first: the same git log without the hook's flags runs it.
  test('a repo’s .git/config can’t make the hook run a program', async () => {
    const signed = path.join(home, 'signed');
    const pwned = path.join(home, 'pwned');
    const gpg = path.join(home, 'fake-gpg.sh');
    fs.writeFileSync(gpg, `#!/bin/sh\ncase "$*" in *--verify*) touch ${JSON.stringify(pwned)}; exit 1;; esac\necho '[GNUPG:] SIG_CREATED ' >&2\nprintf -- '-----BEGIN PGP SIGNATURE-----\\nx\\n-----END PGP SIGNATURE-----\\n'\n`, { mode: 0o755 });
    const git = (...a: string[]) => execFileSync('git', ['-C', signed, ...a], { stdio: 'ignore', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } });
    fs.mkdirSync(signed);
    git('init', '-q', '-b', 'main');
    git('remote', 'add', 'origin', 'git@github.com:winding-labs/zest.git');
    git('commit', '-q', '--allow-empty', '-m', 'base');
    git('update-ref', 'refs/remotes/origin/main', 'HEAD');
    git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
    git('checkout', '-q', '-b', 'feature');
    git('-c', `gpg.program=${gpg}`, 'commit', '-q', '-S', '--allow-empty', '-m', 'signed');
    git('config', 'log.showSignature', 'true');
    git('config', 'gpg.program', gpg);
    try {
      git('log', '-n', '1', 'origin/main..HEAD');
    } catch {}
    expect(fs.existsSync(pwned)).toBe(true); // the control: a plain git log would run it
    fs.rmSync(pwned);
    writeCfg();
    reqs.length = 0;
    reply = () => ({ status: 202, body: { messages: [] } });
    // and GIT_CONFIG_PARAMETERS from the agent's environment can't turn it back on
    await hook('codex-stop', { session_id: 'sig', cwd: signed, last_assistant_message: 'x' }, { GIT_CONFIG_PARAMETERS: "'log.showsignature'='true'" });
    expect(fs.existsSync(pwned)).toBe(false);
    expect((reqs[0]?.body as { commits: { title: string }[] }).commits.map((c) => c.title)).toEqual(['signed']);
  }, 30_000); // ten git processes: slow on a busy machine

  test('claude: a revoked key stops listening at once', async () => {
    writeCfg();
    reqs.length = 0;
    reply = (r) => (r.path === '/api/v1/agent/reports' ? { status: 202, body: { messages: [] } } : { status: 401, body: { code: 'invalid_key' } });
    const out = await hook('claude-stop', { session_id: 'abc-124', cwd: repo, last_assistant_message: 'Done.' }, { GLOW_POLL_MS: '50' });
    expect(out.code).toBe(0);
    expect(reqs.filter((r) => JSON.stringify(r).includes('abc-124')).length).toBe(2); // the report, then one inbox poll
  });

  test('setup: finds the agents, pairs, writes an owner-only config and both hooks; uninstall undoes it and revokes the key', async () => {
    fs.rmSync(path.join(home, '.glow'), { recursive: true, force: true });
    const bin = path.join(home, 'bin');
    fs.mkdirSync(bin, { recursive: true });
    for (const b of ['claude', 'codex']) fs.writeFileSync(path.join(bin, b), '#!/bin/sh\n', { mode: 0o755 });
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    fs.mkdirSync(path.join(home, 'dotfiles'), { recursive: true });
    fs.writeFileSync(path.join(home, 'dotfiles', 'claude.json'), JSON.stringify({ model: 'opus', hooks: { Stop: [{ hooks: [{ type: 'command', command: 'say done' }] }] } }));
    fs.symlinkSync(path.join(home, 'dotfiles', 'claude.json'), path.join(home, '.claude', 'settings.json'));
    reqs.length = 0;
    let claims = 0;
    reply = (r) => {
      if (r.path === '/api/v1/agent/pairings') return { status: 201, body: { code: 'ABCD-2345', secret: 's'.repeat(43), url: 'https://evil.example/', expires_at: '', interval_s: 2 } };
      if (r.path === '/api/v1/agent/pairings/claim') {
        claims++;
        const confirm = (r.body as { confirm?: string }).confirm;
        if (!confirm) return { status: 202, body: { status: claims < 2 ? 'waiting' : 'confirm' } };
        if (confirm !== '482913') return { status: 400, body: { error: 'That isn’t the code Glow showed. 4 tries left.', code: 'invalid' } };
        return { status: 200, body: { status: 'approved', key: KEY, computer: { id: 'c1', name: 'Test Mac' }, workspace: { id: 'w1', name: 'Win\u001b]0;pwn\u0007ding' }, repos: ['winding-labs/zest'] } };
      }
      if (r.path === '/api/v1/agent/computer') return { status: 204 };
      return { status: 404 };
    };
    const run = (args: string[], input = '') => exec(process.env.NODE ?? 'node', [path.join(ROOT, 'bin', 'glow.mjs'), ...args], { cwd: repo, env: { PATH: `${bin}:${process.env.PATH}`, HOME: home }, input });
    // typed: something that isn't six digits, a wrong code, the right one (all piped at once: none may be lost)
    const out = (await run(['--dev', '--api', api(), '--no-open', '--name', 'Test Mac'], '12\n000000\n482 913\n')).stdout;
    expect(out).toContain(`${api()}/app/pair?code=ABCD-2345`); // its own link, not the server's
    expect(out).not.toContain('evil.example');
    expect(out).toContain('Six digits');
    expect(out).toContain('4 tries left');
    expect(out).toContain('Paired');
    expect(out).toContain('Win]0;pwnding'); // the server's text, without its escape sequences
    expect(out).not.toContain('\u001b]0;');
    expect(reqs.filter((r) => r.path.endsWith('/claim')).map((r) => (r.body as { confirm?: string }).confirm ?? null)).toEqual([null, null, '000000', '482913']);
    expect(reqs[0]!.body).toEqual({ name: 'Test Mac', agents: ['claude_code', 'codex'], repo: 'winding-labs/zest' });
    expect(reqs[0]!.auth).toBeNull();
    const glow = path.join(home, '.glow');
    expect(fs.statSync(glow).mode & 0o777).toBe(0o700);
    expect(fs.statSync(path.join(glow, 'config.json')).mode & 0o777).toBe(0o600);
    expect(fs.statSync(path.join(glow, 'hook')).mode & 0o777).toBe(0o700);
    expect(JSON.parse(fs.readFileSync(path.join(glow, 'config.json'), 'utf8'))).toMatchObject({ api: api(), dev: true, key: KEY, repos: ['winding-labs/zest'] });
    const claude = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'));
    expect(claude.model).toBe('opus');
    expect(fs.lstatSync(path.join(home, '.claude', 'settings.json')).isSymbolicLink()).toBe(true); // dotfiles: still a link
    expect(JSON.parse(fs.readFileSync(path.join(home, 'dotfiles', 'claude.json'), 'utf8')).hooks.Stop.length).toBe(2);
    expect(claude.hooks.Stop.length).toBe(2);
    expect(claude.hooks.Stop[1].hooks[0]).toMatchObject({ asyncRewake: true, timeout: 1800 });
    expect(fs.existsSync(path.join(home, '.claude', 'settings.json.before-glow'))).toBe(true);
    const codex = JSON.parse(fs.readFileSync(path.join(home, '.codex', 'hooks.json'), 'utf8'));
    expect(codex.hooks.Stop[0].hooks[0].command).toEndWith('codex-stop');
    // the installed hook runs from ~/.glow, through the shim
    reqs.length = 0;
    reply = () => ({ status: 202, body: { messages: [] } });
    await exec(path.join(glow, 'hook'), ['codex-stop'], { input: JSON.stringify({ session_id: 's9', cwd: repo, last_assistant_message: 'hi' }), env: { PATH: process.env.PATH!, HOME: home, NODE_OPTIONS: '--require /nonexistent.js' } });
    expect(reqs.map((r) => r.path)).toEqual(['/api/v1/agent/reports']);
    // L2: the shim hands node an empty environment but HOME and PATH (no proxy, TLS or NODE_* setting gets through)
    const shim = fs.readFileSync(path.join(glow, 'hook'), 'utf8');
    expect(shim).toContain('exec env -i HOME="$HOME" PATH="$PATH"');
    reqs.length = 0;
    await exec(path.join(glow, 'hook'), ['codex-stop'], { input: JSON.stringify({ session_id: 's10', cwd: repo, last_assistant_message: 'hi' }), env: { PATH: process.env.PATH!, HOME: home, NODE_USE_ENV_PROXY: '1', HTTP_PROXY: 'http://127.0.0.1:9', HTTPS_PROXY: 'http://127.0.0.1:9', NODE_TLS_REJECT_UNAUTHORIZED: '0' } });
    expect(reqs.map((r) => r.path)).toEqual(['/api/v1/agent/reports']); // straight to Glow, not the proxy

    reqs.length = 0;
    reply = () => ({ status: 204 });
    await run(['uninstall']);
    expect(reqs.map((r) => [r.method, r.path, r.auth])).toEqual([['DELETE', '/api/v1/agent/computer', `Bearer ${KEY}`]]);
    expect(fs.existsSync(glow)).toBe(false);
    expect(JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'))).toEqual({ model: 'opus', hooks: { Stop: [{ hooks: [{ type: 'command', command: 'say done' }] }] } });
    expect(fs.lstatSync(path.join(home, '.claude', 'settings.json')).isSymbolicLink()).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(home, '.codex', 'hooks.json'), 'utf8'))).toEqual({});
  }, 40_000);
});
