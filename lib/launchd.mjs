// macOS: the runner as a LaunchAgent (`glow run --background`), so it starts again at login after a restart, and after
// a crash (docs/security/review-2026-11-03-signed-runs.md, "2026-11-05: runs pick up again"). Yours only: a plist in
// ~/Library/LaunchAgents, loaded into your login session (launchctl bootstrap gui/<uid>), no root, nothing system-wide.
// `glow run stop` and `glow uninstall` unload it (bootout) and remove it. Nothing changes on Linux.
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const AGENT_LABEL = 'ai.meetglow.runner';
export const agentPlistPath = (home = os.homedir()) => path.join(home, 'Library', 'LaunchAgents', `${AGENT_LABEL}.plist`);
const LAUNCHCTL = '/bin/launchctl';

/** launchd here: macOS, with HOME this account's own home (a HOME pointed elsewhere, as in the tests, never touches
 *  ~/Library or launchctl). */
export function launchdHere(platform = process.platform, env = process.env) {
  if (platform !== 'darwin') return false;
  try {
    return path.resolve(env.HOME ?? '') === os.userInfo().homedir;
  } catch {
    return false;
  }
}

/** PATH for the runner under launchd (which starts it with almost none): yours when you set it up, where claude, git
 *  and node are, without npx's own temporary folders (gone after). */
export const agentPath = (p = process.env.PATH ?? '') =>
  [...new Set(String(p).split(':').filter((d) => d.startsWith('/') && !/\/_npx\/|\/node_modules\/\.bin$/.test(d)))].join(':') || '/usr/bin:/bin:/usr/sbin:/sbin';

const xml = (s) => String(s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/**
 * The LaunchAgent: `<node> <script> run <roots…> [--repo …]`, started at login (RunAtLoad) and again only after a crash
 * (KeepAlive SuccessfulExit false: the runner exits 0 whenever it's meant to stop: run stop, off, not set up). Its output
 * goes to runner.log. Its environment is HOME, PATH (agentPath), and LANG and CLAUDE_CONFIG_DIR when set: no key or
 * token. 30 s to stop its sessions and tell Glow before launchd's SIGKILL.
 */
export function agentPlist({ node, script, args, home, cwd, log, env = process.env }) {
  const str = (s) => `<string>${xml(s)}</string>`;
  const vars = { HOME: home, PATH: agentPath(env.PATH), ...(env.LANG ? { LANG: env.LANG } : {}), ...(env.CLAUDE_CONFIG_DIR ? { CLAUDE_CONFIG_DIR: env.CLAUDE_CONFIG_DIR } : {}) };
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>${str(AGENT_LABEL)}
  <key>ProgramArguments</key>
  <array>${[node, script, 'run', ...args].map(str).join('')}</array>
  <key>EnvironmentVariables</key>
  <dict>${Object.entries(vars).map(([k, v]) => `<key>${xml(k)}</key>${str(v)}`).join('')}</dict>
  <key>WorkingDirectory</key>${str(cwd)}
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key>${str('Interactive')}
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ExitTimeOut</key><integer>30</integer>
  <key>StandardOutPath</key>${str(log)}
  <key>StandardErrorPath</key>${str(log)}
</dict>
</plist>
`;
}

const launchctl = (args) => new Promise((resolve) => {
  execFile(LAUNCHCTL, args, { encoding: 'utf8', timeout: 30_000 }, (err, out, errOut) => resolve({ ok: !err, text: String(errOut || out || err?.message || '').trim().split('\n').pop() }));
});
const domain = () => `gui/${process.getuid()}`;

/** Write the LaunchAgent and load it (it starts at once). Null when it's on, else what launchctl said. */
export async function installAgent(o) {
  const file = agentPlistPath(o.home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, agentPlist(o), { mode: 0o644 });
  await launchctl(['bootout', `${domain()}/${AGENT_LABEL}`]); // an older one, if loaded
  const r = await launchctl(['bootstrap', domain(), file]);
  return r.ok ? null : r.text || 'launchctl bootstrap failed';
}

/** Unload the LaunchAgent (launchd stops the runner it started) and remove it. True if there was one. */
export async function removeAgent(home = os.homedir()) {
  const file = agentPlistPath(home);
  const had = fs.existsSync(file);
  const r = had ? await launchctl(['bootout', `${domain()}/${AGENT_LABEL}`]) : { ok: false };
  fs.rmSync(file, { force: true });
  return had || r.ok;
}

/** Start the LaunchAgent's runner if it's loaded and not running (after `glow on`). */
export const kickAgent = async (home = os.homedir()) => fs.existsSync(agentPlistPath(home)) && (await launchctl(['kickstart', `${domain()}/${AGENT_LABEL}`])).ok;
