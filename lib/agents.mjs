// Which coding agents are on this computer, and adding or removing the Glow hook in each one's own settings:
//   Claude Code  ~/.claude/settings.json  hooks.Stop: the hook in the background (asyncRewake), so it can wake an idle
//                session when a message arrives
//   Codex        ~/.codex/hooks.json      hooks.Stop: the hook before the turn ends (≤ 15 s; it takes about a second)
// Every other key in those files is kept as it was. A file that isn't valid JSON is never overwritten.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { dir, writeFileAtomic } from './core.mjs';

export const AGENTS = {
  claude_code: { label: 'Claude Code', bin: 'claude', home: '.claude', file: ['.claude', 'settings.json'], mode: 'claude-stop' },
  codex: { label: 'Codex', bin: 'codex', home: '.codex', file: ['.codex', 'hooks.json'], mode: 'codex-stop' },
};

export const settingsFile = (id) => path.join(os.homedir(), ...AGENTS[id].file);
export const shimPath = () => path.join(dir(), 'hook');

/** On PATH, or its settings folder exists. */
export function detect() {
  const dirs = String(process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const onPath = (bin) => dirs.some((d) => {
    try {
      fs.accessSync(path.join(d, bin), fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
  return Object.keys(AGENTS).filter((id) => onPath(AGENTS[id].bin) || fs.existsSync(path.join(os.homedir(), AGENTS[id].home)));
}

/** POSIX single-quoting for a path in a hook command. */
export const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

export function hookEntry(id, shim = shimPath()) {
  const command = `${shq(shim)} ${AGENTS[id].mode}`;
  return id === 'claude_code' ? { type: 'command', command, asyncRewake: true, timeout: 1800 } : { type: 'command', command, timeout: 15 };
}

/** One of ours: a command that runs ~/.glow/hook. */
export const isOurs = (h) => !!h && typeof h === 'object' && typeof h.command === 'string' && /[/\\]\.glow[/\\]hook['"]?\s/.test(`${h.command} `);

/** The settings with our Stop hook (replacing any older one of ours); everything else untouched. */
export function withHook(settings, entry) {
  const s = { ...settings };
  if (s.hooks !== undefined && (typeof s.hooks !== 'object' || s.hooks === null || Array.isArray(s.hooks))) throw new Error('its "hooks" isn’t an object');
  const hooks = { ...(s.hooks ?? {}) };
  if (hooks.Stop !== undefined && !Array.isArray(hooks.Stop)) throw new Error('its "hooks.Stop" isn’t a list');
  const groups = stripOurs(hooks.Stop ?? []);
  hooks.Stop = [...groups, { hooks: [entry] }];
  s.hooks = hooks;
  return s;
}

/** The settings without our hook; empty groups and an empty "hooks" go too. */
export function withoutHook(settings) {
  if (!settings?.hooks || typeof settings.hooks !== 'object' || !Array.isArray(settings.hooks.Stop)) return settings;
  const s = { ...settings, hooks: { ...settings.hooks } };
  const groups = stripOurs(s.hooks.Stop);
  if (groups.length) s.hooks.Stop = groups;
  else delete s.hooks.Stop;
  if (!Object.keys(s.hooks).length) delete s.hooks;
  return s;
}

function stripOurs(groups) {
  return groups
    .map((g) => (g && typeof g === 'object' && Array.isArray(g.hooks) ? { ...g, hooks: g.hooks.filter((h) => !isOurs(h)) } : g))
    .filter((g) => !(g && typeof g === 'object' && Array.isArray(g.hooks) && g.hooks.length === 0));
}

export const hasHook = (settings) => Array.isArray(settings?.hooks?.Stop) && settings.hooks.Stop.some((g) => Array.isArray(g?.hooks) && g.hooks.some(isOurs));

/** The file's JSON ({} when missing). Throws when it exists but isn't a JSON object, so it's never clobbered. */
export function readJson(file) {
  if (!fs.existsSync(file)) return {};
  const text = fs.readFileSync(file, 'utf8');
  if (!text.trim()) return {};
  const v = JSON.parse(text);
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('it isn’t a JSON object');
  return v;
}

/**
 * Write next to the original with its mode kept; the first time, the original is copied to <file>.before-glow. A
 * symlinked settings file (dotfiles) is written through to its target, so the link stays a link.
 */
export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const target = fs.existsSync(file) ? fs.realpathSync(file) : file;
  let mode = 0o644;
  if (fs.existsSync(target)) {
    mode = fs.statSync(target).mode & 0o777;
    const backup = `${file}.before-glow`;
    if (!fs.existsSync(backup)) fs.copyFileSync(target, backup);
  }
  writeFileAtomic(target, `${JSON.stringify(value, null, 2)}\n`, mode);
}

export function install(id) {
  const file = settingsFile(id);
  writeJson(file, withHook(readJson(file), hookEntry(id)));
  return file;
}

export function uninstall(id) {
  const file = settingsFile(id);
  if (!fs.existsSync(file)) return null;
  const before = readJson(file);
  if (!hasHook(before)) return null;
  writeJson(file, withoutHook(before));
  return file;
}

export const installed = (id) => {
  try {
    return hasHook(readJson(settingsFile(id)));
  } catch {
    return false;
  }
};
