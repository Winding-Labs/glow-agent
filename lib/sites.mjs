// Site logins a listing run makes (docs/security/review-2026-11-06-site-accounts-and-posting.md, Part 1). Plain Node
// 18+, no dependencies.
//
//  - A listing run is one whose signed prompt starts with `Task: Site listings · <Product>` or `Task: Rotate listing
//    logins · <Product>` and carries one `Sites: a.com, b.org, …` line (at most 15) and, optionally, one `Email: <the
//    product's listings alias>` line (listingOf). The runner reads them only from what the Glow phone signed.
//  - Its agent gets a browser and the `glow-sites` MCP server (lib/sites-mcp.mjs), nothing else. The helper makes each
//    password here (Node's CSPRNG, `gs-xxxxx-xxxxx-xxxxx-xxxxx`, base58), keeps it in the login keychain (service
//    ai.meetglow.sites, account <product>:<site>; the password goes to `security -i` on stdin, never in argv), puts it
//    on the clipboard for 30 s (this Mac only, marked concealed and transient; cleared after if nothing else was copied)
//    and answers the agent with the site, username and item: never the password. It serves only the sites the signed
//    brief names.
//  - Before a password reaches the clipboard, the helper hands it to the runner (a socket the runner opened for that
//    run), which masks it by value in everything it sends to Glow. Nothing comes back over that socket.
//  - `inbox` asks the listings mail relay (lib/listing-mail.gs: an Apps Script on a member of the listing@ group, read-only
//    Gmail, a key only this Mac's keychain holds) for mail to the brief's alias from the last 30 minutes, and returns only
//    links on the site's own domain and short numeric codes.
//  - Glow never gets a password. `glow sites export` writes them to a 0600 CSV for 1Password's import, at a terminal,
//    after you type `export`.
//  - `brand_file` downloads the product's own logo or screenshots from its Glow brand kit into the run's brand folder
//    (0400, named by the helper) and records each file's realpath, hash and size in a manifest outside the folders the
//    browser writes to. The browser filter (sites-browser.mjs) lets browser_file_upload send only those files, unchanged,
//    and refuses any tool's `filename` (so nothing the model names is written for a page to take).
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { api, apiBase, dir, printable, readConfig, SESSION_RE, VERSION, writeFileAtomic } from './core.mjs';

export const SERVICE = 'ai.meetglow.sites';
const MAIL_SERVICE = 'ai.meetglow.sites.mail';
export const SITES_MAX = 15;
const CLIP_MS = 30_000;
/** The browser a listing run drives: Playwright's MCP server over the installed Chrome, this exact version. */
export const PLAYWRIGHT_MCP = '@playwright/mcp@0.0.83';
/** What a listing run may use (the browser and the helper), and the browser tools it may not (code in the server
 *  process, script in the page that could read a pasted password back, a file dropped onto the page, which hands a page
 *  what Playwright saved in the run's folder unmasked, such as a snapshot with a password field's value; a request's
 *  headers, which carry the site's session cookie). browser_file_upload is allowed for brand_file's files only: the
 *  filter checks each path against the helper's manifest (browserCall). */
export const LISTING_TOOLS = ['mcp__glow-browser', 'mcp__glow-sites'];
export const LISTING_DENY = ['mcp__glow-browser__browser_run_code_unsafe', 'mcp__glow-browser__browser_evaluate', 'mcp__glow-browser__browser_drop', 'mcp__glow-browser__browser_network_request'];

export const listingsDir = () => path.join(dir(), 'listings');
/** A product's own Chrome profile (its slug, as listingOf makes it): its listing runs stay signed in to its accounts
 *  only, never another product's (2026-11-07: one profile for all of them put drafts in other products' accounts). */
export const browserProfile = (slug) => {
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(String(slug ?? ''))) throw new Error('bad_slug');
  return path.join(dir(), 'browsers', `listing-${slug}`);
};
const indexPath = () => path.join(listingsDir(), 'logins.json');

// ---------- which runs are listing runs ----------

const TITLES = { 'Site listings · ': 'listings', 'Rotate listing logins · ': 'rotate' };
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const EMAIL = /^[a-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/**
 * A listing run's brief, from the prompt the phone signed: { kind, product, slug, sites, email? }; { error } when its
 * title says listing but the rest doesn't hold (such a run never runs, and never as a full-access one); null for any
 * other run.
 */
export function listingOf(prompt) {
  const lines = String(prompt ?? '').split('\n').map((l) => l.trim());
  const first = (lines[0] ?? '').replace(/^Task:\s*/, '');
  const prefix = Object.keys(TITLES).find((p) => first.startsWith(p));
  if (!prefix) return null;
  const product = first.slice(prefix.length).split(' · ')[0].trim();
  const slug = product.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  if (!slug) return { error: 'no product in its title' };
  const said = lines.filter((l) => l.startsWith('Sites:'));
  if (said.length !== 1) return { error: said.length ? 'more than one Sites line' : 'no Sites line' };
  const sites = [...new Set(said[0].slice('Sites:'.length).split(/[,\s]+/).map((s) => s.toLowerCase().replace(/\.$/, '')).filter(Boolean))];
  if (!sites.length || sites.length > SITES_MAX) return { error: `${sites.length} sites on its Sites line (1 to ${SITES_MAX})` };
  const bad = sites.find((s) => !DOMAIN.test(s));
  if (bad) return { error: `not a domain on its Sites line: ${printable(bad, 60)}` };
  const mails = lines.filter((l) => l.startsWith('Email:'));
  const email = mails[0]?.slice('Email:'.length).trim().toLowerCase();
  if (mails.length > 1 || (email !== undefined && !EMAIL.test(email))) return { error: 'its Email line isn’t one address' };
  return { kind: TITLES[prefix], product: printable(product, 80), slug, sites, ...(email ? { email } : {}) };
}

/** The brief's site this is (a host or URL on it, its subdomains too), else null. */
export function siteIn(sites, raw) {
  let h = String(raw ?? '').trim().toLowerCase();
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(h)) {
    try {
      h = new URL(h).hostname;
    } catch {
      return null;
    }
  }
  h = h.replace(/[/?#].*$/, '').replace(/\.$/, '');
  return sites.find((s) => h === s || h.endsWith(`.${s}`)) ?? null;
}

/** A login page as kept: https on the site (or a subdomain), no query, fragment or credentials. */
function loginUrl(raw, site) {
  try {
    const u = new URL(String(raw ?? ''));
    if (u.protocol !== 'https:' || u.username || u.password || siteIn([site], u.hostname) !== site) return null;
    return `${u.origin}${u.pathname}`.slice(0, 300);
  } catch {
    return null;
  }
}

// ---------- passwords ----------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const C58 = '[1-9A-HJ-NP-Za-km-z]';
export const PASSWORD_RE = new RegExp(`^gs-${C58}{5}(?:-${C58}{5}){3}$`);
export const SHORT_PASSWORD_RE = new RegExp(`^gs!${C58}{13}$`);

/** A new site password: 20 base58 characters (about 117 bits) as gs-xxxxx-xxxxx-xxxxx-xxxxx, or 13 (about 76 bits) as
 *  the 16-character gs!xxxxxxxxxxxxx for a site that caps length. Drawn again until it has a digit, an upper and a
 *  lower case letter. */
export function newPassword(short = false, pick = randomInt) {
  for (;;) {
    let s = '';
    for (let i = 0; i < (short ? 13 : 20); i++) s += B58[pick(58)];
    if (/\d/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s)) return short ? `gs!${s}` : `gs-${s.match(/.{5}/g).join('-')}`;
  }
}

/** Both password shapes (and the short one form-encoded), wherever they are in a text (the same rows as core.mjs's
 *  KEY_SHAPES). */
const SHAPES = new RegExp(`\\bgs(?:-${C58}{5}(?:-${C58}{5}){3}|(?:!|%21)${C58}{13})(?![0-9A-Za-z])`, 'g');
export const maskShapes = (text) => String(text).replace(SHAPES, '[masked]');

/** Every value in `secrets` (and its form-encoded spelling) → [masked]. */
export function maskValues(secrets, text) {
  let s = String(text);
  for (const v of secrets ?? []) for (const w of new Set([v, v.replace(/!/g, '%21')])) s = s.split(w).join('[masked]');
  return s;
}

// ---------- the store: the login keychain (1Password: see storeFor) ----------

const SAFE_SECRET = /^[A-Za-z0-9+/=!_.-]{1,8000}$/;
const quoted = (s) => `"${String(s).replace(/[^\p{L}\p{N} ·@._:/+-]/gu, '')}"`;

/**
 * Logins in the macOS login keychain: one generic password per site (service ai.meetglow.sites, account
 * <product>:<site>, label "Glow listing · …"), plus an index of what's there (~/.glow/listings/logins.json, 0600:
 * product, site, username, login URL, when; never a password). The password reaches `security` on stdin (`security -i`),
 * never as an argument, where `ps` would show it; each write is read back. Items `security` made are read by it again
 * without a prompt.
 */
export function keychainStore({ security = '/usr/bin/security', index = indexPath(), keychain } = {}) {
  const kc = keychain ? [keychain] : [];
  const read = (service, account) => {
    try {
      return execFileSync(security, ['find-generic-password', '-s', service, '-a', account, '-w', ...kc], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15_000 }).replace(/\n$/, '');
    } catch {
      return null;
    }
  };
  const write = (service, account, secret, label, comment) => {
    if (!SAFE_SECRET.test(secret)) throw new Error('store_failed');
    // `security -i` reads its commands on stdin and exits 0 whatever happened: the read-back is the check.
    execFileSync(security, ['-i'], {
      input: `add-generic-password -U -s ${quoted(service)} -a ${quoted(account)} -l ${quoted(label)} -j ${quoted(comment)} -w "${secret}"${keychain ? ` ${quoted(keychain)}` : ''}\n`,
      stdio: ['pipe', 'ignore', 'ignore'], timeout: 15_000,
    });
    if (read(service, account) !== secret) throw new Error('store_failed');
  };
  const rows = () => {
    try {
      const all = JSON.parse(fs.readFileSync(index, 'utf8'));
      return Array.isArray(all) ? all.filter((r) => r && typeof r.product === 'string' && typeof r.site === 'string') : [];
    } catch {
      return [];
    }
  };
  return {
    put({ product, site, username, url, password }) {
      const account = `${product}:${site}`;
      write(SERVICE, account, password, `Glow listing · ${product} · ${site}`, `${username} · ${url}`);
      const item = `${SERVICE}/${account}`;
      fs.mkdirSync(path.dirname(index), { recursive: true, mode: 0o700 });
      writeFileAtomic(index, `${JSON.stringify([...rows().filter((r) => r.product !== product || r.site !== site), { product, site, username, url, item, updated_at: new Date().toISOString() }], null, 1)}\n`, 0o600);
      return item;
    },
    get({ product, site }) {
      const row = rows().find((r) => r.product === product && r.site === site);
      const password = read(SERVICE, `${product}:${site}`);
      return password ? { item: `${SERVICE}/${product}:${site}`, ...row, password } : null;
    },
    list: rows,
    /** The listings mail relay (its web app URL and key), or null. */
    mail() {
      try {
        const m = JSON.parse(Buffer.from(read(MAIL_SERVICE, 'relay') ?? '', 'base64').toString('utf8'));
        return RELAY_URL.test(m?.url) && typeof m.key === 'string' ? m : null;
      } catch {
        return null;
      }
    },
    setMail(m) {
      write(MAIL_SERVICE, 'relay', Buffer.from(JSON.stringify({ url: m.url, key: m.key })).toString('base64'), 'Glow listings mail relay', 'listing@ group');
    },
  };
}

/**
 * Where logins go. Today the login keychain. A 1Password store (a service account that reaches only a "Glow Listings"
 * vault; OP_SERVICE_ACCOUNT_TOKEN from the keychain, never the environment of a run) slots in here with the same put, get
 * and list: `op item create` with the item as a JSON template on stdin, `op item get --fields password` (never a
 * password in argv). Not built: 1Password's CLI isn't on this computer to check it against.
 */
export const storeFor = () => keychainStore();

// ---------- the clipboard (macOS) ----------

const CLIP_SET = `ObjC.import('AppKit');
function run(argv) {
  const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
  const text = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);
  const pb = argv[0] ? $.NSPasteboard.pasteboardWithName(argv[0]) : $.NSPasteboard.generalPasteboard;
  pb.prepareForNewContentsWithOptions($.NSPasteboardContentsCurrentHostOnly);
  pb.setStringForType(text, $.NSPasteboardTypeString);
  pb.setStringForType($(''), $('org.nspasteboard.ConcealedType'));
  pb.setStringForType($(''), $('org.nspasteboard.TransientType'));
  return String(pb.changeCount);
}`;
const CLIP_CLEAR = `ObjC.import('AppKit');
function run(argv) {
  const pb = argv[1] ? $.NSPasteboard.pasteboardWithName(argv[1]) : $.NSPasteboard.generalPasteboard;
  if (String(pb.changeCount) === argv[0]) pb.clearContents;
  return '';
}`;

/** The clipboard: a value (on stdin) for this Mac only (no Universal Clipboard), marked concealed and transient so
 *  clipboard managers skip it; cleared later only if nothing was copied since (its change count). */
export function macClipboard({ osascript = '/usr/bin/osascript', board = '' } = {}) {
  return {
    put: (value) => execFileSync(osascript, ['-l', 'JavaScript', '-e', CLIP_SET, ...(board ? [board] : [])], { input: value, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'], timeout: 10_000 }).trim(),
    clear(count) {
      try {
        execFileSync(osascript, ['-l', 'JavaScript', '-e', CLIP_CLEAR, String(count), ...(board ? [board] : [])], { stdio: 'ignore', timeout: 10_000 });
      } catch {
        // nothing to clear
      }
    },
  };
}

// ---------- telling the runner what to mask ----------

/** The runner's side, one per listing run: a socket that takes values to mask ({"mask": "…"} a line) and answers ok.
 *  Nothing is ever read back from it, so whoever else can reach it can only add to what's masked. */
export function secretsListener(file, secrets) {
  return new Promise((resolve) => {
    fs.rmSync(file, { force: true });
    const server = net.createServer((c) => {
      let buf = '';
      c.setEncoding('utf8');
      c.on('error', () => undefined);
      c.on('data', (d) => {
        buf += d;
        if (buf.length > 4096) return c.destroy();
        for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
          let v;
          try {
            v = JSON.parse(buf.slice(0, i))?.mask;
          } catch {
            v = undefined;
          }
          buf = buf.slice(i + 1);
          const ok = typeof v === 'string' && v.length >= 8 && v.length <= 200 && secrets.size < 500;
          if (ok) secrets.add(v);
          c.write(ok ? 'ok\n' : 'no\n');
        }
      });
    });
    server.on('error', () => resolve(null));
    server.listen(file, () => {
      try {
        fs.chmodSync(file, 0o600);
      } catch {
        // the folder is 0700 anyway
      }
      resolve(server);
    });
  });
}

/** The helper's side: the runner has this value (and masks it) before it's released, or it isn't released. */
export const releaseTo = (file, timeoutMs = 3000) => (value) => new Promise((resolve, reject) => {
  const c = net.createConnection(file);
  let got = '';
  const done = (err) => {
    clearTimeout(t);
    c.destroy();
    if (err) reject(new Error(err));
    else resolve();
  };
  const t = setTimeout(() => done('runner_unreachable'), timeoutMs);
  c.on('connect', () => c.write(`${JSON.stringify({ mask: value })}\n`));
  c.on('data', (d) => {
    got += d;
    if (got.includes('\n')) done(got.startsWith('ok') ? null : 'runner_refused');
  });
  c.on('error', () => done('runner_unreachable'));
});

// ---------- the listings mail (a relay on the group member's account) ----------

const MAIL_WINDOW_MS = 30 * 60_000;
const CODE = /\b(?:codes?|verif\w*|otp|pin|passcode|one-time)\b\D{0,40}?\b(\d{4,8})\b/gi;
/** A deployed Apps Script web app: lib/listing-mail.gs. */
export const RELAY_URL = /^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]{20,200}\/exec$/;
export const RELAY_SCRIPT = fileURLToPath(new URL('./listing-mail.gs', import.meta.url));

/** Links on the site's own domain (https, none holding an excluded value or a site password's shape) and short
 *  numeric codes next to a word like "code", from one mail's text; and how many other links it had. */
export function linksAndCodes(text, site, exclude = []) {
  const t = String(text).replace(/&amp;/g, '&');
  const links = new Set();
  let other = 0;
  for (const raw of t.match(/https:\/\/[^\s"'<>()[\]{}]+/g) ?? []) {
    const u = raw.replace(/[.,;:!?]+$/, '');
    let host;
    try {
      host = new URL(u).hostname;
    } catch {
      continue;
    }
    if (siteIn([site], host) === site && !/gs(?:-|!|%21)[1-9A-HJ-NP-Za-km-z]{5}/.test(u) && !exclude.some((v) => v && maskValues([v], u) !== u)) links.add(u);
    else other++;
  }
  const plain = t.replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ');
  const codes = new Set([...plain.matchAll(CODE)].map((m) => m[1]));
  return { links: [...links].slice(0, 5), codes: [...codes].slice(0, 3), other_links: other };
}

/** One call to the relay: { ok, messages: [{ at, text }] } for mail to `alias` in the last 30 minutes, or { ok: false,
 *  error }. The key goes in the body, never the URL. */
async function askRelay(f, relay, alias) {
  const res = await f(relay.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: relay.key, alias }), signal: AbortSignal.timeout(30_000) });
  // Apps Script answers a POST with a redirect to its echo host; anything else is not the relay.
  if (!res.ok || (res.url && !/^https:\/\/script\.google(?:usercontent)?\.com\//.test(res.url))) throw new Error(`relay_${res.status}`);
  return res.json();
}

/**
 * Reads the listings mail for one site's verification through the relay `glow sites connect-mail` set up (an Apps Script
 * on a member of the listing@ group, lib/listing-mail.gs: read-only Gmail, mail to listing+<product>@ from the last 30
 * minutes, nothing else; it needs the key only this Mac's keychain holds). Only links on the site's own domain and short
 * codes leave here, never a subject, sender or body. `fetch` and `now` for the tests.
 */
export function relayMail({ relay, fetch: f = fetch, now = () => Date.now() }) {
  return async ({ alias, site, exclude = [] }) => {
    try {
      const j = await askRelay(f, relay, alias);
      if (!j?.ok || !Array.isArray(j.messages)) throw new Error(String(j?.error ?? 'relay_failed'));
      const out = { ok: true, site, links: [], codes: [], other_links: 0, messages: 0 };
      for (const m of j.messages.slice(0, 10)) {
        if (typeof m?.text !== 'string' || !(Number(m.at) >= now() - MAIL_WINDOW_MS)) continue;
        const found = linksAndCodes(m.text, site, exclude);
        out.messages++;
        out.other_links += found.other_links;
        out.links = [...new Set([...out.links, ...found.links])].slice(0, 5);
        out.codes = [...new Set([...out.codes, ...found.codes])].slice(0, 3);
      }
      if (!out.links.length && !out.codes.length) out.note = out.messages ? 'Mail came, but with no link on the site’s own domain and no code: needs_owner if nothing else comes.' : 'Nothing yet: wait a minute and ask again.';
      return out;
    } catch {
      return { ok: false, error: 'mail_unreachable', needs_owner: 'verification email', message: 'The listings mail relay couldn’t be read (set it up again: glow sites connect-mail).' };
    }
  };
}

// ---------- brand files: the logo and screenshots a listing run uploads ----------

/** What brand_file hands a run: the product's own images (never media a run made, which waits for the owner). */
export const BRAND_FILE_KINDS = ['logo', 'icon', 'screenshot', 'feature', 'social'];
export const BRAND_FILE_MAX = 8 * 1024 * 1024;
/** An image's type by its first bytes (PNG, JPEG or WebP), else null. */
export function imageExt(b) {
  if (!b || b.length < 12) return null;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpg';
  if (b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  return null;
}
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/** The files brand_file wrote for a run ({ root, files: [{ path, sha256, size }] }; root the brand folder's realpath). */
export function readManifest(file) {
  try {
    const m = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (m && typeof m.root === 'string' && Array.isArray(m.files)) return m;
  } catch {
    // none yet
  }
  return { root: null, files: [] };
}

/** A path the run gave browser_file_upload, as the realpath of a file brand_file wrote and nobody changed since, else
 *  null. A bare or relative name is looked for in the brand folder. */
export function brandFileOk(man, p) {
  if (!man.root || typeof p !== 'string' || !p) return null;
  try {
    const real = fs.realpathSync(path.isAbsolute(p) ? p : path.join(man.root, path.basename(p)));
    const entry = man.files.find((f) => f && f.path === real);
    if (!entry || path.dirname(real) !== man.root) return null;
    const st = fs.lstatSync(real);
    if (!st.isFile() || st.nlink !== 1 || st.size !== entry.size) return null;
    return sha256(fs.readFileSync(real)) === entry.sha256 ? real : null;
  } catch {
    return null;
  }
}

/** A signed media URL's bytes, from Glow's own host only (no redirects), ≤ BRAND_FILE_MAX, else null. */
export const mediaFetch = (cfg, fetcher = fetch) => async (url) => {
  try {
    const u = new URL(url);
    if (u.origin !== apiBase(cfg.api) || !u.pathname.startsWith('/api/v1/media/') || u.username || u.password) return null;
    const res = await fetcher(u.href, { redirect: 'error', signal: AbortSignal.timeout(20_000) });
    if (!res.ok || Number(res.headers.get('content-length') ?? 0) > BRAND_FILE_MAX) return null;
    const b = Buffer.from(await res.arrayBuffer());
    return b.length <= BRAND_FILE_MAX ? b : null;
  } catch {
    return null;
  }
};

/**
 * brand_file for one run: `get()` is GET /api/v1/agent/sessions/:id/brand ({ status, json }); `download(url)` a signed
 * URL's bytes. Writes each image 0400 into `folder` under a name of its own (kind and hash, by the bytes' type), never
 * over a file, and records it in `manifest` (0600, outside the folders the browser writes to).
 */
export function brandFiles({ folder, manifest, get, download }) {
  return async (kind, n) => {
    const want = Number.isInteger(n) ? Math.min(Math.max(n, 1), 4) : 1;
    const r = await get();
    if (r.status !== 200 || !Array.isArray(r.json?.assets)) return { ok: false, error: r.status === 404 ? 'not_this_run' : 'glow_unreachable', message: 'Glow didn’t give the brand kit: mark the site needs_owner, gate "logo".', needs_owner: 'logo' };
    const own = r.json.assets.filter((a) => a && typeof a.url === 'string' && a.source !== 'run');
    let pick = own.filter((a) => a.kind === kind);
    if (!pick.length && kind === 'logo') pick = own.filter((a) => a.kind === 'icon');
    if (!pick.length) return { ok: false, error: 'none', message: `The brand kit has no ${kind}: mark the site needs_owner, gate "logo".`, needs_owner: 'logo' };
    fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
    const root = fs.realpathSync(folder);
    const man = readManifest(manifest);
    if (man.root !== root) Object.assign(man, { root, files: [] });
    const files = [];
    for (const a of pick.slice(0, want)) {
      const bytes = await download(a.url);
      const ext = bytes ? imageExt(bytes) : null;
      if (!ext) continue;
      const hash = sha256(bytes);
      const file = path.join(root, `${kind}-${hash.slice(0, 12)}.${ext}`);
      if (!brandFileOk(man, file)) {
        try {
          fs.writeFileSync(file, bytes, { flag: 'wx', mode: 0o400 });
        } catch {
          continue; // something else is there under that name: not ours
        }
        man.files.push({ path: file, sha256: hash, size: bytes.length });
      }
      files.push({ path: file, kind: a.kind, label: a.label ?? null, width: a.width ?? null, height: a.height ?? null });
    }
    writeFileAtomic(manifest, `${JSON.stringify(man)}\n`, 0o600);
    if (!files.length) return { ok: false, error: 'download_failed', message: 'The image didn’t download: mark the site needs_owner, gate "logo".', needs_owner: 'logo' };
    return { ok: true, files, next: 'Click the site’s upload button so its file chooser opens, then browser_file_upload {paths: [the path]}. Only these files upload.' };
  };
}

/** brand_file for the run the runner handed this helper (its env), with this computer's Glow key; null without one. */
export function brandFor(env, config = readConfig) {
  const cfg = config();
  const run = env.GLOW_SITES_RUN;
  if (!cfg || !SESSION_RE.test(String(run ?? '')) || !env.GLOW_SITES_BRAND_DIR || !env.GLOW_SITES_MANIFEST) return null;
  return brandFiles({
    folder: env.GLOW_SITES_BRAND_DIR, manifest: env.GLOW_SITES_MANIFEST,
    get: () => api(cfg, 'GET', `/api/v1/agent/sessions/${encodeURIComponent(run)}/brand`, undefined, 15_000), download: mediaFetch(cfg),
  });
}

/**
 * The browser filter's check of one line the model's client sends Playwright: { forward } (the line to pass on, made
 * from the parsed message, so what was checked is what goes) or { reply } (answered in Playwright's place). One JSON
 * object a line: a batch or a line that doesn't parse is refused. No tool may save to a model-named file; an upload
 * sends only brand_file's files, unchanged, by their realpaths.
 */
export function browserCall(line, manifestFile) {
  let m;
  try {
    m = JSON.parse(line);
  } catch {
    return { reply: { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } } };
  }
  if (!m || typeof m !== 'object' || Array.isArray(m)) return { reply: { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'One message a line' } } };
  if (m.method !== 'tools/call') return { forward: JSON.stringify(m) };
  const no = (text) => ({ reply: { jsonrpc: '2.0', id: m.id ?? null, result: { content: [{ type: 'text', text }], isError: true } } });
  const args = m.params?.arguments;
  if (args && typeof args === 'object' && Object.hasOwn(args, 'filename')) return no('Saving to a file is off in listing runs: call it without filename.');
  if (m.params?.name !== 'browser_file_upload' || !args || args.paths === undefined) return { forward: JSON.stringify(m) };
  const man = readManifest(manifestFile);
  const paths = Array.isArray(args.paths) && args.paths.length <= 4 ? args.paths.map((p) => brandFileOk(man, p)) : [null];
  if (!paths.length || paths.some((p) => !p)) return no('Only the files brand_file gave you upload, unchanged: call brand_file {kind} and pass the path it answers.');
  return { forward: JSON.stringify({ ...m, params: { ...m.params, arguments: { ...args, paths } } }) };
}

// ---------- the helper's tools ----------

const SITE_ARG = { type: 'string', description: 'The site, as the brief’s Sites line names it (its domain, e.g. uneed.best)' };
export const TOOLS = [
  {
    name: 'new_login',
    description: 'Make the login for a site in this run’s brief: a new random password, made and kept on this computer (you never see it), put on the clipboard for 30 seconds. Then click the password field and paste (browser_press_key "Meta+v"), and paste again in a confirm field. Replaces the one kept for that site. Never type, invent or read a password.',
    inputSchema: {
      type: 'object', additionalProperties: false, required: ['site', 'url', 'username'],
      properties: {
        site: SITE_ARG,
        url: { type: 'string', description: 'The https sign-up (or reset) page on that site' },
        username: { type: 'string', description: 'What you sign up with: the brief’s email, or a handle' },
        max_length: { type: 'integer', description: 'Only if the site caps password length: its cap (16 or more)' },
      },
    },
  },
  {
    name: 'fill',
    description: 'Log back in to a site in this run’s brief: its kept password goes on the clipboard for 30 seconds; click the password field and paste (browser_press_key "Meta+v"). No login kept, or it fails: the site’s Forgot password, then new_login.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['site'], properties: { site: SITE_ARG } },
  },
  {
    name: 'brand_file',
    description: 'The product’s own logo, icon, screenshots or feature graphic as a file on this computer, for a site’s upload field: from its Glow brand kit (what Glow read from its site and store pages, and what its owner added). Answers each file’s path: click the site’s upload button so its file chooser opens, then browser_file_upload {paths: [that path]}. Only these files upload, unchanged. Nothing in the kit: mark the site needs_owner, gate "logo".',
    inputSchema: {
      type: 'object', additionalProperties: false, required: ['kind'],
      properties: {
        kind: { type: 'string', enum: BRAND_FILE_KINDS, description: 'logo (square), icon, screenshot, feature (wide banner) or social' },
        n: { type: 'integer', minimum: 1, maximum: 4, description: 'How many, for screenshots (1 to 4)' },
      },
    },
  },
  {
    name: 'inbox',
    description: 'The verification mail for a site in this run’s brief, from the last 30 minutes: only links on that site’s own domain and short numeric codes. Never opens a mailbox in the browser.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['site'], properties: { site: SITE_ARG } },
  },
];

/**
 * The tools, for one listing run's brief (ctx: { slug, sites, email? }). `store` keeps logins, `clipboard` holds one for
 * 30 s, `release` hands each value to the runner before it's released (or the call fails), `mail` reads the mailbox (or
 * null). Results never carry a password.
 */
export function sitesTools({ ctx, store, clipboard, release, mail = null, brand = null, clipMs = CLIP_MS, timers = { setTimeout, clearTimeout } }) {
  let held = null;
  const released = new Set();
  /** The runner has it (and masks it) first; then the clipboard, for clipMs. */
  const hand = async (value) => {
    await release(value);
    released.add(value);
  };
  const toClipboard = (value) => {
    if (held) timers.clearTimeout(held.timer);
    const count = clipboard.put(value);
    held = { count, timer: timers.setTimeout(() => {
      clipboard.clear(count);
      held = null;
    }, clipMs) };
  };
  const no = (error, message, more = {}) => ({ ok: false, error, message, ...more });
  const call = async (name, args) => {
    const a = args && typeof args === 'object' ? args : {};
    if (!TOOLS.some((t) => t.name === name)) return no('unknown_tool', 'new_login, fill, inbox or brand_file.');
    if (name === 'brand_file') {
      if (!BRAND_FILE_KINDS.includes(a.kind)) return no('bad_kind', `kind: ${BRAND_FILE_KINDS.join(', ')}.`);
      if (!brand) return no('no_brand', 'This computer can’t reach the brand kit: mark the site needs_owner, gate "logo".', { needs_owner: 'logo' });
      return await brand(a.kind, a.n).catch(() => no('helper_failed', 'The brand file couldn’t be made: mark the site needs_owner, gate "logo".', { needs_owner: 'logo' }));
    }
    const site = siteIn(ctx.sites, a.site);
    if (!site) return no('not_in_brief', `Only the sites this run’s brief names: ${ctx.sites.join(', ')}.`);
    const seconds = Math.round(clipMs / 1000);
    try {
      if (name === 'new_login') {
        const url = loginUrl(a.url, site);
        if (!url) return no('bad_url', `url: the https sign-up or reset page on ${site}.`);
        const username = String(a.username ?? '').trim();
        if (!/^[^\s"\\]{1,120}$/.test(username)) return no('bad_username', 'username: the email or handle you sign up with (no spaces).');
        if (ctx.email && username.includes('@') && username.toLowerCase() !== ctx.email) return no('not_the_alias', `Sign up with ${ctx.email}, the email this brief names.`);
        const cap = Number.isInteger(a.max_length) ? a.max_length : null;
        if (cap !== null && cap < 16) return no('too_short', 'A password cap under 16 characters: stop, and mark the site needs_owner.', { needs_owner: 'password length cap' });
        const password = newPassword(cap !== null && cap < 26);
        await hand(password);
        const item = store.put({ product: ctx.slug, site, username, url, password });
        toClipboard(password);
        return { ok: true, site, username, item, clipboard_seconds: seconds, next: 'Click the password field and paste (browser_press_key "Meta+v"); paste again in a confirm field.' };
      }
      if (name === 'fill') {
        const got = store.get({ product: ctx.slug, site });
        if (!got?.password) return no('no_login', `No login kept for ${site}: use its Forgot password, then new_login.`);
        await hand(got.password);
        toClipboard(got.password);
        return { ok: true, site, username: got.username ?? '', item: got.item, clipboard_seconds: seconds, next: 'Click the password field and paste (browser_press_key "Meta+v").' };
      }
      if (!mail) return no('no_mailbox', 'The listings mail relay isn’t set up on this computer (glow sites connect-mail): stop at this step and mark it needs_owner.', { needs_owner: 'verification email' });
      if (!ctx.email) return no('no_alias', 'This brief names no Email line to read mail for: mark it needs_owner.', { needs_owner: 'verification email' });
      return await mail({ alias: ctx.email, site, exclude: [...released, store.get({ product: ctx.slug, site })?.password].filter(Boolean) });
    } catch (e) {
      const code = /^(store_failed|runner_unreachable|runner_refused)$/.test(e?.message) ? e.message : 'helper_failed';
      return no(code, 'The helper on this computer couldn’t do that: mark the site needs_owner.');
    }
  };
  return {
    tools: TOOLS,
    call,
    /** On the way out: a password still on the clipboard is cleared now (if nothing was copied since). */
    close() {
      if (!held) return;
      timers.clearTimeout(held.timer);
      clipboard.clear(held.count);
      held = null;
    },
  };
}

// ---------- MCP over stdio ----------

const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

/** A minimal MCP server on newline-delimited JSON-RPC: initialize, ping, tools/list, tools/call. Resolves when its
 *  input closes. */
export function mcpServe({ input = process.stdin, output = process.stdout, name, tools, call }) {
  const send = (o) => output.write(`${JSON.stringify(o)}\n`);
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  const busy = new Set();
  rl.on('line', (line) => {
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      return send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    }
    if (!m || typeof m !== 'object' || m.id === undefined || m.id === null) return; // a notification
    const reply = (result) => send({ jsonrpc: '2.0', id: m.id, result });
    if (m.method === 'initialize') {
      const v = m.params?.protocolVersion;
      return reply({ protocolVersion: PROTOCOLS.includes(v) ? v : PROTOCOLS[0], capabilities: { tools: {} }, serverInfo: { name, version: VERSION } });
    }
    if (m.method === 'ping') return reply({});
    if (m.method === 'tools/list') return reply({ tools });
    if (m.method !== 'tools/call') return send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
    const p = Promise.resolve()
      .then(() => call(String(m.params?.name ?? ''), m.params?.arguments))
      .catch(() => ({ ok: false, error: 'helper_failed' }))
      .then((out) => reply({ content: [{ type: 'text', text: JSON.stringify(out) }], isError: out?.ok === false }));
    busy.add(p);
    void p.finally(() => busy.delete(p));
  });
  return new Promise((resolve) => rl.on('close', () => void Promise.allSettled([...busy]).then(resolve)));
}

/** The MCP config a listing run's Claude Code gets (--strict-mcp-config: these two only): the helper for this brief, and
 *  the browser, the installed Chrome with the product's own profile (browserProfile), no tools a page offers (WebMCP),
 *  behind the filter that masks password shapes in all it answers (sites-browser.mjs). */
export function listingMcpConfig({ node, helper, filter, npx, cwd, profile, socket, ctx, run, manifest }) {
  const brand = run && manifest ? { GLOW_SITES_RUN: String(run), GLOW_SITES_BRAND_DIR: path.join(cwd, 'brand'), GLOW_SITES_MANIFEST: manifest } : {};
  return {
    mcpServers: {
      'glow-sites': {
        type: 'stdio', command: node, args: [helper],
        env: { GLOW_SITES_SOCKET: socket, GLOW_SITES_PRODUCT: ctx.slug, GLOW_SITES_LIST: ctx.sites.join(','), ...(ctx.email ? { GLOW_SITES_EMAIL: ctx.email } : {}), ...brand },
      },
      'glow-browser': {
        type: 'stdio', command: node, args: [filter, npx, '-y', PLAYWRIGHT_MCP, '--browser', 'chrome', '--user-data-dir', profile, '--output-dir', cwd, '--no-webmcp'],
        ...(manifest ? { env: { GLOW_UPLOAD_MANIFEST: manifest } } : {}),
      },
    },
  };
}

// ---------- export for 1Password ----------

/** One CSV field: quoted only when it has to be (a comma, quote, line break, or space at either end). */
export const csvField = (v) => {
  const s = String(v ?? '');
  return /[",\r\n]|^\s|\s$/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
export const toCsv = (rows) => `${rows.map((r) => r.map(csvField).join(',')).join('\r\n')}\r\n`;
/** For 1Password's CSV import (1Password.com › Import data › CSV File, where each column is labelled): one login a row,
 *  every row the same fields. The header row is there to label by; mark it Ignore Row. */
export const CSV_HEADER = ['title', 'website', 'username', 'password', 'notes', 'tags'];
export const csvRows = (logins) => [CSV_HEADER, ...logins.map((l) => [`${l.product} · ${l.site}`, l.url || `https://${l.site}/`, l.username ?? '', l.password, `Made by a Glow listing run${l.updated_at ? ` (${l.updated_at.slice(0, 10)})` : ''}`, `glow-listings,${l.product}`])];

// ---------- glow sites … ----------

const USAGE = `npx @winding-labs/glow sites list [--product <name>]          the site logins kept here (never a password)
npx @winding-labs/glow sites export --out <file> [--product <name>]
                                                             every one, passwords too, as a CSV for 1Password's import
npx @winding-labs/glow sites connect-mail                    let listing runs read their verification mail (the relay)`;

const ask = (q) => new Promise((resolve) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(q, (a) => {
    rl.close();
    resolve(String(a));
  });
});
const home = (p) => path.resolve(String(p).replace(/^~(?=$|\/)/, os.homedir()));

/** `glow sites …`; the exit code. `inRun`: inside a session Glow started (refused for export and connect-mail). */
export async function sitesCommand(args, { inRun = false, store = storeFor(), say = console.log, warn = console.error } = {}) {
  const [cmd, ...rest] = args;
  const opt = (n) => {
    const i = rest.indexOf(n);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const product = opt('--product')?.toLowerCase();
  if (!['list', 'export', 'connect-mail'].includes(cmd)) {
    say(USAGE);
    return cmd && cmd !== '--help' && cmd !== '-h' ? 1 : 0;
  }
  if (cmd === 'list') {
    const rows = store.list().filter((r) => !product || r.product === product);
    if (!rows.length) return say('No site logins kept on this computer yet.'), 0;
    for (const r of rows) say([r.product, r.site, r.username, r.url, String(r.updated_at ?? '').slice(0, 10)].map((x) => printable(x, 120)).join('  ·  '));
    say(`${rows.length} login${rows.length === 1 ? '' : 's'} in the login keychain (${SERVICE}). Export them for 1Password: npx @winding-labs/glow sites export --out <file>`);
    return 0;
  }
  if (inRun) return warn('✗ Not from a run Glow started: run it yourself, in a terminal.'), 1;
  if (!process.stdin.isTTY || !process.stdout.isTTY) return warn('✗ Run it yourself, in a terminal: it asks you first.'), 1;
  if (cmd === 'export') {
    if (!opt('--out')) return warn(`✗ Say where: ${USAGE.split('\n')[1].trim()}`), 1;
    const out = home(opt('--out'));
    if (fs.existsSync(out)) return warn(`✗ ${printable(out, 200)} is there already: pick a new file.`), 1;
    const rows = store.list().filter((r) => !product || r.product === product);
    if (!rows.length) return warn('No site logins kept on this computer yet.'), 1;
    say(`This writes ${rows.length} site password${rows.length === 1 ? '' : 's'}, unencrypted, to ${printable(out, 200)} (only you can read it).`);
    if ((await ask('Type export to go on: ')).trim() !== 'export') return say('Nothing written.'), 1;
    const logins = [];
    for (const r of rows) {
      const got = store.get(r);
      if (got?.password) logins.push(got);
      else warn(`! ${printable(r.site, 80)} (${printable(r.product, 40)}): not in the keychain any more, left out.`);
    }
    fs.writeFileSync(out, toCsv(csvRows(logins)), { mode: 0o600, flag: 'wx' });
    fs.chmodSync(out, 0o600);
    say(`✓ Wrote ${logins.length} login${logins.length === 1 ? '' : 's'} to ${printable(out, 200)}.`);
    say('Import it: 1Password.com › your name › Import data › CSV File (mark the first row Ignore Row; label the columns Title, Website, Username, Password, Notes, Tags).');
    say(`Then delete it: rm ${JSON.stringify(out)}  (and keep it out of iCloud Drive, Dropbox and backups meanwhile).`);
    return 0;
  }
  return connectMail({ store, say, warn });
}

/**
 * `glow sites connect-mail`: links this Mac to the listings mail relay (lib/listing-mail.gs, an Apps Script web app on a
 * member of the listing@ group). It makes a key here, shows its SHA-256 for the script, takes the web app's URL, checks
 * the relay knows the key, and keeps both in the login keychain. Glow gets nothing; the script never sees the key.
 */
async function connectMail({ store, say, warn, read = ask, f = fetch }) {
  const key = randomBytes(32).toString('base64url');
  say(`1. Open the Apps Script that relays your listings mail (the code: ${RELAY_SCRIPT}) and set its key line to:
     var KEY_SHA256 = '${createHash('sha256').update(key).digest('hex')}';
2. Deploy › Web app, execute as Me, access Anyone (every call needs the key, which stays in this Mac's keychain).`);
  const url = (await read('3. Paste the web app URL here: ')).trim();
  if (!RELAY_URL.test(url)) return warn('✗ That isn’t a web app URL (https://script.google.com/macros/s/…/exec).'), 1;
  // A key it knows gets past the key check to the alias check, which this address fails.
  const j = await askRelay(f, { url, key }, 'listing+check@invalid.invalid').catch(() => null);
  if (j?.error !== 'not_a_listing_alias') return warn(j?.error === 'unauthorized' ? '✗ The relay doesn’t know this key: set KEY_SHA256 as above, deploy a new version, and run this again.' : '✗ The relay didn’t answer (is it deployed for Anyone?).'), 1;
  store.setMail({ url, key });
  say('✓ Listing runs on this computer can read their verification mail (links on the site’s own domain and codes only). Kept in the login keychain; Glow gets nothing.');
  return 0;
}
