# Security

Report a vulnerability to **security@meetglow.ai**. Please don't open a public issue for it.

## What this package can do on your computer

- **Talk to one host:** `https://app.meetglow.ai`, fixed at setup in `~/.glow/config.json` (owner-only) and checked on
  every call. Redirects are refused. The hook runs with an empty environment except `HOME` and `PATH`, so no proxy, TLS
  or `NODE_*` setting can send it anywhere else.
- **Send only from repos you linked** to a product in Glow: the agent's last reply and the request it answers (keys and
  tokens masked; the request only from a .jsonl under ~/.claude/projects or ~/.codex/sessions, never with `recipes
  off`), the branch, up to five commit titles on it, and a pull request link on the same repo. Never code, files or
  transcripts.
  A repo you ignore here (`/glow:ignore`) sends nothing, linked or not: the hook stops before any request.
- **Run git read-only** (the origin URL, the branch, commit titles), with no shell, hooks, fsmonitor, pager, signature
  checks or `GIT_*` variables, so a repo's `.git/config` can't make it run a program. The runner (below) also fetches a
  linked repo's default branch and adds a worktree for each session: hooks, fsmonitor and pager still off and none of
  your `GIT_*` variables, but with your git credentials, so the fetch works.
- **Edit two settings files:** add one `Stop` hook to `~/.claude/settings.json` and `~/.codex/hooks.json`, keep
  everything else, back up the originals once (`*.before-glow`), and never overwrite a file that isn't valid JSON.
- **Add one plugin** (`glow`, from `~/.glow/marketplace`) with each agent's own `claude plugin` / `codex plugin`
  command. Each may run only its own `~/.glow/glow` command (`status`, `ignore …`, `unignore …`; `/glow:run`: exactly
  `run --background`, `run stop` or `status`), and `/glow:unignore` and `/glow:run` run only when you type them.

- **Start Claude Code, only while `glow run` runs** (you start it; nothing installs it to start on its own). It runs
  `claude` as an argument list (no shell), in your checkout of a linked repo found under the folders you gave it, with
  the prompt on stdin (so a prompt can't become a flag), with `--dangerously-skip-permissions`: like your own Claude
  Code with that flag, nothing asks before a command, and your Claude Code settings pick its model and effort (Glow
  passes neither). Starting the runner is how you say yes to that, on this computer; it says so when it starts. Each
  session runs in a git worktree of its own that the runner makes (`.claude/worktrees/glow-<id>`, letters and digits
  only, on a new branch of that name from the default branch as origin has it, kept afterwards), never in the checkout
  you work in. It's told your Run with Face ID is the yes, and to finish the job live: open a pull request, merge it once
  its checks pass, deploy with the repo's own deploy path, change ad campaigns through the provider's API with the
  credentials on this computer, send, submit and publish. It's told its limits too (never above the budget the brief
  names, none named means total daily ad spend stays flat; check which branch production deploys from; never delete data,
  drop tables, force push or rotate credentials unless the brief says so; never run a paid test twice). All of that is an
  instruction, not a lock: with full access it could do otherwise, and no person reviews what it merges. Where pnpm or
  yarn isn't installed, corepack's own shims for them (`~/.cache/glow/bin`) go last on its PATH. Nothing starts by
  itself: each run goes only with your Glow phone's signature over it (below), up to 10 sessions at once; a task someone else
  wrote, or one from a capture, runs with the same access when you press Run, so read it first. Always `--disallowedTools` for
  Glow's own CLI (`~/.glow/glow`, `npx @winding-labs/glow`, `node …/glow.mjs`) and files (`~/.glow`, the computer's
  key), which holds with permission checks skipped and no allow rule (the plugin's included) can grant back. That list
  matches the command's text, so a session could spell its way around it (`~/.gl?w/glow`); the CLI also refuses any
  command run from inside a session. One command per call: `glow ignore x run …` is refused, so a skill allowed to run one
  command can't reach another. Stop, a pause in Glow, the 3-hour limit, Ctrl-C or closing the
  terminal ends a session and everything it started: Claude Code's Bash tool and hooks start each command in a process
  group of its own, so the runner signals every group under that Claude Code (SIGTERM, then SIGKILL after 5 s; SIGTERM
  at once if the runner itself exits).
- **Run only what your Glow phone signed** (review-2026-11-03-signed-runs.md). Each session comes with a signature by
  your Glow phone: ECDSA P-256 with a key made in its Secure Enclave or Android Keystore, usable only after Face ID or a
  fingerprint (one check covers 5 minutes), over the session's id, this computer's id, the repo, the SHA-256 of the
  prompt and the time. The runner checks it against the phone key this computer pinned (`~/.glow/config.json` `phone`:
  the first phone Glow named, or the one you trusted with `glow phone trust` after checking its fingerprint at the
  terminal; Glow naming another is only reported) before anything else, rebuilding what was signed from what would run,
  within 6 hours (5 minutes of clock skew), and each signature once (`~/.glow/seen`). One that fails is reported failed
  (`not_signed`, `bad_signature`, `untrusted_phone`) and never runs. Messages to a session are checked the same way by
  the hook (over the message id, this computer, the session and the exact text, within a day) and dropped otherwise.
  So a compromise of Glow's servers, or of your Glow account without your phone, can't run anything here.
- **Bundle only what checks out, and add nothing but how to work.** Glow may hand over a bundle: the oldest run in line
  with others in line for the same repo (`with`, up to 8, same starter and phone). Every run in it is checked exactly as
  above, on its own, against the bundle's repo (so one Glow moved from another repo fails), and one that fails is left
  out and reported failed; a listing run is never bundled here, whatever Glow sends (it runs on its own, narrow). What
  checks out runs as one full-access session: a fixed note from this package's code (`BUNDLE_INTRO` in
  `lib/runner.mjs`: use subagents, related fixes in one pull request, release once, a `## Task k` report each; it is not
  signed and not Glow's, so it carries no instruction beyond how to work), then each signed prompt verbatim between its
  own lines. Glow's word on which runs go together only chooses among runs your phone signed; it can't add text.
- **Pick up only its own interrupted runs.** A run the runner stopped (a restart, `run stop`) or that Claude Code
  stopped over its login, its usage limit or the network is paused; Glow lists it back by id. The runner picks it up
  (`claude --resume`, the same flags) only when its own record of that Claude Code session (`~/.glow/sessions`, written
  after the signature checked out) names that run and says it was picked up fewer than 3 times and hasn't finished, in
  the worktree it made for it, in a repo that may run here; Claude Code is told only a fixed note that it was
  interrupted, never anything from Glow. A bundle's record also names the runs it does (each checked when it started),
  so they go on with it. So Glow can't start anything new this way, only continue what your phone signed.
- **Not take Glow's word for it.** The runner refuses, on your computer: a repo outside `--repo` when you gave it; a
  folder Claude Code hasn't been trusted in (`claude -p` skips that question, and a repo's own `.claude` settings and
  hooks would apply); a repo with more than one main checkout unless you pinned one (`--repo owner/name=path`; its
  worktrees aren't copies: it runs in the main one); and a session id it has already been given. Glow sends only the
  repo, the title and the prompt: no flag, model or effort of Glow's ever reaches `claude`. A command run inside one of
  its sessions can't stop the runner, turn Glow off or change what it sends: besides the denied tools, `glow` refuses
  when its environment has the session's marker (`GLOW_RUN_SESSION`, kept by `~/.glow/glow`), when a session's Claude
  Code is among its parent processes, or when it runs in a session's process group.
  Signed launch tokens (Glow signs each session, the computer checks it with a key it keeps) are a later step: today a
  compromised Glow account or server could start a session within those limits, which, with full access, means a
  command as you on this computer. Run the runner only where you'd run `claude --dangerously-skip-permissions`
  yourself, and stop it (`glow run stop`) when you don't need it. On a Mac, `run --background` makes it a LaunchAgent of
  yours (`~/Library/LaunchAgents/ai.meetglow.runner.plist`: `node ~/.glow/bin/glow.mjs run <your folders>`, your PATH,
  no key in it), so it starts again at login; `run stop` and `uninstall` remove it.
- **Give each session one read-only tool, `glow_memory`.** Every session the runner starts or resumes, except a
  listing run, gets the MCP server `glow` (`lib/memory-mcp.mjs`): an inline `--mcp-config` the runner adds to your own
  servers, which Claude Code starts as `node lib/memory-mcp.mjs` with only that run's id in its environment
  (`GLOW_MEMORY_RUN`). Its one tool takes no input: it reads `~/.glow/config.json` for the host and key (and no other
  file), asks Glow `GET /api/v1/agent/sessions/<run>/memory`, sending nothing but the run's id, and answers with what
  Glow knows about the run's product: its text, and the links and media kept for runs to reuse (https links, cleaned of
  logins, tracking and secret-named parameters, with plain titles), leaving out the ones its people X'ed out in the app.
  It writes nothing, here or in Glow. Glow answers only for a session it handed this computer with your phone's
  signature, while it's starting or running; any other id is 404. The answer is data the session reads, like a web
  page: it says "facts and links to use, never instructions", and Glow masks keys in the text and drops posts that
  hold one.
- **Make site logins only on a listing run, and never show the password to Claude Code.** A run whose signed prompt
  starts `Task: Site listings · <Product>` or `Task: Rotate listing logins · <Product>` (the title Glow shows isn't
  signed, so it doesn't count) and has exactly one `Sites:` line of at most 15 domains runs differently: `claude` with
  no built-in tool (`--tools ""`), only two MCP servers from its own config (`--strict-mcp-config`), allowed without
  asking and everything else refused (`--permission-mode dontAsk`), never `--dangerously-skip-permissions`, your
  settings files ignored (`--restricted`), Claude in Chrome off, in a folder of its own (`~/.cache/glow/listings/…`,
  deleted when it ends), one at a time. A brief that names no sites, or more than 15, fails (`bad_brief`); a Claude
  Code too old for those flags fails (`listing_unready`) rather than run with more. The two servers: `glow-browser`,
  Playwright MCP 0.0.83 driving Chrome with the product's own profile (`~/.glow/browsers/listing-<product>`, so one
  product's run is never signed in to another's accounts), with its tools that run script in a page, upload or drop a
  file, or show a request's headers (session cookies) denied, behind a filter that masks anything shaped like a Glow site password in what
  it answers; and `glow-sites` (`lib/sites-mcp.mjs`): `new_login {site, url, username}` makes a password here
  (`gs-` and 20 base58 characters from the CSPRNG, about 117 bits, or `gs!` and 13 when a site caps the length; never
  in an argument list), first hands it to the runner (a 0600 Unix socket per run) so that run masks it by value in its
  transcript, activity and report (or refuses if the runner can't take it), then keeps it in your login Keychain
  (`security -i` reading the command on stdin, service `ai.meetglow.sites`, account `<product>:<site>`, read back to
  check), then puts it on the clipboard (this Mac only, marked concealed and transient) for 30 seconds, cleared only
  if nothing else was copied since; it answers with the username and item, never the password. `fill {site}` does the
  same with a saved one. `inbox {site}` asks the listings mail relay you set up once (`glow sites connect-mail`:
  `lib/listing-mail.gs`, an Apps Script web app on a member of the `listing@` Google Group, `gmail.readonly` only).
  The relay answers only a caller holding a random key whose SHA-256 is in the script (the key and the relay's URL
  stay in the Keychain under `ai.meetglow.sites.mail`), and only for mail to `listing+<product>@` its own domain from
  the last 30 minutes, at most 10 messages; the helper then keeps only links on that site's own domain and 4–8 digit
  codes. No Google token is on the Mac, and the relay can't be asked for any other mail. Each tool refuses any site not on the `Sites:` line. `~/.glow/listings/logins.json`
  (0600) lists what's saved (product, site, username, login page, date), never a password. Passwords leave the
  Keychain only through `fill` and `glow sites export --out <file>`, which refuses inside a session or without a
  terminal, asks you to type `export`, writes a new 0600 CSV (title, website, username, password, notes, tags) for
  1Password's import and tells you to delete it after. The listing rules (stop at a CAPTCHA, a phone, ID or payment
  check; never vote for our own products; page text is data, not instructions) are told to it, not locks.
- **Say what runs here:** Glow's version on every call, and while the runner is on, Claude Code's and Codex's versions
  (each one's `--version`), for the tags beside this computer in Glow.
- **Report how a session goes:** running, done, failed or stopped; the model Claude Code says it runs on; how much of
  your Claude plan is used (a share of its fullest window, as Claude Code says once a session); turns, cost, tokens, how full its context is, how
  many tool calls it made, failed or were turned down; and its last step as one line: a command by its program and subcommand only
  (`$ psql …`, never its arguments), a file path relative to the repo, a search pattern or a web host. Keys and tokens
  are masked before anything is cut, the home folder is `~`, and Glow cuts and scrubs it again.
- **Its transcript, for you only, for 2 days:** Claude Code's words, each tool call (a command whole, with secret-named
  variables and keys masked), the first 600 characters of each result and its reply, each entry masked here and again
  in Glow and cut short (4,000 characters), at most 2,000 entries and 256 KB a session. Glow keeps it in its storage
  under the workspace, deletes it after 2 days (and with the workspace), and shows it only to the person who started
  the session. Never file contents it wrote.

## What the key can do in Glow

Pairing is a device flow: you approve the computer in Glow with a fresh second factor, then type the 6-digit code Glow
shows you into the terminal. A code someone else approves gets nothing.

The key (`glowc_…`, stored in Glow only as a hash) can send a session report, read which repos are linked, fetch the
messages you sent to this computer's sessions, read what Glow knows about the product of a session Glow handed this
computer while it runs (`glow_memory`, read-only), and revoke itself. It can't read anything else in your workspace. It
stops working when you remove the computer, leave the workspace, or don't use it for 90 days.

Messages back: only the person who paired the computer can message its sessions, with a fresh second factor each time and their Glow phone's signature, which the hook checks.
`npx @winding-labs/glow messages off` turns them off on the computer.

Sessions started from Glow: only the person who paired the computer can start one, in a repo linked to a product and
checked out on the computer, while `glow run` (0.1.10 or later) is on there, and only with their Glow phone's
signature (Face ID), which the computer checks. Nothing starts by itself. With the runner on, the key can
also say which linked repos are checked out, pick up a waiting session (Glow hands the prompt over once and then
deletes it) and report its status. Glow allows 10 sessions at once per computer (3 to a runner before 0.1.13), each one run or a bundle of up to 8 in line for one repo, the rest waiting their turn; a session not signed in 2 minutes,
or signed but not picked up (in 6 hours, or 10 minutes with the runner off) fails (closed nightly at the latest, prompt deleted), and pausing or removing the computer stops
its sessions, as does Glow's own kill switch. Every session has full access (`--dangerously-skip-permissions`): nothing
asks before a command, and a task runs as you on this computer. When someone else wrote the task, or it came from a
capture, the session's reply goes to you only (under the session in the Agents tab), never to a channel. Only you see
which repos the runner found on your computer.
