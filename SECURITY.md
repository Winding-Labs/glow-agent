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
  itself: each session runs only with your Glow phone's signature over it (below), up to 3 at once; a task someone else
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
  yourself, and stop it (`glow run stop`) when you don't need it.
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
messages you sent to this computer's sessions, and revoke itself. It can't read anything else in your workspace. It
stops working when you remove the computer, leave the workspace, or don't use it for 90 days.

Messages back: only the person who paired the computer can message its sessions, with a fresh second factor each time and their Glow phone's signature, which the hook checks.
`npx @winding-labs/glow messages off` turns them off on the computer.

Sessions started from Glow: only the person who paired the computer can start one, in a repo linked to a product and
checked out on the computer, while `glow run` (0.1.10 or later) is on there, and only with their Glow phone's
signature (Face ID), which the computer checks. Nothing starts by itself. With the runner on, the key can
also say which linked repos are checked out, pick up a waiting session (Glow hands the prompt over once and then
deletes it) and report its status. Glow allows 3 at once per computer, the rest waiting their turn, and 30 a day; a session not signed in 2 minutes,
or signed but not picked up (in 6 hours, or 10 minutes with the runner off) fails (closed nightly at the latest, prompt deleted), and pausing or removing the computer stops
its sessions, as does Glow's own kill switch. Every session has full access (`--dangerously-skip-permissions`): nothing
asks before a command, and a task runs as you on this computer. When someone else wrote the task, or it came from a
capture, the session's reply goes to you only (under the session in the Agents tab), never to a channel. Only you see
which repos the runner found on your computer.
