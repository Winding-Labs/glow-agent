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
  checks or `GIT_*` variables, so a repo's `.git/config` can't make it run a program.
- **Edit two settings files:** add one `Stop` hook to `~/.claude/settings.json` and `~/.codex/hooks.json`, keep
  everything else, back up the originals once (`*.before-glow`), and never overwrite a file that isn't valid JSON.
- **Add one plugin** (`glow`, from `~/.glow/marketplace`) with each agent's own `claude plugin` / `codex plugin`
  command. Each may run only its own `~/.glow/glow` command (`status`, `ignore …`, `unignore …`; `/glow:run`: exactly
  `run --background`, `run stop` or `status`), and `/glow:unignore` and `/glow:run` run only when you type them.

- **Start Claude Code, only while `glow run` runs** (you start it; nothing installs it to start on its own). It runs
  `claude` as an argument list (no shell), in your checkout of a linked repo found under the folders you gave it, with
  the prompt on stdin (so a prompt can't become a flag), in the mode picked in Glow: `plan` for *Look only* (it changes
  nothing), `acceptEdits` for *Edit files*, `auto` for *Auto*, with permission prompts turned down. Never
  `bypassPermissions` or `--dangerously-skip-permissions`; and always `--disallowedTools` for Glow's own CLI
  (`~/.glow/glow`, `npx @winding-labs/glow`, `node …/glow.mjs`) and files (`~/.glow`, the computer's key), which no
  allow rule (the plugin's included) can grant back. That list matches the command's text, so a session already
  allowed arbitrary shell commands (*Auto*, or a broad allow rule in your own or the repo's settings) could spell its
  way around it (`~/.gl?w/glow`); *Look only* and *Edit files* don't allow that, and the CLI also refuses any command
  run from inside a session. One command per call: `glow ignore x run …` is refused, so a skill allowed to run one
  command can't reach another. Stop, a pause in Glow, the 3-hour limit, Ctrl-C or closing the
  terminal ends a session and everything it started: Claude Code's Bash tool and hooks start each command in a process
  group of its own, so the runner signals every group under that Claude Code (SIGTERM, then SIGKILL after 5 s; SIGTERM
  at once if the runner itself exits).
- **Not take Glow's word for it.** The runner refuses, on your computer: a mode above `--max-mode` (*Look only*
  unless you widen it: `--max-mode edit` or `auto`, also for `/glow:run`); a repo outside `--repo` when you gave it; a folder Claude Code hasn't been trusted in (`claude -p` skips
  that question, and a repo's own `.claude` settings and hooks would apply); a repo with more than one main checkout
  unless you pinned one (`--repo owner/name=path`; its worktrees aren't copies: it runs in the main one); a model or
  effort not on its list (only `--model opus|sonnet|haiku|fable` and `--effort low…max` ever reach `claude`); and a
  session id it has already been given. A command run inside one of
  its sessions can't stop the runner, turn Glow off or change what it sends: besides the denied tools, `glow` refuses
  when its environment has the session's marker (`GLOW_RUN_SESSION`, kept by `~/.glow/glow`), when a session's Claude
  Code is among its parent processes, or when it runs in a session's process group.
  Signed launch tokens (Glow signs each session, the computer checks it with a key it keeps) are a later step: today a
  compromised Glow account or server could start a session within those limits.
- **Report how a session goes:** running, done, failed or stopped; turns, cost, how many tool calls were turned down;
  and its last step as one line: a command by its program and subcommand only (`$ psql …`, never its arguments), a
  file path relative to the repo, a search pattern or a web host. Keys and tokens are masked before anything is cut,
  the home folder is `~`, and Glow cuts and scrubs it again. Never output, file contents or the transcript.

## What the key can do in Glow

Pairing is a device flow: you approve the computer in Glow with a fresh second factor, then type the 6-digit code Glow
shows you into the terminal. A code someone else approves gets nothing.

The key (`glowc_…`, stored in Glow only as a hash) can send a session report, read which repos are linked, fetch the
messages you sent to this computer's sessions, and revoke itself. It can't read anything else in your workspace. It
stops working when you remove the computer, leave the workspace, or don't use it for 90 days.

Messages back: only the person who paired the computer can message its sessions, with a fresh second factor each time.
`npx @winding-labs/glow messages off` turns them off on the computer.

Sessions started from Glow: only the person who paired the computer can start one, with a fresh second factor, in a
repo linked to a product and checked out on the computer, while `glow run` is on there. With the runner on, the key can
also say which linked repos are checked out, pick up a waiting session (Glow hands the prompt over once and then
deletes it) and report its status. Glow allows 3 at once per computer, one per repo, and 30 a day, and never more
than the runner's `--max-mode`; a session not picked up in 10 minutes fails (closed nightly at the latest, prompt
deleted), and pausing or removing the computer stops its sessions, as does Glow's own kill switch. A queued task never
runs in *Auto*, and the start sheet says who wrote the task's text. When someone else wrote the task, or it came from a
capture, the session's reply goes to you only (under the session in the Agents tab), never to a channel. Only you see
which repos the runner found on your computer.
