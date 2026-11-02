# Security

Report a vulnerability to **security@meetglow.ai**. Please don't open a public issue for it.

## What this package can do on your computer

- **Talk to one host:** `https://app.meetglow.ai`, fixed at setup in `~/.glow/config.json` (owner-only) and checked on
  every call. Redirects are refused. The hook runs with an empty environment except `HOME` and `PATH`, so no proxy, TLS
  or `NODE_*` setting can send it anywhere else.
- **Send only from repos you linked** to a product in Glow: the agent's last reply (keys and tokens masked), the branch,
  up to five commit titles on it, and a pull request link on the same repo. Never code, files, prompts or transcripts.
- **Run git read-only** (the origin URL, the branch, commit titles), with no shell, hooks, fsmonitor, pager, signature
  checks or `GIT_*` variables, so a repo's `.git/config` can't make it run a program.
- **Edit two settings files:** add one `Stop` hook to `~/.claude/settings.json` and `~/.codex/hooks.json`, keep
  everything else, back up the originals once (`*.before-glow`), and never overwrite a file that isn't valid JSON.

## What the key can do in Glow

Pairing is a device flow: you approve the computer in Glow with a fresh second factor, then type the 6-digit code Glow
shows you into the terminal. A code someone else approves gets nothing.

The key (`glowc_…`, stored in Glow only as a hash) can send a session report, read which repos are linked, fetch the
messages you sent to this computer's sessions, and revoke itself. It can't read anything else in your workspace. It
stops working when you remove the computer, leave the workspace, or don't use it for 90 days.

Messages back: only the person who paired the computer can message its sessions, with a fresh second factor each time.
`npx @winding-labs/glow messages off` turns them off on the computer.
