# Glow for coding agents

```
npx @winding-labs/glow
```

Run it once on your computer. It finds the coding agents you use (Claude Code, Codex), pairs the computer with your
Glow workspace (you approve it in Glow with your passkey, then type the 6-digit code Glow shows you back into the
terminal), and adds a small hook to each agent. From then on, every
session in a repo that's linked to one of your products keeps one post in that product's channel: what it did, its
branch, commits and pull request. From that post in Glow you can send the session a message, and the agent gets it.

## What it sends, and where

- **Only to Glow** (`https://app.meetglow.ai`). The address is fixed when you set up and can't be changed by a repo or
  an environment variable (the hook runs with an empty environment but `HOME` and `PATH`).
- **Only from linked repos.** A session in any other repo sends nothing. You link repos to products in Glow.
- **Only the agent's last reply**, with keys and tokens masked, plus the branch, the titles of the branch's commits and
  a pull request link on the same repo. Never your code, files, prompts or the transcript.
- Glow turns the reply into a short summary right away and **doesn't keep the reply itself**.
- This computer's key can do three things: send a report, read which repos are linked, and fetch messages you sent to
  its sessions. It can't read anything else in your workspace. It stops working after 90 days unused.

## Messages back

Only the person who paired the computer can message its sessions, and Glow asks them for Face ID or their passkey
first. Claude Code picks a message up while it's idle (for 25 minutes after its last reply); Codex picks it up when its
current turn ends. Don't want that? `npx @winding-labs/glow messages off` on the computer.

## Commands

```
npx @winding-labs/glow                 set up (or add an agent you installed later)
npx @winding-labs/glow status          what's set up and which repos report
npx @winding-labs/glow off | on        stop or start sending from this computer
npx @winding-labs/glow messages off    messages from Glow no longer reach your agents here (messages on: again)
npx @winding-labs/glow uninstall       remove the hooks, revoke the key, delete ~/.glow
```

Codex asks before it runs any new hook: open Codex and run `/hooks` once to trust Glow's.

Files: `~/.glow/` (the key, owner-only), a `Stop` hook in `~/.claude/settings.json` and `~/.codex/hooks.json` (a
symlinked settings file stays a link). The first time, the originals are copied to `*.before-glow`.

Security: [SECURITY.md](SECURITY.md).
