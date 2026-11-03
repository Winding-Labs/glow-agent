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
- **Never from a repo you ignore.** `/glow:ignore` in a repo (or `npx @winding-labs/glow ignore`) and its sessions send
  nothing from this computer, even if it's linked: the hook stops before it makes any request.
- **Only the agent's last reply and the request it answers**, with keys and tokens masked, plus the branch, the titles
  of the branch's commits and a pull request link on the same repo, and which of GitHub (`gh` signed in), Chrome, Docker
  and Xcode this computer has (yes or no each, for its tags in Glow). Never your code, files or the transcript: the hook
  reads only your latest request from the agent's own session file.
- Glow turns the reply into a short summary right away and **doesn't keep the reply or the request**. From the request
  it keeps only the recipe it names when it's a job you'd run again ("Pen test the API", "Optimize SEO"), so it can
  count how often you run it and offer to run it for you. Don't want that? `npx @winding-labs/glow recipes off`.
- This computer's key can do three things: send a report, read which repos are linked, and fetch messages you sent to
  its sessions. While `glow run` is on, it also picks up the sessions you start here and says how they're going (the
  repo, the last command or file, masked; never output or code). It can't read anything else in your workspace. It
  stops working after 90 days unused.

## Messages back

Only the person who paired the computer can message its sessions, and Glow asks them for Face ID or their passkey
first. Claude Code picks a message up while it's idle (for 25 minutes after its last reply); Codex picks it up when its
current turn ends. Don't want that? `npx @winding-labs/glow messages off` on the computer.

## Start sessions from Glow

```
npx @winding-labs/glow run ~/code
```

Only if you want it, and only while it runs: Glow's Agents tab can then start a Claude Code session on this computer,
from a queued task ("Run on …") or a prompt you type ("New session"). It runs in your checkout of a repo that's linked
to a product and found under the folders you give it (the current folder by default), and the Agents tab shows it live:
the repo, what it's on, its status, how long it's been running, its last command or tool, and a Stop button. Its reply
posts to the product's channel like any session's, except for a task someone else wrote or one filed from a capture:
then only you see it, under the session.

- **Only you** (the person who paired the computer) can start one, and Glow asks for Face ID or your passkey first.
- **A mode you pick each time:** *Look only* (Claude Code's plan mode: it reads, changes nothing), *Edit files* (also
  edits files in the repo) or *Auto* (Claude Code's auto mode; never for a queued task). Never a mode that skips
  permission checks. Opus at medium effort unless you pick another model or effort.
- **This computer decides too**, whatever Glow sends: `--max-mode read|edit|auto` is the most a session may do here
  (*Look only* by default: `--max-mode edit` lets sessions edit files, `--max-mode auto` allows *Auto*; the app offers
  only what the computer allows); `--repo owner/name` (repeat it) runs only those repos,
  and `--repo owner/name=~/code/zest` picks the checkout when a repo is checked out more than once (otherwise it doesn't
  run; worktrees don't count: it runs in the main checkout). Only in a folder you've trusted in Claude Code (opened `claude` there and said yes), since its own `.claude`
  settings and hooks apply. A session id is run once, never again.
- **Up to 3 at once** on a computer, one per repo, 30 a day, 3 hours each at most. Stop from Glow ends the session and
  the commands it started. Pausing the computer in Glow stops them all; Ctrl-C (or closing the terminal) stops the
  runner and its sessions, and everything they started.
- `run --background` keeps it going after you close the terminal (log: `~/.glow/runner.log`); `run stop` stops it. A
  session the runner started can't stop it or turn Glow off.

## In Claude Code and Codex

```
/glow:status      what this folder sends (and why not), what's set up, which repos report or are ignored
/glow:ignore      this repo never sends to Glow from this computer (add a folder or owner/name for another)
/glow:unignore    let it send again (only when you type it: an agent can't run it on its own in Claude Code)
/glow:run         start (or stop) the runner in the background, for the linked repos under the session's folder
                  (only when you type it; Look only: --max-mode and --repo are for the terminal)
```

In Codex they're `$glow:status`, `$glow:ignore`, `$glow:unignore` and `$glow:run`. Setup adds them as a `glow` plugin, through each
agent's own `plugin` command; each may run only its own `~/.glow/glow` command, and a session Glow started can't run
any of them.

## Commands

```
npx @winding-labs/glow                 set up (or add an agent you installed later)
npx @winding-labs/glow status          what this folder sends, what's set up, which repos report
npx @winding-labs/glow ignore [repo]   this repo (or a folder, or owner/name) never sends from this computer
npx @winding-labs/glow unignore [repo] let it send again
npx @winding-labs/glow off | on        stop or start sending from this computer
npx @winding-labs/glow messages off    messages from Glow no longer reach your agents here (messages on: again)
npx @winding-labs/glow run [folders]   let Glow start Claude Code sessions in the linked repos under these folders
    [--max-mode read|edit|auto] [--repo owner/name[=path]…] [--background]
npx @winding-labs/glow run stop        stop the runner (and its sessions)
npx @winding-labs/glow uninstall       remove the hooks and the plugin, revoke the key, delete ~/.glow
```

Codex asks before it runs any new hook: open Codex and run `/hooks` once to trust Glow's.

Files: `~/.glow/` (owner-only: the key, the ignored repos, a copy of this package and the plugin), a `Stop` hook in `~/.claude/settings.json` and `~/.codex/hooks.json` (a
symlinked settings file stays a link). The first time, the originals are copied to `*.before-glow`.

Security: [SECURITY.md](SECURITY.md).
