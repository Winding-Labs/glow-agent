---
name: run
description: Start or stop Glow's runner on this computer, so Claude Code sessions can be started from the Glow app (Agents tab) in the linked repos under this folder. Only when the user types /glow:run.
allowed-tools: Bash(~/.glow/glow run --background), Bash(~/.glow/glow run stop), Bash(~/.glow/glow status)
disable-model-invocation: true
metadata:
  short-description: Let Glow start sessions here
---

`/glow:run` starts it, `/glow:run stop` stops it. Run exactly one of these commands, nothing else, and add no folders or options to it (for those, the user runs `npx @winding-labs/glow run` in a terminal).

To start it in the background, for the linked repos checked out in the session's working folder and the folders under it. Its sessions look only (Claude Code's plan mode: they read and change nothing); to let them edit files, the user runs `npx @winding-labs/glow run --max-mode edit` in a terminal (`--repo` and other folders are for the terminal too):

```bash
~/.glow/glow run --background
```

To stop it (and the sessions it runs):

```bash
~/.glow/glow run stop
```

To see whether it's on: `~/.glow/glow status` (the Runner row).

Show the output to the user as it is, in a code block. While it runs, the person who paired this computer can start Claude Code sessions here from Glow. It reads ~/.glow/config.json and calls Glow's API: if a sandbox blocks that, run it with permission to go outside the sandbox. If `~/.glow/glow` isn't there, Glow isn't set up on this computer: tell the user to run `npx @winding-labs/glow`.
