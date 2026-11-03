---
name: status
description: Show what Glow sends from this computer. Use when the user asks whether Glow is set up, whether this repo reports to Glow, or which repos report or are ignored.
allowed-tools: Bash(~/.glow/glow status)
metadata:
  short-description: What Glow sends from here
---

Run this in the session's working folder:

```bash
~/.glow/glow status
```

Show the output to the user as it is, in a code block. It reads (and for ignore, writes) ~/.glow/config.json and calls Glow’s API: if a sandbox blocks that, run it with permission to go outside the sandbox. If `~/.glow/glow` isn't there, Glow isn't set up on this computer: tell the user to run `npx @winding-labs/glow`.
