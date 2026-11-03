---
name: unignore
description: Let this repo send to Glow again from this computer (undoes ignore). Use when the user wants Glow to stop ignoring the current repo or folder, or a repo they name.
allowed-tools: Bash(~/.glow/glow unignore:*)
disable-model-invocation: true
metadata:
  short-description: Let this repo send to Glow again
---

Run this in the session's working folder:

```bash
~/.glow/glow unignore
```

If the user named another folder, or a repo as owner/name, put it after `unignore` (quoted). Show the output to the user as it is, in a code block. It reads (and for ignore, writes) ~/.glow/config.json and calls Glow’s API: if a sandbox blocks that, run it with permission to go outside the sandbox. If `~/.glow/glow` isn't there, Glow isn't set up on this computer: tell the user to run `npx @winding-labs/glow`.
