---
name: ignore
description: Stop this repo sending anything to Glow from this computer. Use when the user wants Glow to ignore, mute or stop reporting the current repo or folder, or a repo they name.
allowed-tools: Bash(~/.glow/glow ignore:*)
metadata:
  short-description: Stop this repo sending to Glow
---

Run this in the session's working folder:

```bash
~/.glow/glow ignore
```

If the user named another folder, or a repo as owner/name, put it after `ignore` (quoted). Show the output to the user as it is, in a code block. It reads (and for ignore, writes) ~/.glow/config.json and calls Glow’s API: if a sandbox blocks that, run it with permission to go outside the sandbox. If `~/.glow/glow` isn't there, Glow isn't set up on this computer, so it sends nothing: tell the user that.
