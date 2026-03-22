# Railguard — Active Guardrails

Railguard is monitoring this session. Every tool call (Bash, Write, Edit, Read) passes through Railguard before execution.

## What you need to know

- **Some commands will be blocked.** If you see a "denied" response from a hook, it means Railguard blocked the command. Do NOT retry the same command — find a safer alternative.
- **Some commands require human approval.** If you see an "ask" response, the human will be prompted to approve or deny.
- **File writes are snapshotted.** Every Write/Edit you make is backed up before execution. The human can rollback any change.
- **Everything is logged.** All tool calls and decisions are recorded in `.railguard/traces/`.

## If something goes wrong

If the human asks you to undo changes, fix a mistake, or rollback:

1. **Get context first.** Run: `railguard context --session $SESSION_ID --verbose`
   This shows you exactly what changed, diffs, blocked commands, and available rollback commands.

2. **Check what changed.** Run: `railguard diff --session $SESSION_ID`
   Or for a specific file: `railguard diff --session $SESSION_ID --file <path>`

3. **Rollback options:**
   - Undo the last edit: `railguard rollback --session $SESSION_ID --steps 1`
   - Undo the last N edits: `railguard rollback --session $SESSION_ID --steps N`
   - Restore a specific file: `railguard rollback --session $SESSION_ID --file <path>`
   - Restore everything: `railguard rollback --session $SESSION_ID`
   - Restore a specific snapshot: `railguard rollback --session $SESSION_ID --id <snapshot-id>`

4. **Find your session ID.** Run: `railguard log`
   This lists all sessions. Pick the most recent one.

## Configuring Railguard

You **can** help the user customize their Railguard policy. This is encouraged:

- **Read `railguard.yaml`** to understand the current policy.
- **Propose edits to `railguard.yaml`** — the user will be prompted to approve before any change is applied.
- **Run `railguard init`** to generate a starter `railguard.yaml` if one doesn't exist (user approves).
- **Run `railguard status`** to show the current protection state.
All changes to Railguard policy require explicit human approval. You generate the change, the user reviews and accepts or rejects it. Changes take effect on the next tool call — no restart needed.

## Do NOT attempt to

- Run `railguard uninstall` — it will be blocked.
- Modify `~/.claude/settings.json` — it will be blocked.
- Remove the railguard binary — it will be blocked.
- Access `~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc`, or other fenced paths (if path fencing is enabled).
