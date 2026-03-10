<p align="center">
  <h1 align="center">railyard</h1>
  <p align="center"><strong>Guardrails for AI coding agents. Deterministic. On-device. Tamper-proof.</strong></p>
</p>

<p align="center">
  <a href="https://github.com/railyarddev/railyard/stargazers"><img src="https://img.shields.io/github/stars/railyarddev/railyard?style=flat" alt="GitHub stars"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/tests-77%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/built%20with-Rust-orange.svg" alt="Built with Rust">
  <a href="https://discord.gg/PLACEHOLDER"><img src="https://img.shields.io/badge/Discord-join%20chat-7289da" alt="Discord"></a>
</p>

<p align="center">
  <a href="#what-is-railyard">What is it?</a> &middot;
  <a href="#install">Install</a> &middot;
  <a href="#how-it-works">How it works</a> &middot;
  <a href="#protections">Protections</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

---

> **We're looking for contributors.** Railyard is early and there's a lot to build — more evasion detectors, support for other agents (Cursor, Windsurf, Codex), better policy tooling, Windows/Linux testing. If you care about making AI agents safer, [jump in](https://discord.gg/PLACEHOLDER). See [Contributing](#contributing) to get started.

---

## What is Railyard?

A Rust binary that sits between Claude Code and your system. Every tool call — shell commands, file writes, file reads — passes through Railyard **before it touches the world**.

```
$ railyard install
  ✓ Hooks registered with Claude Code
  ✓ Mode: chill (16 rules)

$ claude "clean up duplicate AWS resources"
  ⛔ BLOCKED  terraform destroy
     rule: terraform-destroy · railyard.yaml:14
```

**One command to install. Two modes: chill or hardcore. <2ms per decision. Fully on-device. The agent can't turn it off.**

### Why does this exist?

AI coding agents have shell access. They make mistakes — and prompt-based guardrails are just suggestions the model can ignore.

| When | What happened |
|------|---------------|
| Feb 2026 | Claude Code ran `terraform destroy` on production. **1.9M rows gone.** |
| Feb 2026 | A background agent ran `drizzle-kit push --force`. **60 tables wiped.** |
| 2025-26 | Agents ran `rm -rf ~/`, `git reset --hard`, `DROP DATABASE` on live systems. |

These aren't hypothetical. Agents have been [documented bypassing their own safety rules](https://github.com/anthropics/claude-code/issues/29691). Railyard enforces rules **deterministically at the system level** — outside the LLM, where the model can't talk its way around them.

---

## Install

```bash
# Option 1: Build from source
cargo install --path .
railyard install

# Option 2: npm (downloads prebuilt binary)
npm install -g railyard
railyard install
```

That's it. You're protected. Zero config required — ships with **chill mode** (blocks destructive commands, no restrictions on file access or network).

Want full lockdown? Use **hardcore mode**:

```bash
railyard install --mode hardcore
```

### Interactive setup

```bash
railyard configure
```

Pick your mode, toggle individual protections on/off, configure fencing — all from an interactive terminal UI.

To uninstall, run `railyard uninstall` from your terminal — a native OS confirmation dialog will appear. The agent cannot click it. [More on self-protection below.](#6-self-protection--the-agent-cant-turn-it-off)

---

## Two Modes

| | **Chill** | **Hardcore** |
|---|---|---|
| **Philosophy** | Just don't blow stuff up | Full lockdown |
| **Destructive commands** | 13 rules (block/approve) | 13 rules (block/approve) |
| **Self-protection** | 3 rules | 3 rules |
| **Network policy** | — | 5 rules (curl\|sh, netcat, POST, wget, ssh) |
| **Credential protection** | — | 2 rules (env dump, git config) |
| **Evasion detection** | — | 4 rules (base64, eval, hex, symlinks) |
| **Path fencing** | Off by default | On (project dir only, denies ~/.ssh, ~/.aws, etc.) |
| **Trace logging** | On | On |
| **Snapshots** | On | On |
| **Total rules** | 16 | 27 |

**Chill mode** is the default. You get protection from the commands that actually destroy things, plus self-protection so the agent can't disable Railyard. No restrictions on file access or network — the agent can still be productive.

**Hardcore mode** is for when you want full control. Network egress is monitored, credentials are fenced, evasion techniques are caught, and the agent can only access your project directory.

---

## How It Works

```
┌──────────────────────────────────────────┐
│                                          │
│   Claude Code                            │
│                                          │
│   Agent wants to run:                    │
│   terraform destroy                      │
│                                          │
│         │                                │
│         ▼                                │
│                                          │
│   Hook fires before execution ───────────┼──────►  Railyard (Rust binary)
│                                          │                │
│         │                                │                ▼
│         │                                │    ┌───────────────────────┐
│         │                                │    │                       │
│         │                                │    │  1. Path Fence        │
│         │                                │    │     Is the file in    │
│         │                                │    │     a safe location?  │
│         │                                │    │                       │
│         │                                │    │  2. Evasion Detection │
│         │                                │    │     Decode base64,    │
│         │                                │    │     expand variables, │
│         │                                │    │     unwrap sh -c      │
│         │                                │    │                       │
│         │                                │    │  3. Policy Engine     │
│         │                                │    │     Match against     │
│         │                                │    │     allow/block/ask   │
│         │                                │    │     rules             │
│         │                                │    │                       │
│         │                                │    │  4. Snapshot          │
│         │                                │    │     Back up file      │
│         │                                │    │     before write      │
│         │                                │    │                       │
│         │                                │    │  5. Trace Log         │
│         │                                │    │     Log the decision  │
│         │                                │    │                       │
│         │                                │    └───────────┬───────────┘
│         │                                │                │
│         │  ◄─────────────────────────────┼────────────────┘
│         │  { permissionDecision: "deny"} │
│         ▼                                │        Decision in <2ms
│                                          │        No network calls
│   ⛔ Tool blocked. Agent informed.       │        Fully on-device
│                                          │
└──────────────────────────────────────────┘
```

Railyard hooks into Claude Code's native [hooks system](https://docs.anthropic.com/en/docs/claude-code/hooks). Every tool call is intercepted **before execution**. The binary evaluates your policy and returns `allow`, `deny`, or `ask`. The model never gets a chance to bypass it — this runs outside the LLM.

---

## Protections

### 1. Command Blocking — Stops Real Disasters

Active in both modes. Zero config.

| Rule | What it catches | Why |
|------|----------------|-----|
| `terraform-destroy` | `terraform destroy`, `apply -auto-approve` | DataTalks 1.9M row incident |
| `rm-rf-critical` | `rm -rf /`, `~/`, `$HOME` | Home directory deletion |
| `sql-drop` | `DROP TABLE`, `DATABASE`, `SCHEMA` | Production database wipes |
| `git-force-push` | `git push --force` | Overwrites remote history |
| `git-reset-hard` | `git reset --hard` | Destroys uncommitted work |
| `git-clean-force` | `git clean -f` | Removes untracked files |
| `drizzle-force` | `drizzle-kit push --force` | 60-table drop incident |
| `disk-format` | `mkfs`, `dd of=/dev/` | Disk destruction |
| `k8s-delete-ns` | `kubectl delete namespace` | K8s namespace deletion |
| `aws-s3-rm-recursive` | `aws s3 rm --recursive` | S3 data loss |
| `docker-system-prune` | `docker system prune -a` | Removes all images |
| `chmod-777-recursive` | `chmod -R 777 /` | Security disaster |
| `npm-publish` | `npm publish` | Requires human approval |

### 2. Evasion Detection — Catches Agent Bypass Attempts (Hardcore)

Agents sometimes try to sneak past safety rules. Railyard normalizes commands before matching:

```
Direct:     terraform destroy                           → ⛔ blocked
Base64:     echo dGVycmFmb3Jt... | base64 -d | sh      → decoded    → ⛔ blocked
Variable:   CMD="terraform destroy"; $CMD               → expanded   → ⛔ blocked
Shell wrap: sh -c "terraform destroy"                   → unwrapped  → ⛔ blocked
Eval:       eval "ter""raform destroy"                  → joined     → ⛔ blocked
Backtick:   `echo terraform` destroy                    → resolved   → ⛔ blocked
Hex:        $'\x74\x65\x72\x72...'                      → decoded    → ⛔ blocked
```

### 3. Filesystem Sandboxing — Protects Your Credentials (Hardcore)

```
  Your project directory     ✅ Claude Code can read/write here
  ~/.ssh/                    ⛔ DENIED
  ~/.aws/                    ⛔ DENIED
  ~/.gnupg/                  ⛔ DENIED
  ~/.claude/                 ⛔ DENIED
  ~/.config/gcloud/          ⛔ DENIED
  /etc/                      ⛔ DENIED
```

All paths are canonicalized — `../` traversal and symlink escapes are caught.

### 4. Network Policy (Hardcore)

| Rule | Action |
|------|--------|
| `curl \| sh` / `curl \| bash` | Block |
| `nc` / `netcat` / `ncat` | Block |
| `curl -X POST` / `curl --data` | Approve (human sign-off) |
| `wget` | Approve |
| `ssh` / `scp` / `rsync` | Approve |

### 5. Snapshots — Cursor-Style Checkpoints for Claude Code

Every file write/edit is backed up before the change. Undo one edit, N edits, or an entire session.

```
$ railyard rollback --steps 1 --session abc123
  ✓ Restored src/main.rs from snapshot c3

$ railyard rollback --session abc123
  ✓ Restored src/main.rs from snapshot a1
  ✓ Restored src/lib.rs from snapshot a2
```

### 6. Audit Trail — Know Exactly What the Agent Did

Every tool call logged as structured JSONL:

```
$ railyard log --session abc123

[14:22:01Z] BLOCKED   Bash | terraform destroy (terraform-destroy)
[14:22:01Z]   OK      Bash | npm test
[14:22:02Z]   OK      Edit | src/main.rs
[14:22:03Z] APPROVE   Bash | psql -h prod-db (prod-db)
```

### 7. Self-Protection — The Agent Can't Turn It Off

Three layers prevent the agent from disabling Railyard:

```
Layer 1: Hook Blocklist
  Claude Code runs "railyard uninstall"
  → Railyard's own hook intercepts it
  → ⛔ BLOCKED before it executes

Layer 2: Terminal Check
  Even if the hook is bypassed, uninstall
  checks if stdin is an interactive terminal.
  Agents pipe stdin → rejected.

Layer 3: Native OS Dialog
  Even if both layers are bypassed, a native
  confirmation dialog appears:

  ┌─────────────────────────────────────────┐
  │                                         │
  │  ⚠️  Railyard                           │
  │                                         │
  │  Remove Railyard guardrails?            │
  │                                         │
  │  Claude Code will run without           │
  │  restrictions until you reinstall.      │
  │                                         │
  │  To turn protection back on:            │
  │    railyard install                     │
  │                                         │
  │          [ Cancel ]  [ Remove ]         │
  │                                         │
  └─────────────────────────────────────────┘

  macOS: native AppleScript dialog
  Windows: PowerShell MessageBox
  Linux: zenity (GNOME) / kdialog (KDE)

  An agent cannot click a GUI button.
```

---

## Configuration

### Quick start

```bash
# Interactive — pick mode, toggle protections
railyard configure

# Or generate a YAML file to edit manually
railyard init                    # chill mode (default)
railyard init --mode hardcore    # hardcore mode
```

### railyard.yaml

```yaml
version: 1
mode: chill   # or "hardcore"

blocklist:
  - name: terraform-destroy
    tool: Bash
    pattern: "terraform\\s+(destroy|apply\\s+.*-auto-approve)"
    action: block
    message: "Blocked: destructive infrastructure command"

approve:
  - name: npm-publish
    tool: Bash
    pattern: "npm\\s+publish"
    action: approve
    message: "npm publish requires approval"

allowlist: []

fence:
  enabled: true
  allowed_paths: []          # empty = project directory only
  denied_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - "/etc"

trace:
  enabled: true
  directory: .railyard/traces

snapshot:
  enabled: true
  tools: [Write, Edit]
  directory: .railyard/snapshots
```

**Rule evaluation order:** allowlist → blocklist → approve → allow

Or skip the YAML and use plain English:

```bash
$ railyard chat
> "Block all database migrations against production"
> "Require approval for any docker push command"
```

---

## CLI Reference

```
railyard install [--mode chill|hardcore]   # Register hooks with Claude Code
railyard uninstall                         # Remove hooks (requires OS confirmation)
railyard init [--mode chill|hardcore]      # Generate starter railyard.yaml
railyard configure                         # Interactive protection setup
railyard status                            # Show current protection status
railyard chat                              # Policy builder via Claude Code

railyard log                               # List sessions with traces
railyard log --session <id>                # View traces for a session

railyard rollback --session <id>                     # List snapshots
railyard rollback --session <id> --steps 3           # Undo last 3 edits
railyard rollback --session <id> --id <snap>         # Restore specific snapshot
railyard rollback --session <id> --file path         # Restore specific file
```

---

## Architecture

```
railyard/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── types.rs             # Shared types (HookInput, Policy, Decision)
│   ├── configure.rs         # Interactive terminal configuration UI
│   ├── hook/
│   │   ├── handler.rs       # Reads stdin JSON, dispatches to handlers
│   │   ├── pre_tool.rs      # PreToolUse: fence → evasion → policy → snapshot → trace
│   │   ├── post_tool.rs     # PostToolUse: trace completion
│   │   └── session.rs       # SessionStart: init logging
│   ├── block/
│   │   ├── matcher.rs       # Regex matching against policy rules
│   │   └── evasion.rs       # Command normalization (7 evasion techniques)
│   ├── policy/
│   │   ├── engine.rs        # Rule evaluation (allowlist → block → approve)
│   │   ├── loader.rs        # Find & parse railyard.yaml, merge with defaults
│   │   └── defaults.rs      # Built-in rules (16 chill + 11 hardcore)
│   ├── fence/
│   │   └── path.rs          # Filesystem sandboxing with path canonicalization
│   ├── snapshot/
│   │   ├── capture.rs       # SHA-256 snapshots before file writes
│   │   └── rollback.rs      # Restore from any snapshot
│   ├── trace/
│   │   └── logger.rs        # JSONL structured audit logging
│   └── install/
│       └── hooks.rs         # Register/remove hooks + native OS confirmation
├── defaults/
│   └── railyard.yaml        # Starter policy template
├── npm/
│   ├── package.json         # npm distribution wrapper
│   ├── install.js           # Binary download/build script
│   └── demo.js              # Quick demo of protections
└── tests/
    └── attack_simulation.rs # 28 real-world incident + evasion tests
```

---

## Testing

```bash
# All tests: 49 unit + 28 attack simulations = 77
cargo test

# Just the attack simulations
cargo test --test attack_simulation
```

Every test represents a real pattern that has been observed or reported:

- **Incident reproductions** — terraform destroy, drizzle-kit force push, rm -rf home, DROP DATABASE, git force push, S3 recursive delete
- **Evasion attempts** — base64 encoding, variable expansion, shell wrappers, eval concatenation, backtick substitution
- **Fence violations** — SSH key access, AWS credential access, /etc/passwd reads
- **Self-protection** — agent can't uninstall hooks, can't edit settings, can't remove binary

---

## Contributing

Railyard is early. There's a lot to build and we'd love your help.

**Good first issues:**
- Add new default blocklist rules for common footguns
- Test on Windows and Linux
- Improve evasion detection (new encoding schemes, new shell tricks)

**Bigger projects:**
- Support for Cursor, Windsurf, Codex, and other agents
- `railyard watch` — live TUI dashboard for active sessions
- Policy inheritance (org-wide defaults + project overrides)
- `railyard test` — dry-run a policy against a list of commands
- Homebrew / apt / winget distribution

```bash
# Get started
git clone https://github.com/railyarddev/railyard.git
cd railyard
cargo test
```

**[Join us on Discord](https://discord.gg/PLACEHOLDER)**

---

## License

MIT License. Copyright 2026 Ari Choudhury.
