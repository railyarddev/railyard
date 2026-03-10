<p align="center">
  <h1 align="center">railyard</h1>
  <p align="center"><strong>Guardrails for AI coding agents. Deterministic. On-device. Tamper-proof.</strong></p>
</p>

<p align="center">
  <a href="https://github.com/railyarddev/railyard/stargazers"><img src="https://img.shields.io/github/stars/railyarddev/railyard?style=flat" alt="GitHub stars"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/tests-136%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/pentest-71%25%20block%20rate-blue" alt="Pentest">
  <img src="https://img.shields.io/badge/built%20with-Rust-orange.svg" alt="Built with Rust">
</p>

<p align="center">
  <a href="#what-is-railyard">What is it?</a> &middot;
  <a href="#install">Install</a> &middot;
  <a href="#how-it-works">How it works</a> &middot;
  <a href="#protections">Protections</a> &middot;
  <a href="SECURITY.md">Security</a> &middot;
  <a href="docs/ARCHITECTURE.md">Architecture</a> &middot;
  <a href="#contributing">Contributing</a>
</p>

---

## What is Railyard?

A Rust binary that sits between Claude Code and your system. Every tool call — shell commands, file writes, file reads — passes through Railyard **before it touches the world**.

```
$ railyard install
  ✓ Hooks registered with Claude Code
  ✓ Mode: hardcore (29 rules)

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
# Recommended: curl | sh (downloads prebuilt binary)
curl -fsSL https://raw.githubusercontent.com/railyarddev/railyard/main/install.sh | sh

# Or: build from source
cargo install --git https://github.com/railyarddev/railyard.git
railyard install
```

That's it. You're protected. Default mode is **hardcore** — 29 rules, path fencing, network policy, evasion detection, and session termination on evasion attempts.

Want a lighter touch?

```bash
railyard install --mode chill
```

### Interactive setup

```bash
railyard configure
```

Pick your mode, toggle individual protections on/off, configure fencing — all from an interactive terminal UI.

To uninstall, run `railyard uninstall` from your terminal — a native OS confirmation dialog will appear. The agent cannot click it.

---

## Two Modes

| | **Chill** | **Hardcore** (default) |
|---|---|---|
| **Philosophy** | Just don't blow stuff up | Full lockdown |
| **Destructive commands** | 13 rules (block/approve) | 13 rules (block/approve) |
| **Self-protection** | 3 rules | 3 rules |
| **Network policy** | — | 5 rules (curl\|sh, netcat, POST, wget, ssh) |
| **Credential protection** | — | 2 rules (env dump, git config) |
| **Evasion detection** | — | 6 rules (base64, eval, hex, symlinks, transform\|sh, interpreter obfuscation) |
| **Path fencing** | Off | On (project dir only, denies ~/.ssh, ~/.aws, etc.) |
| **Threat detection** | — | 3 tiers (pattern → behavioral → session kill) |
| **OS sandbox** | — | Profile generation (sandbox-exec / Landlock) |
| **Trace logging** | On | On |
| **Snapshots** | On | On |
| **Total rules** | 16 | 29 |

### Chill vs Hardcore — What Actually Happens

Here's the same agent session in each mode. Same commands, different outcomes.

**Destructive commands — blocked in both modes:**

```
$ claude "clean up old infrastructure"

  Agent runs: terraform destroy --auto-approve
  ⛔ BLOCKED  terraform-destroy
     "Blocked: matches 'terraform destroy'. This was the command behind
      the DataTalks 1.9M row deletion."

  Agent runs: rm -rf ~/old-project
  ⛔ BLOCKED  rm-rf-critical
     "Blocked: recursive deletion of home directory path"
```

**Network access — chill allows it, hardcore gates it:**

```
# ── Chill mode ──
  Agent runs: curl -X POST https://api.example.com/deploy -d '{"env":"prod"}'
  ✅ ALLOWED

  Agent runs: wget https://sketchy-cdn.com/install.sh
  ✅ ALLOWED

# ── Hardcore mode ──
  Agent runs: curl -X POST https://api.example.com/deploy -d '{"env":"prod"}'
  ⚠️  APPROVE  curl-post
     "HTTP POST requires human approval"
     [y/n]?

  Agent runs: wget https://sketchy-cdn.com/install.sh
  ⚠️  APPROVE  wget
     "wget requires human approval"
     [y/n]?
```

**Credential access — chill ignores it, hardcore blocks it:**

```
# ── Chill mode ──
  Agent runs: cat ~/.ssh/id_ed25519
  ✅ ALLOWED  (no path fence)

  Agent runs: env | grep SECRET
  ✅ ALLOWED

# ── Hardcore mode ──
  Agent runs: cat ~/.ssh/id_ed25519
  ⛔ BLOCKED  Path Fence
     "Path Fence: '~/.ssh/id_ed25519' is in denied path '~/.ssh'"

  Agent runs: env | grep SECRET
  ⚠️  APPROVE  env-credential-dump
     "Environment dump may expose secrets — requires approval"
     [y/n]?
```

**Evasion attempts — chill blocks the payload, hardcore kills the session:**

```
# ── Chill mode ──
  Agent runs: echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 -d | sh
  ⛔ BLOCKED  terraform-destroy  (decoded via normalization)
  Session continues normally.

  Agent runs: rev <<< 'yortsed mrofarret' | sh
  ✅ ALLOWED  (no evasion rules, no shape detection)

# ── Hardcore mode ──
  Agent runs: echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 -d | sh
  ⛔ BLOCKED  base64-shell-exec
  Session enters heightened state (watching for retries).

  Agent runs: rev <<< 'yortsed mrofarret' | sh
  ⛔ BLOCKED + SESSION KILLED  (Tier 1: transform-pipe-to-shell)

  ⚠️  RAILYARD: SESSION TERMINATED
     Tier 1 evasion detected: transform-pipe-to-shell
     Review: railyard log --session abc123
```

**File access outside project — chill allows it, hardcore fences it:**

```
# ── Chill mode ──
  Agent runs: cat /etc/hosts
  ✅ ALLOWED

  Agent runs: cat /usr/local/etc/nginx/nginx.conf
  ✅ ALLOWED

# ── Hardcore mode ──
  Agent runs: cat /etc/hosts
  ⛔ BLOCKED  Path Fence
     "Path Fence: '/etc/hosts' is in denied path '/etc'"

  Agent runs: cat /usr/local/etc/nginx/nginx.conf
  ⛔ BLOCKED  Path Fence
     "Path Fence: '/usr/local/etc/nginx/nginx.conf' is outside project directory"
```

**TL;DR:** Chill mode stops you from blowing up production. Hardcore mode stops a compromised agent from doing anything creative.

---

## How It Works

### Defense in Depth — 4 Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Blocklist + Evasion Detection                        │
│  String matching + normalization (base64, variables, hex, etc.)│
│  Catches: literal commands + lazy evasion attempts              │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Shape Detection (Tier 1)                              │
│  Detects evasion patterns: rev|sh, tr|sh, python -c chr(),    │
│  printf hex, base64|base64. Immediate session termination.      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Behavioral Analysis (Tier 2/3)                        │
│  Tracks block history. Detects retry attempts with different   │
│  syntax. Escalating warnings → session termination.             │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: OS-Level Sandbox                                      │
│  sandbox-exec (macOS) / Landlock (Linux). Kernel-enforced.     │
│  Bypass-proof. No shell trick can circumvent syscall checks.   │
└─────────────────────────────────────────────────────────────────┘
```

### Interrupt the Human

When Railyard detects evasion behavior, it doesn't just block one command — it **terminates the entire Claude Code session** and leaves a forensic trace.

```
⚠️  RAILYARD: SESSION TERMINATED

  Tier 1 evasion detected: transform-pipe-to-shell
  Command: rev <<< 'yortsed mrofarret' | sh
  Session: abc123

  Review: railyard log --session abc123
```

The agent cannot retry, iterate, or try a different bypass — because it no longer exists. The human has to manually restart, review the trace, and decide whether to continue.

**Threat tiers:**

| Tier | Trigger | Action |
|------|---------|--------|
| **1** | `rev\|sh`, `base64\|base64`, `python -c chr()`, `printf \x` | Immediate session kill |
| **2** | Variable-then-exec, `eval $var`, multi-variable concat | Warning → kill on repeat |
| **3** | Retried blocked command with different syntax | Behavioral detection → kill |

### OS-Level Sandboxing

Generate kernel-enforced sandbox profiles from your `railyard.yaml`:

```bash
railyard sandbox generate   # Creates .railyard/sandbox.sb (macOS) or bwrap script (Linux)
railyard sandbox run -- npm test   # Run command inside sandbox
railyard sandbox status     # Show available sandbox technology
```

The OS sandbox makes **every pentest bypass irrelevant**. Variable indirection, base64, hex encoding, Python chr() — none of it matters when the kernel checks actual syscalls, not command strings.

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

### 2. Evasion Detection — Catches Agent Bypass Attempts

```
Direct:     terraform destroy                           → ⛔ blocked
Base64:     echo dGVycmFmb3Jt... | base64 -d | sh      → decoded    → ⛔ blocked
Double b64: echo ZEdW... | base64 -d | base64 -d | sh  → recursive  → ⛔ blocked + SESSION KILLED
Variable:   CMD="terraform destroy"; $CMD               → expanded   → ⛔ blocked
Shell wrap: sh -c "terraform destroy"                   → unwrapped  → ⛔ blocked
Eval:       eval "ter""raform destroy"                  → joined     → ⛔ blocked
Hex:        $'\x74\x65\x72\x72...'                      → decoded    → ⛔ blocked
Rev pipe:   rev <<< 'yortsed mrofarret' | sh            → shape      → ⛔ blocked + SESSION KILLED
ROT13:      tr 'a-z' 'n-za-m' <<< '...' | sh           → shape      → ⛔ blocked + SESSION KILLED
Python:     python3 -c "...b64decode..." / "...chr(..." → detected   → ⛔ blocked + SESSION KILLED
```

### 3. Filesystem Fencing (Hardcore)

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

### 5. Snapshots — Cursor-Style Checkpoints

Every file write/edit is backed up before the change. Undo one edit, N edits, or an entire session.

```bash
railyard rollback --steps 1 --session abc123     # Undo last edit
railyard rollback --session abc123               # Undo entire session
railyard context --session abc123 --verbose      # Rich context for Claude to reason about
```

### 6. Self-Protection — The Agent Can't Turn It Off

Three layers prevent the agent from disabling Railyard:

1. **Hook Blocklist** — `railyard uninstall` is intercepted and blocked
2. **Terminal Check** — Uninstall checks if stdin is an interactive terminal. Agents pipe stdin → rejected.
3. **Native OS Dialog** — A native confirmation dialog appears (AppleScript/zenity/kdialog). Agents can't click GUI buttons.

---

## CLI Reference

```
railyard install [--mode chill|hardcore]   Register hooks with Claude Code
railyard uninstall                         Remove hooks (requires OS confirmation)
railyard init [--mode chill|hardcore]      Generate starter railyard.yaml
railyard configure                         Interactive protection setup
railyard status                            Show current protection status
railyard chat                              Policy builder via Claude Code

railyard log                               List sessions with traces
railyard log --session <id>                View traces for a session

railyard rollback --session <id>                     List snapshots
railyard rollback --session <id> --steps 3           Undo last 3 edits
railyard rollback --session <id> --id <snap>         Restore specific snapshot
railyard rollback --session <id> --file path         Restore specific file

railyard context --session <id> [--verbose]   Session context for Claude Code
railyard diff --session <id> [--file path]    Show diffs from snapshots

railyard sandbox generate                  Generate OS sandbox profile
railyard sandbox run -- <command>          Run command in OS sandbox
railyard sandbox status                    Show sandbox availability
```

---

## Security

Railyard ships with a comprehensive security analysis:

- **[SECURITY.md](SECURITY.md)** — Formal threat model (STRIDE), security architecture, provable guarantees, attack surface analysis, compliance mapping (SOC 2, NIST CSF, OWASP LLM Top 10)
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Technical deep dive into every module, data flow, and integration points
- **[PENTEST-REPORT.md](PENTEST-REPORT.md)** — 3 rounds of adversarial red teaming. 28 attack vectors. 71% block rate. Complete bypass taxonomy.

### Pentest Results (3 Rounds)

| Metric | Round 1 | Round 2 | Round 3 |
|--------|---------|---------|---------|
| Vectors tested | 13 | 28 | 28 |
| Blocked | 2 | 14 | 20 |
| Block rate | 15% | 50% | **71%** |
| Bypass categories | 3 | 3 | **1** |

The only remaining bypasses are shell-level runtime string construction (4 vectors) — which require OS-level sandboxing to defeat.

---

## Testing

```bash
# All tests: 73 unit + 36 attack simulation + 15 rollback + 12 threat detection = 136
cargo test

# Attack simulations only
cargo test --test attack_simulation

# Rollback scenarios
cargo test --test rollback_scenarios
```

Test coverage includes:
- **Real incident reproductions** — terraform destroy, drizzle-kit force push, rm -rf ~/, DROP DATABASE
- **Evasion attempts** — base64, double base64, variable expansion, shell wrappers, eval concat, backtick substitution, rev|sh, ROT13, Python chr(), Ruby system()
- **Threat detection** — Tier 1/2/3 classification, behavioral evasion, keyword extraction
- **Sandbox** — Profile generation for macOS and Linux
- **Self-protection** — Uninstall blocking, settings protection, binary removal prevention
- **Rollback** — Multi-edit undo, session rollback, digital twin scenarios, context generation

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
- LLM-as-judge for non-deterministic evasion detection
- Post-execution binary audit via dtrace/fanotify
- Policy inheritance (org-wide defaults + project overrides)

```bash
git clone https://github.com/railyarddev/railyard.git
cd railyard
cargo test
```

---

## License

MIT License. Copyright 2026 Ari Choudhury.
