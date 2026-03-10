# Railyard Architecture

Technical reference for engineers and security researchers who want to understand how Railyard works internally. Railyard is a Rust binary that interposes on every Claude Code tool call via the hook system, enforcing policy, detecting evasion, snapshotting files, and logging decisions.

---

## 1. System Overview

### Integration with Claude Code

Railyard registers itself as a hook handler in `~/.claude/settings.json` for three hook events:

- **PreToolUse** -- Fires before every tool call (Bash, Write, Edit, Read, etc.). This is the critical enforcement path. Railyard can allow, deny, or escalate to human approval.
- **PostToolUse** -- Fires after every tool call completes. Used for audit logging.
- **SessionStart** -- Fires when a Claude Code session begins. Used to initialize logging and warn about previously terminated sessions.

### Protocol

Each hook invocation is a **separate OS process**. Claude Code spawns `railyard hook --event <EventName>` and communicates via JSON on stdin/stdout:

1. Claude Code writes a `HookInput` JSON object to Railyard's stdin, containing `session_id`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`, and optionally `tool_response`.
2. Railyard reads stdin to EOF, processes the request, and writes a `HookOutput` JSON object to stdout.
3. Claude Code reads the output and acts on the `permissionDecision` field:
   - **No output / empty `hookSpecificOutput`** -- Tool call proceeds (allow).
   - `"deny"` -- Tool call is blocked. The `permissionDecisionReason` is shown to the agent.
   - `"ask"` -- The human is prompted for approval. `additionalContext` is shown in the prompt.

All hook commands have a 5-second timeout configured in the settings registration.

### Process Isolation

Because each hook invocation is a separate process, Railyard persists session state to disk at `.railyard/state/{session_id}.json`. State is loaded at the beginning of each PreToolUse handler and saved before the response is written. The save uses atomic write-then-rename to prevent corruption from concurrent invocations.

---

## 2. Module Architecture

### `hook/` -- Hook Dispatch

**Files:** `handler.rs`, `pre_tool.rs`, `post_tool.rs`, `session.rs`

`handler::run()` is the main entry point for `railyard hook --event <event>`. It reads JSON from stdin, parses it into a `HookInput`, loads the policy from `railyard.yaml` (walking up the directory tree), and dispatches to the appropriate handler.

- **`pre_tool.rs`** -- The critical path. Every tool call passes through `handle()`. Orchestrates threat detection, path fence checks, policy evaluation, snapshot capture, and trace logging. Returns a `PreToolResult` containing the `HookOutput` and an optional `TerminateRequest` (if evasion was detected). The caller in `handler.rs` flushes the JSON output to stdout *before* acting on any termination request.
- **`post_tool.rs`** -- Logs the completed tool call to the trace log. No enforcement decisions.
- **`session.rs`** -- On `SessionStart`, checks for recently terminated sessions and prints warnings to stderr. Cleans up state files older than 24 hours. Logs the session start event.

### `block/` -- Command Matching with Evasion Normalization

**Files:** `evasion.rs`, `matcher.rs`

#### Evasion Normalization (`evasion.rs`)

`normalize_command(cmd)` takes a raw command string and returns a `Vec<String>` of all decoded variants to match against. This defeats obfuscation by producing the plaintext form of encoded commands. The normalization is recursive -- decoded output is fed back through `normalize_command()` to catch multi-layer encoding.

Normalization techniques:

| Technique | Example | Detection |
|---|---|---|
| **Base64 pipe** | `echo dGVy... \| base64 -d \| sh` | Regex extracts payload, decodes via `base64::Engine` |
| **Eval concat** | `eval "ter""raform destroy"` | Strips quotes and concatenates |
| **Variable expansion** | `CMD="terraform destroy"; $CMD` | Parses `VAR=value; $VAR` assignments |
| **Shell wrapper** | `sh -c "terraform destroy"` | Extracts inner command from `sh/bash/zsh -c "..."` |
| **Xargs indirection** | `echo "rm -rf /" \| xargs sh -c` | Extracts piped argument |
| **Hex escapes** | `$'\x72\x6d' -rf /` | Decodes `\xNN` sequences |
| **Backtick substitution** | `` `echo terraform` destroy `` | Expands `` `echo X` `` to `X` |
| **Recursive base64** | Double/triple base64 encoding | Counts `base64 -d` stages, decodes iteratively |
| **Transform-pipe-to-shell** | `rev <<< 'yortsed' \| sh` | Detected by `is_transform_pipe_to_shell()` |
| **Interpreter obfuscation** | `python3 -c "...b64decode..."` | Detected by `is_interpreter_obfuscation()` -- flags interpreter + obfuscation function combos |

Additionally, `extract_paths_from_command()` parses variable assignments and `$HOME` expansion within commands to extract all file paths, enabling the fence to catch indirect path references like `d="$HOME/.ssh"; cat "$d/id_ed25519"`.

A benign-path whitelist (`is_benign_path()`) prevents false positives on system binary paths (`/usr/bin/*`, `/dev/null`, `/tmp/*`, etc.).

#### Matcher (`matcher.rs`)

`match_rules(command, rules)` normalizes the command via `evasion::normalize_command()`, then tests each variant against each rule's regex pattern. First match wins, returning `Decision::Block`, `Decision::Approve`, or `Decision::Allow`.

`evaluate_tool(tool_name, tool_input, rules)` handles non-Bash tools. For Write/Edit/Read, it matches the `file_path` field against rule patterns. For any tool, it falls back to matching the serialized JSON input. Rules are filtered by `tool` field (`"Bash"`, `"Write"`, `"*"`, etc.).

### `policy/` -- Three-Tier Policy Evaluation

**Files:** `engine.rs`, `loader.rs`, `defaults.rs`

#### Evaluation Order (`engine.rs`)

`evaluate(policy, tool_name, tool_input)` checks rules in this order:

1. **Allowlist** -- If the tool input matches any allowlist rule, the call is immediately allowed (skipping blocklist and approve checks). This lets users whitelist specific safe commands.
2. **Blocklist** -- If the tool input matches a blocklist rule, the call is denied.
3. **Approve** -- If the tool input matches an approve rule, the call is escalated to the human for approval.
4. **Default** -- If no rule matches, the call is allowed.

#### Policy Loading (`loader.rs`)

`find_policy_file(start_dir)` walks up the directory tree from the current working directory looking for `railyard.yaml`, `railyard.yml`, or `.railyard.yaml`.

`load_policy_or_defaults(cwd)` loads and parses the YAML file, validates all regex patterns at load time, then merges with built-in defaults via `merge_with_defaults()`. Built-in blocklist rules are **prepended** to user rules. Users can override a built-in rule by defining one with the same `name` in their config. In chill mode, the fence is disabled by default unless the user explicitly configures paths.

#### Default Rules (`defaults.rs`)

Rules are organized into two tiers:

**Core rules (active in both modes) -- 16 rules:**
- Destructive commands: `terraform destroy`, `rm -rf /`, `DROP TABLE`, `git push --force`, `git reset --hard`, `git clean -f`, `drizzle-kit push --force`, `mkfs`/`dd`, `kubectl delete namespace`, `aws s3 rm --recursive`, `docker system prune -a`, `chmod -R 777 /`
- Approval-gated: `npm publish`
- Self-protection: `railyard uninstall`, `.claude/settings.json` tampering, railyard binary removal

**Hardcore-only rules (13 additional, 29 total):**
- Network: `curl | sh`, netcat, `curl POST` (approve), `wget` (approve), `ssh`/`scp` (approve)
- Credentials: `env`/`printenv` dump (approve), `git config --global` writes
- Dynamic construction: `base64 -d | sh`, `eval $VAR` (approve), `printf \x` hex exec
- Symlinks: `ln -s` to absolute paths (approve)
- P0 evasion: transform-pipe-to-shell (`rev | sh`, `tr | sh`, `sed | sh`), interpreter obfuscation (`python3 -c "...base64..."`)

### `fence/` -- Path Restriction

**Files:** `path.rs`

`check_path(config, file_path, cwd)` enforces filesystem boundaries:

1. `/dev/*` paths are always allowed (virtual devices).
2. All paths are **canonicalized** before comparison using `canonicalize_best_effort()`. This resolves:
   - Symlinks (via `std::fs::canonicalize`)
   - Relative traversal (`../`)
   - Home directory expansion (`~`, `$HOME`)
   - For non-existent paths (pre-creation), it canonicalizes the deepest existing ancestor and appends the remaining components.
3. Denied paths are checked first. Default denied: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.claude`, `/etc`.
4. If `allowed_paths` is non-empty, the path must be within one of them (explicit whitelist mode).
5. Otherwise, the path must be within the project directory (`cwd`).

For Bash tool calls, paths are extracted from the command by `evasion::extract_paths_from_command()` which handles variable indirection. For Write/Edit/Read tools, the `file_path` field is checked directly via `extract_file_path()`.

### `threat/` -- Tiered Threat Detection

**Files:** `classifier.rs`, `state.rs`, `killer.rs`

Threat detection runs **before** policy evaluation in the PreToolUse handler and only activates in `hardcore` mode for Bash commands.

#### Classifier (`classifier.rs`)

`classify_threat(cmd)` returns an `Option<ThreatTier>`:

- **Tier 1 -- Immediate Kill.** Unambiguous evasion patterns with no legitimate use:
  - Transform piped to shell (`rev | sh`, `tr | sh`, `sed | sh`, `awk | sh`)
  - Interpreter with obfuscation (`python3 -c "...b64decode..."`, `ruby -e 'system(...chr(...))'`)
  - Recursive base64 (double/triple encoding piped to shell)
  - `printf` hex in command substitution (`$(printf '\x72\x6d')`)
  - `printf` piped to shell

- **Tier 2 -- Escalating.** Suspicious patterns that might have legitimate use. First occurrence generates a warning; second occurrence terminates:
  - Variable-then-execution (`CMD="..."; $CMD`)
  - `eval` with variable expansion (`eval $SOMETHING`)
  - Multiple short variable assignments with concatenation (`a="x"; b="y"; "$a$b"`)

- **Tier 3 -- Behavioral Retry.** `check_behavioral_evasion(state, cmd)` detects when the agent retries a blocked command using different syntax. After any block, the session enters a "heightened state" for 3 tool calls. During this window, if a new command shares 2+ keywords with the blocked command, it is classified as Tier 3 and the session is terminated.

Keywords are extracted by `extract_keywords()`, which filters out common shell noise tokens (`|`, `&&`, `sh`, `echo`, `if`, etc.) and short words.

#### Session State (`state.rs`)

`SessionState` is a JSON-serialized struct persisted at `.railyard/state/{session_id}.json`. Fields:

- `tool_call_count` -- Monotonically incrementing counter.
- `suspicion_level` -- 0 (normal), 1 (warned), 2 (heightened).
- `warning_count` -- Number of Tier 2 warnings issued.
- `block_history` -- Vec of `BlockEvent` (timestamp, command, rule, keywords, tier).
- `heightened_until_call` -- Tool call count at which heightened mode expires (current + 3).
- `heightened_keywords` -- Keywords to watch for during heightened state.
- `terminated` -- Boolean flag. Once set, all subsequent tool calls in this session are denied.
- `termination_reason`, `termination_timestamp` -- Forensic metadata.

State is loaded at the start of each PreToolUse invocation and saved before returning. Writes use atomic rename (`write .tmp` then `rename`). Old state files (>24 hours) are cleaned up on `SessionStart`.

#### Killer (`killer.rs`)

`terminate_session(state, tier, command, state_dir, trace_dir)`:

1. Marks the session state as terminated with a reason string.
2. Writes a `SessionTerminated` forensic breadcrumb to the trace log.
3. Prints a colored warning to stderr (visible in the user's terminal).
4. Sends `SIGTERM` to the parent process (Claude Code) via `libc::kill(getppid(), SIGTERM)`. Only fires if `ppid > 1` to avoid killing init. Skipped when `RAILYARD_NO_KILL=1` is set (for testing). On non-Unix platforms, logs a warning instead.

The caller in `handler.rs` **must flush the deny JSON to stdout before calling `terminate_session`**, ensuring Claude Code receives the denial message before the process is killed.

### `sandbox/` -- OS-Level Sandbox Profile Generation

**Files:** `detect.rs`, `macos.rs`, `linux.rs`, `profile.rs`

Generates kernel-enforced sandbox profiles from the `fence` config in `railyard.yaml`.

#### Platform Detection (`detect.rs`)

`detect_sandbox()` returns a `SandboxCapability` enum:

- **`MacOsSandboxExec`** -- Detected by running `sandbox-exec -n no-network true`. Available on all macOS versions.
- **`LinuxLandlock { abi_version }`** -- Detected by reading `/proc/sys/kernel/osrelease` and checking for kernel >= 5.13.
- **`None`** -- Falls back to string-based fence only.

#### macOS Sandbox (`macos.rs`)

`generate_profile(config, cwd)` produces an Apple Sandbox Profile Language (SBPL/Scheme) file:

- `(deny default)` -- Default-deny posture.
- Allows process execution, fork, signals, mach IPC.
- Read-only access to `/usr`, `/bin`, `/sbin`, `/opt/homebrew`, `/Library/Frameworks`, `/System`.
- Full read/write to the project directory (`cwd`), `/tmp`, `/dev`, and `~/Library/Caches`.
- Read-only access to `~/.cargo`, `~/.rustup`, `~/.nvm` (toolchains).
- Explicit deny on `~/.ssh`, `~/.aws`, `~/.gnupg` (always, even if not in config).
- Network: deny by default, allow outbound TCP 443/80, allow localhost inbound/bind.

Usage: `sandbox-exec -f .railyard/sandbox.sb -- sh -c "command"`

#### Linux Sandbox (`linux.rs`)

Two output formats:

1. **Bubblewrap script** (`generate_bwrap_command`) -- Generates a `bwrap` command line with `--ro-bind` for system paths, `--bind` for the project directory, `--tmpfs` to shadow denied paths (mounts empty tmpfs over `~/.ssh`, etc.), and `--unshare-net` to disable networking.

2. **Landlock Rust snippet** (`generate_landlock_snippet`) -- Generates reference Rust code using the `landlock` crate, Landlock ABI v3. Default-deny with explicit `PathBeneath` rules for allowed directories. Denied paths are simply omitted from the ruleset.

#### Profile Orchestration (`profile.rs`)

`generate_profiles(policy, cwd)` detects the platform and writes the appropriate profile to `.railyard/`.

`run_sandboxed(policy, cwd, command)` executes a command inside the sandbox. On macOS, generates a profile to `.railyard/sandbox.sb` and runs `sandbox-exec -f ... -- sh -c "command"`. On Linux, tries `bwrap` first.

### `snapshot/` -- SHA-256 File Snapshots

**Files:** `capture.rs`, `rollback.rs`

#### Capture (`capture.rs`)

`capture_snapshot(snapshot_dir, session_id, tool_use_id, file_path)` runs in the PreToolUse handler before Write/Edit operations:

1. Creates `{snapshot_dir}/{session_id}/` if needed.
2. If the file exists: reads content, computes SHA-256 hash, writes content to `{hash_prefix}.snapshot` (deduplicated by hash).
3. If the file does not exist (new file creation): records hash as `__new_file_____0`.
4. Appends a `SnapshotEntry` (JSON) to `{session_id}/manifest.jsonl`. Each entry has a UUID-based `id` (first 8 chars), timestamp, file path, hash prefix (first 16 hex chars), and `existed` flag.

#### Rollback (`rollback.rs`)

Four rollback strategies, all reading from the JSONL manifest:

- **By ID** (`rollback_by_id`) -- Restores a specific snapshot entry.
- **By file** (`rollback_file`) -- Finds the most recent snapshot of a given file path and restores it.
- **By session** (`rollback_session`) -- Restores all files to their state at session start (uses the *first* snapshot of each unique file path).
- **By steps** (`rollback_steps`) -- Undoes the last N edits by restoring each to its pre-edit state.

For files that did not exist before (`existed: false`), rollback deletes the file. For existing files, it reads the `.snapshot` content and writes it back.

### `trace/` -- JSONL Structured Audit Logging

**Files:** `logger.rs`

`log_trace(trace_dir, session_id, entry)` appends a `TraceEntry` JSON line to `{trace_dir}/{session_id}.jsonl`. Each entry contains: timestamp (RFC 3339), session ID, event name, tool name, input summary (first 200 chars of command or file path), decision, matched rule name, and evaluation duration in milliseconds.

`read_traces()` and `list_sessions()` provide read access for the `railyard log` command. `format_trace_entry()` produces human-readable output with decision labels (`BLOCKED`, `APPROVE`, `OK`).

### `context/` -- Rich Session Context for LLM Consumption

**File:** `context.rs`

`generate_context(trace_dir, snapshot_dir, session_id, verbose)` produces a Markdown document designed to be read by Claude Code during rollback operations. Includes:

- Summary statistics (tool calls, blocks, approvals, files modified, snapshots available).
- Per-file change summary with edit history and size deltas.
- Optionally, unified diffs between original snapshots and current file content (in verbose mode), using a simple LCS-based diff algorithm capped at 100 lines.
- List of blocked commands with rule names.
- Recent timeline (last 20 trace entries).
- Copy-pasteable rollback commands for every available snapshot.

`show_diff()` produces diffs between snapshots and current file state, grouped by file.

### `install/` -- Hook Registration

**Files:** `hooks.rs`

`install_hooks()`:
1. Reads or creates `~/.claude/settings.json`.
2. Inserts hook entries for PreToolUse, PostToolUse, and SessionStart. Each entry uses `matcher: ""` (matches all tools) and points to `{railyard_binary_path} hook --event {EventName}` with a 5-second timeout.
3. Injects Railyard instructions into `~/.claude/CLAUDE.md` using marker comments (`<!-- railyard:start -->` / `<!-- railyard:end -->`). This teaches the LLM about rollback commands and blocked operations. If the marker section already exists, it is replaced in-place.

`uninstall_hooks()` has layered anti-tampering protection:
1. **TTY check** -- `stdin.is_terminal() && stdout.is_terminal()` must be true. Agents pipe stdin, so this rejects automated uninstall attempts.
2. **Native OS dialog** -- macOS uses `osascript` (AppleScript dialog), Linux tries `zenity` then `kdialog`, Windows uses PowerShell `MessageBox`. An AI agent cannot click a GUI button.
3. **Terminal fallback** -- If no GUI is available, requires typing "remove" at a prompt.
4. **Self-protection rules** -- The blocklist blocks `railyard uninstall`, `.claude/settings.json` modification, and railyard binary removal, so the agent cannot even reach the uninstall code path.

### `configure/` -- Interactive Terminal UI

**File:** `configure.rs`

`run_configure()` provides a `dialoguer`-based terminal UI for generating `railyard.yaml`:

1. Mode selection (hardcore / chill) via `Select`.
2. Per-category rule toggles via `MultiSelect`. Categories: Destructive Commands, Self-Protection, Network Policy, Credential Protection, Evasion Detection.
3. Fence, trace, and snapshot toggles via `Confirm`.
4. Generates and writes `railyard.yaml` with the selected configuration.

---

## 3. Data Flow

Step-by-step walkthrough of what happens when Claude Code invokes the Bash tool with a command:

```
Claude Code                           Railyard Process
    |                                      |
    |  spawn: railyard hook --event PreToolUse
    |  write HookInput JSON to stdin       |
    |  --------------------------------->  |
    |                                      |
    |                              1. handler::run("PreToolUse")
    |                              2. Read stdin to EOF, parse HookInput
    |                              3. Load policy: find_policy_file(cwd),
    |                                 parse YAML, merge_with_defaults()
    |                              4. Load SessionState from
    |                                 .railyard/state/{session_id}.json
    |                              5. Increment tool_call_count
    |                              6. Check if session was previously
    |                                 terminated -> deny all if so
    |                                      |
    |                              7. THREAT DETECTION (hardcore mode only):
    |                                 a. Tier 3: check_behavioral_evasion()
    |                                    - Is session in heightened state?
    |                                    - Does command share 2+ keywords
    |                                      with recently blocked command?
    |                                    -> If yes: deny + terminate
    |                                 b. Tier 1: classify_threat()
    |                                    - transform | sh? interpreter
    |                                      obfuscation? recursive base64?
    |                                    -> If yes: deny + terminate
    |                                 c. Tier 2: classify_threat()
    |                                    - variable-then-exec? eval $var?
    |                                    -> First time: warn, continue
    |                                    -> Second time: deny + terminate
    |                                      |
    |                              8. PATH FENCE CHECK:
    |                                 a. extract_paths_from_command()
    |                                    (handles variable indirection)
    |                                 b. For each path: check_path()
    |                                    - Expand ~ and $HOME
    |                                    - Canonicalize (resolve symlinks)
    |                                    - Check against denied_paths
    |                                    - Check against allowed_paths
    |                                    - Check within project directory
    |                                 -> If denied: deny + save state
    |                                      |
    |                              9. POLICY EVALUATION:
    |                                 a. evaluate(policy, "Bash", tool_input)
    |                                    i.  Allowlist check -> allow
    |                                    ii. Blocklist check -> deny
    |                                    iii.Approve check   -> ask
    |                                    iv. Default         -> allow
    |                                 b. For Bash: normalize_command()
    |                                    produces decoded variants,
    |                                    each tested against rule regex
    |                                      |
    |                             10. ON ALLOW:
    |                                 a. If tool is Write/Edit and
    |                                    snapshot.enabled:
    |                                    capture_snapshot() ->
    |                                    read file, SHA-256, write
    |                                    .snapshot, append manifest.jsonl
    |                                 b. Log trace entry (JSONL)
    |                                 c. Save SessionState to disk
    |                                 d. Write HookOutput (empty) to stdout
    |                                      |
    |                             11. ON BLOCK:
    |                                 a. Record block in SessionState
    |                                    (for Tier 3 behavioral tracking)
    |                                 b. Save SessionState to disk
    |                                 c. Log trace entry
    |                                 d. Write HookOutput with
    |                                    permissionDecision: "deny"
    |                                      |
    |                             12. ON APPROVE:
    |                                 a. Save SessionState to disk
    |                                 b. Log trace entry
    |                                 c. Write HookOutput with
    |                                    permissionDecision: "ask"
    |                                      |
    |                             13. ON TERMINATE:
    |                                 a. Flush deny JSON to stdout
    |                                 b. Mark SessionState terminated
    |                                 c. Write forensic breadcrumb to trace
    |                                 d. Print warning to stderr
    |                                 e. SIGTERM parent process (Claude Code)
    |                                 f. exit(0)
    |                                      |
    |  <---------------------------------  |
    |  read stdout JSON                    |
    |  act on permissionDecision           |
    |                                      |
```

---

## 4. Configuration

### `railyard.yaml` Schema

```yaml
version: 1                    # Schema version (currently 1)
mode: hardcore                 # "hardcore" or "chill"

blocklist:                     # Rules that deny tool calls
  - name: rule-name            # Unique identifier
    tool: Bash                 # Tool to match: Bash, Write, Edit, Read, or *
    pattern: "regex"           # Rust regex pattern
    action: block              # "block" (deny) or "approve" (escalate)
    message: "Human-readable"  # Shown to the agent on denial

approve:                       # Rules that escalate to human approval
  - name: rule-name
    tool: Bash
    pattern: "regex"
    action: approve
    message: "Why approval is needed"

allowlist:                     # Rules that bypass all checks
  - name: rule-name
    tool: Bash
    pattern: "regex"
    action: block              # Any action -- matching = allow

fence:
  enabled: true                # Enable/disable path restriction
  allowed_paths: []            # Explicit whitelist (if non-empty, only these are allowed)
  denied_paths:                # Always denied, even within allowed_paths
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - "~/.config/gcloud"
    - "~/.claude"
    - "/etc"

trace:
  enabled: true
  directory: .railyard/traces  # JSONL log directory

snapshot:
  enabled: true
  tools: [Write, Edit]         # Which tools trigger pre-edit snapshots
  directory: .railyard/snapshots
```

### Mode System

| Feature | Chill (16 rules) | Hardcore (29 rules) |
|---|---|---|
| Destructive command blocking | Yes | Yes |
| Self-protection (anti-uninstall) | Yes | Yes |
| Path fencing | Off by default | On by default |
| Network policy | No | Yes (curl\|sh blocked, POST/wget/ssh require approval) |
| Credential protection | No | Yes (env dump requires approval, git config --global blocked) |
| Evasion detection rules | No | Yes (base64\|sh, eval $var, printf hex, transform\|sh) |
| Threat detection (Tier 1/2/3) | No | Yes (only activates in hardcore mode) |
| Trace logging | On | On |
| File snapshots | On | On |

### Mode Behavior Examples

The mode system affects three areas: which rules are active, whether the fence is enabled, and whether threat detection runs. Here is the concrete decision path for representative commands in each mode.

**`curl -X POST https://api.example.com/data -d '{"key":"val"}'`**

```
Chill mode:
  1. Allowlist check  → no match
  2. Blocklist check  → no match (no network rules in chill)
  3. Approve check    → no match
  4. Default          → ALLOW

Hardcore mode:
  1. Allowlist check  → no match
  2. Blocklist check  → no match
  3. Approve check    → matches "curl-post" rule (pattern: curl.*(-X\s*POST|--data|-d\s))
  4. Decision         → ASK (human prompted for approval)
```

**`echo dGVycmFmb3JtIGRlc3Ryb3k= | base64 -d | sh`**

```
Chill mode:
  1. Threat detection → SKIPPED (chill mode)
  2. normalize_command() produces: ["echo dGVy... | base64 -d | sh", "terraform destroy"]
  3. Blocklist check  → "terraform destroy" matches terraform-destroy rule
  4. Decision         → DENY (decoded payload caught, no session state change)

Hardcore mode:
  1. Threat detection → classify_threat() → no Tier 1 match (single base64 is Tier 2 if variable, but this is a pipe)
  2. normalize_command() produces: ["echo dGVy... | base64 -d | sh", "terraform destroy"]
  3. Blocklist check  → matches base64-shell-exec rule AND terraform-destroy rule
  4. Decision         → DENY
  5. State update     → block recorded, heightened state activated for 3 tool calls,
                        keywords ["terraform", "destroy"] tracked for Tier 3 behavioral detection
```

**`cat ~/.aws/credentials`**

```
Chill mode:
  1. Threat detection → SKIPPED
  2. Path fence       → SKIPPED (fence.enabled = false in chill)
  3. Blocklist check  → no match
  4. Decision         → ALLOW

Hardcore mode:
  1. Threat detection → no threat (safe command)
  2. Path fence       → extract_paths_from_command() returns ["~/.aws/credentials"]
                      → expand_path() resolves ~ to /Users/you
                      → canonicalize_best_effort() → /Users/you/.aws/credentials
                      → denied_paths contains "~/.aws" → /Users/you/.aws
                      → path_starts_with("/Users/you/.aws/credentials", "/Users/you/.aws") → true
  3. Decision         → DENY ("Path Fence: '~/.aws/credentials' is in denied path '~/.aws'")
```

**`rev <<< 'yortsed mrofarret' | sh`**

```
Chill mode:
  1. Threat detection → SKIPPED
  2. Normalize        → rev|sh is not decoded by normalization (it's not base64/hex/variable)
  3. Blocklist check  → no rule matches the literal string
  4. Decision         → ALLOW (this is a gap in chill mode)

Hardcore mode:
  1. Threat detection → classify_threat()
     → is_transform_pipe_to_shell() checks: rev ... | sh → MATCH
     → returns Tier 1 { pattern: "transform-pipe-to-shell" }
  2. Decision         → DENY + TERMINATE
  3. PreToolResult    → { output: deny, terminate: Some(Tier1) }
  4. handler::run()   → flush deny JSON to stdout
                      → terminate_session(): mark state, write trace, SIGTERM parent
```

### Policy Resolution

1. Walk up the directory tree from `cwd` looking for `railyard.yaml` / `railyard.yml` / `.railyard.yaml`.
2. Parse and validate all regex patterns at load time (invalid regex = load error, falls back to defaults).
3. Merge with built-in defaults: default rules are prepended to user rules. A user rule with the same `name` as a built-in rule overrides it.
4. In chill mode, fence is disabled unless the user explicitly configures paths.

---

## 5. File Layout

```
src/
  main.rs                      CLI entry point (clap). Subcommands: install, uninstall,
                                init, hook, log, rollback, context, diff, status,
                                configure, chat, sandbox.
  lib.rs                        Module declarations.
  types.rs                      Shared types: HookInput, HookOutput, Policy, Rule,
                                FenceConfig, TraceConfig, SnapshotConfig, TraceEntry,
                                SnapshotEntry, Decision enum.

  hook/
    mod.rs                      Module declarations.
    handler.rs                  Main hook entry point. Reads stdin, dispatches by event.
    pre_tool.rs                 PreToolUse handler. Orchestrates threat detection,
                                fence, policy, snapshot, trace. Returns PreToolResult.
    post_tool.rs                PostToolUse handler. Logs completed tool calls.
    session.rs                  SessionStart handler. Warns about terminated sessions,
                                cleans up old state.

  block/
    mod.rs                      Module declarations.
    evasion.rs                  Command normalization: base64, variable expansion,
                                hex escapes, eval concat, shell wrappers, xargs,
                                backtick substitution, recursive base64, transform
                                pipe detection, interpreter obfuscation detection,
                                path extraction from commands.
    matcher.rs                  Rule matching engine. Normalizes then regex-tests all
                                variants. Handles Bash commands and file-path tools.

  policy/
    mod.rs                      Module declarations.
    engine.rs                   Three-tier evaluation: allowlist -> blocklist -> approve
                                -> default allow.
    loader.rs                   YAML loading, directory-tree walk, merge with defaults,
                                regex validation.
    defaults.rs                 Built-in rule definitions. core_blocklist() (16 rules),
                                hardcore_rules() (13 additional). Mode-based selection.

  fence/
    mod.rs                      Module declarations.
    path.rs                     Path canonicalization, symlink resolution, home expansion,
                                denied/allowed path checking, dev-path whitelist,
                                file-path extraction from tool inputs.

  threat/
    mod.rs                      Module declarations.
    classifier.rs               Threat tier classification. Tier 1 (immediate kill),
                                Tier 2 (escalating), Tier 3 (behavioral retry).
                                Keyword extraction for behavioral tracking.
    state.rs                    SessionState struct. Persisted JSON at
                                .railyard/state/{session_id}.json. Atomic save,
                                heightened-state tracking, block history, cleanup.
    killer.rs                   Session termination. Marks state, writes forensic
                                breadcrumb, SIGTERM to parent via libc::kill(getppid()).

  sandbox/
    mod.rs                      Module declarations.
    detect.rs                   Platform detection: macOS sandbox-exec, Linux Landlock.
    macos.rs                    SBPL profile generation for sandbox-exec.
    linux.rs                    Bubblewrap command generation and Landlock Rust snippet.
    profile.rs                  Orchestration: generate profiles, run sandboxed commands.

  snapshot/
    mod.rs                      Module declarations.
    capture.rs                  SHA-256 snapshot capture. Deduped by hash. JSONL manifest.
    rollback.rs                 Restore by ID, file, session, or step count.

  trace/
    logger.rs                   JSONL append-only logging. Read, list, format functions.

  context.rs                    Rich Markdown context generation for LLM consumption.
                                Diffs, timelines, rollback command suggestions.
  configure.rs                  Interactive terminal UI (dialoguer). Mode selection,
                                per-category rule toggles, YAML generation.
  install/
    mod.rs                      Module declarations.
    hooks.rs                    Hook registration in ~/.claude/settings.json.
                                CLAUDE.md injection with marker comments.
                                Anti-tampering uninstall (TTY + native OS dialog).

defaults/
  railyard.yaml                 Starter policy template (embedded via include_str!).
  CLAUDE.md                     LLM instructions (embedded into ~/.claude/CLAUDE.md).

tests/
  attack_simulation.rs          End-to-end evasion attack tests.
  rollback_scenarios.rs         Snapshot/rollback integration tests.
  simulation/
    mod.rs                      Test simulation helpers.

.railyard/                      Runtime data directory (created per-project):
  state/                        Session state JSON files.
    {session_id}.json
  traces/                       JSONL audit logs.
    {session_id}.jsonl
  snapshots/                    File snapshots.
    {session_id}/
      manifest.jsonl            Snapshot manifest (append-only).
      {hash}.snapshot           File content snapshots (deduplicated).
  sandbox.sb                    Generated macOS sandbox profile.
  sandbox-bwrap.sh              Generated Linux bubblewrap wrapper.
  sandbox-landlock.rs           Generated Landlock reference code.
```
