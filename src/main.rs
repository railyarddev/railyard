use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::Path;

use railguard::{configure, coord, context, dashboard, hook, install, memory, policy, replay, snapshot, trace, update};

#[derive(Parser)]
#[command(name = "railguard", version, about = "A secure runtime for Claude Code.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install railguard hooks into Claude Code
    Install,

    /// Remove railguard hooks from Claude Code
    Uninstall,

    /// Generate a starter railguard.yaml in the current directory
    Init,

    /// Internal: handle a hook event (reads JSON from stdin)
    Hook {
        #[arg(long)]
        event: String,
    },

    /// Show recent trace logs
    Log {
        /// Show traces for a specific session
        #[arg(long)]
        session: Option<String>,
        /// Number of recent entries to show
        #[arg(short, long, default_value = "20")]
        count: usize,
    },

    /// Rollback file changes from snapshots
    Rollback {
        /// Snapshot ID to rollback
        #[arg(long)]
        id: Option<String>,
        /// Session ID
        #[arg(long)]
        session: Option<String>,
        /// File path to rollback
        #[arg(long)]
        file: Option<String>,
        /// Number of steps to undo
        #[arg(long)]
        steps: Option<usize>,
    },

    /// Show session context for rollback (designed for Claude Code to read)
    Context {
        /// Session ID
        #[arg(long)]
        session: String,
        /// Show full diffs (verbose)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show diff between snapshots and current files
    Diff {
        /// Session ID
        #[arg(long)]
        session: String,
        /// Specific file to diff (optional)
        #[arg(long)]
        file: Option<String>,
    },

    /// Show railguard status
    Status,

    /// Interactive protection configuration
    Configure,

    /// Interactive policy configuration (launches Claude Code)
    Chat,

    /// Live dashboard showing all tool calls and decisions
    Dashboard {
        /// Session ID to monitor (auto-detects latest if omitted)
        #[arg(long)]
        session: Option<String>,
        /// Use streaming output instead of TUI
        #[arg(long)]
        stream: bool,
        /// Show historical entries on startup (streaming mode only)
        #[arg(long)]
        history: bool,
    },

    /// Replay a session — browse tool calls, decisions, and details
    Replay {
        /// Session ID to replay
        #[arg(long)]
        session: String,
    },

    /// Show active file locks across all sessions
    Locks,

    /// Check for updates and install the latest version
    Update {
        /// Only check if an update is available (don't install)
        #[arg(long)]
        check: bool,
    },

    /// Memory safety commands — provenance, integrity, audit
    Memory {
        #[command(subcommand)]
        action: MemoryCommands,
    },

    /// Show plugin directory path (for use with claude --plugin-dir)
    Plugin,
}

#[derive(Subcommand)]
enum MemoryCommands {
    /// List all memory files with provenance info
    List,
    /// Verify integrity of all memory files
    Verify,
    /// Show memory write audit trail
    Log {
        /// Number of entries to show
        #[arg(short, long, default_value = "20")]
        count: usize,
    },
    /// Mark a tampered memory file as untrusted
    Quarantine {
        /// Path to the memory file
        file: String,
    },
    /// Re-sign a memory file (confirm content is trusted)
    Trust {
        /// Path to the memory file
        file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Some(Commands::Install) => cmd_install(),
        Some(Commands::Uninstall) => cmd_uninstall(),
        Some(Commands::Init) => cmd_init(),
        Some(Commands::Hook { event }) => hook::handler::run(&event),
        Some(Commands::Log { session, count }) => cmd_log(session, count),
        Some(Commands::Rollback { id, session, file, steps }) => cmd_rollback(id, session, file, steps),
        Some(Commands::Context { session, verbose }) => cmd_context(&session, verbose),
        Some(Commands::Diff { session, file }) => cmd_diff(&session, file),
        Some(Commands::Status) => cmd_status(),
        Some(Commands::Configure) => configure::run_configure(),
        Some(Commands::Chat) => cmd_chat(),
        Some(Commands::Dashboard { session, stream, history }) => {
            if stream {
                dashboard::run_stream(session, history)
            } else {
                dashboard::run(session)
            }
        }
        Some(Commands::Replay { session }) => replay::run(&session),
        Some(Commands::Locks) => cmd_locks(),
        Some(Commands::Update { check }) => update::run_update(check),
        Some(Commands::Memory { action }) => cmd_memory(action),
        Some(Commands::Plugin) => cmd_plugin(),
        None => {
            // No subcommand: show status
            cmd_status()
        }
    };

    std::process::exit(exit_code);
}

fn cmd_install() -> i32 {
    use dialoguer::{theme::ColorfulTheme, Confirm};

    println!("{}", "railguard".bold());
    println!();

    match install::hooks::install_hooks() {
        Ok(msg) => {
            let rule_count = policy::defaults::default_blocklist().len();

            println!("  {} Hooks registered with Claude Code", "✓".green().bold());
            println!("  {} {}", "✓".green().bold(), msg);
            println!("  {} {} default rules active", "✓".green().bold(), rule_count);

            // Prompt to enable bypass permissions (Railguard replaces it)
            println!();
            println!("  {} We recommend enabling skip permissions — Railguard replaces", "→".cyan().bold());
            println!("    Claude Code's permission system with its own guardrails,");
            println!("    so you won't need to approve every command manually.");
            println!();
            let enable_bypass = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("  Enable skip permissions?")
                .default(true)
                .interact()
                .unwrap_or(true);

            if enable_bypass {
                match install::hooks::enable_bypass_permissions() {
                    Ok(_) => {
                        println!("  {} Skip permissions enabled — Railguard handles safety now", "✓".green().bold());
                    }
                    Err(e) => {
                        eprintln!("  {} Failed to enable bypass mode: {}", "✗".yellow().bold(), e);
                    }
                }
            }

            println!();
            println!("  Customize with: {}", "railguard init".cyan());
            println!("  Or use as plugin: {}", "claude --plugin-dir $(railguard plugin)".cyan());
            0
        }
        Err(e) => {
            eprintln!("  {} {}", "✗".red().bold(), e);
            1
        }
    }
}

fn cmd_plugin() -> i32 {
    // Find the plugin directory: look for .claude-plugin/plugin.json relative to the binary
    let plugin_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| {
            // Walk up from the binary to find the repo root with .claude-plugin/
            let mut dir = exe.parent()?.to_path_buf();
            for _ in 0..5 {
                if dir.join(".claude-plugin").join("plugin.json").exists() {
                    return Some(dir);
                }
                dir = dir.parent()?.to_path_buf();
            }
            None
        });

    match plugin_dir {
        Some(dir) => {
            println!("{}", dir.display());
            eprintln!();
            eprintln!("  Usage: {}", format!("claude --plugin-dir {}", dir.display()).cyan());
            eprintln!();
            eprintln!("  This loads Railguard as a Claude Code plugin — no need to run {}.", "railguard install".cyan());
            0
        }
        None => {
            eprintln!("  {} Could not find plugin directory.", "✗".red().bold());
            eprintln!("  Expected .claude-plugin/plugin.json near the railguard binary.");
            eprintln!();
            eprintln!("  If you installed via cargo, the plugin files are in the source repo.");
            eprintln!("  Clone the repo and use: {}", "claude --plugin-dir /path/to/railguard".cyan());
            1
        }
    }
}

fn cmd_uninstall() -> i32 {
    match install::hooks::uninstall_hooks() {
        Ok(msg) => {
            println!("  {} {}", "✓".green().bold(), msg);
            0
        }
        Err(e) => {
            eprintln!("  {} {}", "✗".red().bold(), e);
            1
        }
    }
}

fn cmd_init() -> i32 {
    let policy_path = Path::new("railguard.yaml");
    if policy_path.exists() {
        eprintln!("  {} railguard.yaml already exists", "✗".red().bold());
        return 1;
    }

    let default_yaml = include_str!("../defaults/railguard.yaml");

    match std::fs::write(policy_path, default_yaml) {
        Ok(_) => {
            println!("  {} Created railguard.yaml", "✓".green().bold());
            println!();
            println!("  Edit this file to customize your policy.");
            println!("  Run {} to configure interactively.", "railguard chat".cyan());
            0
        }
        Err(e) => {
            eprintln!("  {} Failed to create railguard.yaml: {}", "✗".red().bold(), e);
            1
        }
    }
}

fn cmd_log(session: Option<String>, count: usize) -> i32 {
    let trace_dir = trace::logger::global_trace_dir();

    if let Some(session_id) = session {
        match trace::logger::read_traces(&trace_dir, &session_id) {
            Ok(entries) => {
                if entries.is_empty() {
                    println!("  No traces found for session {}", session_id);
                } else {
                    for entry in entries.iter().rev().take(count).rev() {
                        println!("{}", trace::logger::format_trace_entry(entry));
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                1
            }
        }
    } else {
        match trace::logger::list_sessions(&trace_dir) {
            Ok(sessions) => {
                if sessions.is_empty() {
                    println!("  No trace sessions found.");
                    println!("  Traces are created automatically when Claude Code runs with railguard.");
                } else {
                    println!("  {} Sessions with traces:\n", "●".cyan());
                    for s in &sessions {
                        println!("    {}", s);
                    }
                    println!();
                    println!("  View a session: {}", "railguard log --session <id>".cyan());
                }
                0
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                1
            }
        }
    }
}

fn cmd_rollback(
    id: Option<String>,
    session: Option<String>,
    file: Option<String>,
    steps: Option<usize>,
) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let policy = policy::loader::load_policy_or_defaults(&cwd);
    let snap_dir = cwd.join(&policy.snapshot.directory);

    if id.is_none() && file.is_none() && steps.is_none() {
        let session_id = session.unwrap_or_else(|| {
            trace::logger::list_sessions(&trace::logger::global_trace_dir())
                .unwrap_or_default()
                .last()
                .cloned()
                .unwrap_or_default()
        });

        if session_id.is_empty() {
            println!("  No snapshots found. Specify --session <id>.");
            return 1;
        }

        match snapshot::rollback::list_snapshots(&snap_dir, &session_id) {
            Ok(lines) => {
                if lines.is_empty() {
                    println!("  No snapshots for session {}", session_id);
                } else {
                    println!("  {} Snapshots for session {}:\n", "●".cyan(), session_id);
                    for line in &lines {
                        println!("{}", line);
                    }
                    println!();
                    println!("  Rollback: {}", "railguard rollback --id <id> --session <session>".cyan());
                    println!("  Undo last N: {}", "railguard rollback --steps 3 --session <session>".cyan());
                }
                0
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                1
            }
        }
    } else {
        let session_id = session.unwrap_or_default();
        if session_id.is_empty() {
            eprintln!("  {} --session is required for rollback", "✗".red().bold());
            return 1;
        }

        if let Some(steps) = steps {
            match snapshot::rollback::rollback_steps(&snap_dir, &session_id, steps) {
                Ok(msgs) => {
                    for msg in &msgs {
                        println!("  {} {}", "✓".green().bold(), msg);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        } else if let Some(id) = id {
            match snapshot::rollback::rollback_by_id(&snap_dir, &session_id, &id) {
                Ok(msg) => {
                    println!("  {} {}", "✓".green().bold(), msg);
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        } else if let Some(file) = file {
            match snapshot::rollback::rollback_file(&snap_dir, &session_id, &file) {
                Ok(msg) => {
                    println!("  {} {}", "✓".green().bold(), msg);
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        } else {
            match snapshot::rollback::rollback_session(&snap_dir, &session_id) {
                Ok(msgs) => {
                    for msg in &msgs {
                        println!("  {} {}", "✓".green().bold(), msg);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".red().bold(), e);
                    1
                }
            }
        }
    }
}

fn cmd_context(session_id: &str, verbose: bool) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let policy = policy::loader::load_policy_or_defaults(&cwd);
    let trace_dir = trace::logger::global_trace_dir();
    let snap_dir = cwd.join(&policy.snapshot.directory);

    context::print_context(&trace_dir, &snap_dir, session_id, verbose);
    0
}

fn cmd_diff(session_id: &str, file: Option<String>) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let policy = policy::loader::load_policy_or_defaults(&cwd);
    let snap_dir = cwd.join(&policy.snapshot.directory);

    context::print_diff(&snap_dir, session_id, file.as_deref());
    0
}

fn cmd_status() -> i32 {
    println!("{}", "railguard status".bold());
    println!();

    match install::hooks::check_installed() {
        Ok(true) => println!("  {} Hooks installed in Claude Code", "✓".green().bold()),
        Ok(false) => println!("  {} Hooks not installed (run {})", "✗".yellow().bold(), "railguard install".cyan()),
        Err(e) => println!("  {} Could not check hooks: {}", "?".yellow().bold(), e),
    }

    let cwd = std::env::current_dir().unwrap_or_default();
    let loaded_policy = policy::loader::load_policy_or_defaults(&cwd);

    match policy::loader::find_policy_file(&cwd) {
        Some(path) => {
            println!("  {} Policy loaded: {}", "✓".green().bold(), path.display());
            println!("       {} blocklist rules", loaded_policy.blocklist.len());
            println!("       {} approve rules", loaded_policy.approve.len());
            println!("       {} allowlist rules", loaded_policy.allowlist.len());
            println!("       fence: {}", if loaded_policy.fence.enabled { "on" } else { "off" });
            println!("       trace: {}", if loaded_policy.trace.enabled { "on" } else { "off" });
            println!("       snapshot: {}", if loaded_policy.snapshot.enabled { "on" } else { "off" });
            println!("       memory safety: {}", if loaded_policy.memory.enabled { "on" } else { "off" });
        }
        None => {
            println!("  {} No railguard.yaml found (using defaults)", "●".cyan().bold());
            println!("       {} default rules active", loaded_policy.blocklist.len());
        }
    }

    println!();
    0
}

fn cmd_locks() -> i32 {
    let locks = coord::lock::list_active_locks();

    if locks.is_empty() {
        println!("  No active file locks.");
        return 0;
    }

    println!("{}", "railguard locks".bold());
    println!();

    // Group by session
    let mut by_session: std::collections::HashMap<String, Vec<&coord::lock::FileLock>> =
        std::collections::HashMap::new();
    for lock in &locks {
        by_session
            .entry(lock.session_id.clone())
            .or_default()
            .push(lock);
    }

    for (session_id, files) in &by_session {
        let short = if session_id.len() > 8 {
            &session_id[..8]
        } else {
            session_id
        };
        println!("  {} Session {}...  ({} files)", "●".cyan(), short, files.len());
        for lock in files {
            let elapsed = chrono::DateTime::parse_from_rfc3339(&lock.last_heartbeat)
                .map(|hb| {
                    let secs = chrono::Utc::now()
                        .signed_duration_since(hb)
                        .num_seconds()
                        .max(0);
                    format!("{}s ago", secs)
                })
                .unwrap_or_else(|_| "?".to_string());
            println!("    {} {} ({})", "→".green(), lock.file_path, elapsed);
        }
        println!();
    }

    0
}

fn cmd_chat() -> i32 {
    println!("{}", "railguard chat".bold());
    println!();
    println!("  Launching interactive policy configuration...");
    println!();

    let claude_check = std::process::Command::new("which")
        .arg("claude")
        .output();

    match claude_check {
        Ok(output) if output.status.success() => {
            let prompt = r#"You are the Railguard policy configuration assistant. Help the user create or modify their railguard.yaml policy file.

The user's current working directory has (or will have) a railguard.yaml file. Help them:
1. Add blocklist rules to prevent dangerous commands
2. Add approve rules for commands that need human sign-off
3. Configure path fencing (allowed/denied directories)
4. Configure trace and snapshot settings

The railguard.yaml format is:
```yaml
version: 1
blocklist:
  - name: rule-name
    tool: Bash          # Bash, Write, Edit, Read, or *
    pattern: "regex"    # regex pattern to match
    action: block
    message: "Why it's blocked"
approve:
  - name: rule-name
    tool: Bash
    pattern: "regex"
    action: approve
    message: "Why approval needed"
allowlist:
  - name: rule-name
    tool: Bash
    pattern: "regex"
    action: allow
fence:
  enabled: true
  allowed_paths: []
  denied_paths:
    - "~/.ssh"
    - "~/.aws"
trace:
  enabled: true
  directory: .railguard/traces
snapshot:
  enabled: true
  tools: [Write, Edit]
  directory: .railguard/snapshots
```

Read the current railguard.yaml (if it exists) and help the user modify it based on their needs. Always write valid YAML with valid regex patterns."#;

            let status = std::process::Command::new("claude")
                .arg("--print")
                .arg("-p")
                .arg(prompt)
                .status();

            match status {
                Ok(s) => s.code().unwrap_or(0),
                Err(e) => {
                    eprintln!("  {} Failed to launch claude: {}", "✗".red().bold(), e);
                    1
                }
            }
        }
        _ => {
            eprintln!("  {} Claude Code CLI not found.", "✗".red().bold());
            eprintln!("  Install it: https://docs.anthropic.com/en/docs/claude-code");
            eprintln!();
            eprintln!("  Alternatively, edit railguard.yaml manually.");
            eprintln!("  Run {} to generate a starter config.", "railguard init".cyan());
            1
        }
    }
}

fn cmd_memory(action: MemoryCommands) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();

    match action {
        MemoryCommands::List => {
            println!("{}", "railguard memory list".bold());
            println!();

            let entries = memory::provenance::load_entries(&cwd);
            if entries.is_empty() {
                println!("  No memory provenance records found.");
                println!("  Records are created when Claude Code writes memory files through Railguard.");
                return 0;
            }

            // Group by file path, show latest entry per file
            let mut by_file: std::collections::HashMap<String, &railguard::types::MemoryEntry> =
                std::collections::HashMap::new();
            for entry in &entries {
                by_file.insert(entry.file_path.clone(), entry);
            }

            let mut files: Vec<_> = by_file.into_iter().collect();
            files.sort_by(|a, b| a.0.cmp(&b.0));

            for (file_path, entry) in &files {
                let short: String = if let Some(idx) = file_path.find(".claude/projects/") {
                    format!("~/{}", &file_path[idx..])
                } else {
                    file_path.clone()
                };

                let approved_icon = if entry.human_approved {
                    "✓".green().to_string()
                } else {
                    "●".cyan().to_string()
                };

                println!(
                    "  {} {} [{}] {}",
                    approved_icon,
                    short,
                    entry.classification.cyan(),
                    entry.provenance.dimmed()
                );
            }

            println!();
            println!("  {} entries across {} files", entries.len(), files.len());
            0
        }

        MemoryCommands::Verify => {
            println!("{}", "railguard memory verify".bold());
            println!();

            let warnings = memory::guard::verify_memory_integrity(&cwd);
            if warnings.is_empty() {
                println!("  {} All memory files verified — no integrity issues", "✓".green().bold());
            } else {
                println!(
                    "  {} {} issue(s) found:\n",
                    "⚠".yellow().bold(),
                    warnings.len()
                );
                for warning in &warnings {
                    println!("    {} {}", "•".yellow(), warning);
                }
                println!();
                println!("  To trust a file: {}", "railguard memory trust <file>".cyan());
                println!(
                    "  To quarantine: {}",
                    "railguard memory quarantine <file>".cyan()
                );
            }
            0
        }

        MemoryCommands::Log { count } => {
            println!("{}", "railguard memory log".bold());
            println!();

            let entries = memory::provenance::load_entries(&cwd);
            if entries.is_empty() {
                println!("  No memory write history.");
                return 0;
            }

            let start = if entries.len() > count {
                entries.len() - count
            } else {
                0
            };

            for entry in &entries[start..] {
                let short_path = if let Some(idx) = entry.file_path.find(".claude/projects/") {
                    format!("~/{}", &entry.file_path[idx..])
                } else {
                    entry.file_path.clone()
                };

                let approved = if entry.human_approved {
                    " (human-approved)".green().to_string()
                } else {
                    String::new()
                };

                let short_session = if entry.session_id.len() > 8 {
                    &entry.session_id[..8]
                } else {
                    &entry.session_id
                };

                // Parse and format timestamp
                let time = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
                    .map(|dt| dt.format("%m-%d %H:%M").to_string())
                    .unwrap_or_else(|_| entry.timestamp.clone());

                println!(
                    "  {} {} [{}] {} session:{}...{}",
                    time.dimmed(),
                    short_path,
                    entry.classification.cyan(),
                    entry.provenance,
                    short_session,
                    approved
                );
            }
            0
        }

        MemoryCommands::Quarantine { file } => {
            println!("{}", "railguard memory quarantine".bold());
            println!();

            let file_path = if file.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    format!("{}{}", home.display(), &file[1..])
                } else {
                    file.clone()
                }
            } else {
                file.clone()
            };

            if !Path::new(&file_path).exists() {
                eprintln!("  {} File not found: {}", "✗".red().bold(), file);
                return 1;
            }

            // Rename with .quarantined suffix
            let quarantined = format!("{}.quarantined", file_path);
            match std::fs::rename(&file_path, &quarantined) {
                Ok(_) => {
                    println!(
                        "  {} Quarantined: {} → {}",
                        "✓".green().bold(),
                        file,
                        quarantined
                    );
                    println!("  The memory file has been renamed and will not be loaded by Claude Code.");
                    0
                }
                Err(e) => {
                    eprintln!("  {} Failed to quarantine: {}", "✗".red().bold(), e);
                    1
                }
            }
        }

        MemoryCommands::Trust { file } => {
            println!("{}", "railguard memory trust".bold());
            println!();

            let file_path = if file.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    format!("{}{}", home.display(), &file[1..])
                } else {
                    file.clone()
                }
            } else {
                file.clone()
            };

            let content = match std::fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("  {} Failed to read file: {}", "✗".red().bold(), e);
                    return 1;
                }
            };

            let classification = memory::classifier::classify(&content);
            let label = memory::classifier::classification_label(&classification);

            match memory::provenance::sign(&cwd, "manual-trust", &file_path, &content, label, true)
            {
                Ok(_) => {
                    println!(
                        "  {} Trusted: {} [{}]",
                        "✓".green().bold(),
                        file,
                        label.cyan()
                    );
                    println!("  Content hash recorded. Future integrity checks will use this as baseline.");
                    0
                }
                Err(e) => {
                    eprintln!("  {} Failed to sign: {}", "✗".red().bold(), e);
                    1
                }
            }
        }
    }
}

