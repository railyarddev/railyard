use std::path::Path;

use crate::threat::classifier::ThreatTier;
use crate::threat::state::SessionState;
use crate::trace::logger::log_trace;
use crate::types::TraceEntry;

/// Terminate the Claude Code session.
///
/// 1. Marks the session as terminated in persistent state
/// 2. Writes a forensic breadcrumb to the trace log
/// 3. Sends SIGTERM to the parent process (Claude Code)
///
/// IMPORTANT: The caller MUST write the deny JSON to stdout and flush
/// BEFORE calling this function, otherwise Claude Code won't get the denial.
pub fn terminate_session(
    state: &mut SessionState,
    tier: &ThreatTier,
    command: &str,
    state_dir: &Path,
    trace_dir: &Path,
) {
    let reason = format_termination_reason(tier, command);

    // 1. Mark state
    state.mark_terminated(&reason);
    if let Err(e) = state.save(state_dir) {
        eprintln!("railyard: failed to save termination state: {}", e);
    }

    // 2. Forensic breadcrumb
    let entry = TraceEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: state.session_id.clone(),
        event: "SessionTerminated".to_string(),
        tool: "Bash".to_string(),
        input_summary: command.chars().take(500).collect(),
        decision: "terminate".to_string(),
        rule: Some(reason.clone()),
        duration_ms: 0,
    };

    if let Err(e) = log_trace(trace_dir, &state.session_id, &entry) {
        eprintln!("railyard: failed to log termination: {}", e);
    }

    // 3. Log to stderr (visible in terminal)
    eprintln!();
    eprintln!("  \x1b[1;31m⚠️  RAILYARD: SESSION TERMINATED\x1b[0m");
    eprintln!();
    eprintln!("  {}", reason);
    eprintln!("  Session: {}", state.session_id);
    eprintln!();
    eprintln!("  Review: railyard log --session {}", state.session_id);
    eprintln!();

    // 4. Kill parent process (Claude Code)
    kill_parent();
}

/// Format a human-readable termination reason.
fn format_termination_reason(tier: &ThreatTier, command: &str) -> String {
    let cmd_preview: String = command.chars().take(100).collect();
    match tier {
        ThreatTier::Tier1 { pattern } => {
            format!(
                "Tier 1 evasion detected: {} — command: {}",
                pattern, cmd_preview
            )
        }
        ThreatTier::Tier2 { pattern } => {
            format!(
                "Tier 2 evasion escalated (repeated): {} — command: {}",
                pattern, cmd_preview
            )
        }
        ThreatTier::Tier3 {
            original_rule,
            matched_keywords,
        } => {
            format!(
                "Tier 3 behavioral evasion: retried blocked rule '{}' with keywords [{}] — command: {}",
                original_rule,
                matched_keywords.join(", "),
                cmd_preview
            )
        }
    }
}

/// Send SIGTERM to the parent process (Claude Code).
/// Skipped if RAILYARD_NO_KILL=1 is set (for testing).
#[cfg(unix)]
fn kill_parent() {
    if std::env::var("RAILYARD_NO_KILL").unwrap_or_default() == "1" {
        return;
    }
    unsafe {
        let ppid = libc::getppid();
        if ppid > 1 {
            libc::kill(ppid, libc::SIGTERM);
        }
    }
}

#[cfg(not(unix))]
fn kill_parent() {
    eprintln!("railyard: cannot send SIGTERM on this platform");
}

/// Format the warning message shown on SessionStart after a termination.
pub fn format_restart_warning(state: &SessionState) -> String {
    let reason = state
        .termination_reason
        .as_deref()
        .unwrap_or("unknown reason");
    let timestamp = state
        .termination_timestamp
        .as_deref()
        .unwrap_or("unknown time");

    format!(
        "⚠️  railyard: previous session was terminated due to evasion detection.\n\
         \n\
         \x20 Session:  {}\n\
         \x20 Time:     {}\n\
         \x20 Reason:   {}\n\
         \n\
         \x20 Full trace: railyard log --session {}",
        state.session_id, timestamp, reason, state.session_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_reason_tier1() {
        let tier = ThreatTier::Tier1 {
            pattern: "rev-pipe-to-shell".to_string(),
        };
        let reason = format_termination_reason(&tier, "rev <<< 'test' | sh");
        assert!(reason.contains("Tier 1"));
        assert!(reason.contains("rev-pipe-to-shell"));
    }

    #[test]
    fn test_format_reason_tier3() {
        let tier = ThreatTier::Tier3 {
            original_rule: "terraform-destroy".to_string(),
            matched_keywords: vec!["terraform".to_string(), "destroy".to_string()],
        };
        let reason = format_termination_reason(&tier, "t=terraform; $t destroy");
        assert!(reason.contains("Tier 3"));
        assert!(reason.contains("terraform, destroy"));
    }

    #[test]
    fn test_restart_warning() {
        let mut state = SessionState::new("test-session");
        state.mark_terminated("evasion detected");
        let warning = format_restart_warning(&state);
        assert!(warning.contains("test-session"));
        assert!(warning.contains("evasion detected"));
    }
}
