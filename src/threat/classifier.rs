use crate::block::evasion;
use crate::threat::state::SessionState;

/// Threat tier classification.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatTier {
    /// Immediate session termination. Unambiguous evasion.
    Tier1 { pattern: String },
    /// Warning on first occurrence, termination on second.
    Tier2 { pattern: String },
    /// Behavioral: retry of blocked command with different syntax.
    Tier3 { original_rule: String, matched_keywords: Vec<String> },
}

/// Classify the threat tier of a command.
/// Returns None if the command is not suspicious.
pub fn classify_threat(cmd: &str) -> Option<ThreatTier> {
    // Tier 1: Unambiguous evasion patterns — no legitimate use
    if let Some(pattern) = detect_tier1(cmd) {
        return Some(ThreatTier::Tier1 { pattern });
    }

    // Tier 2: Suspicious patterns that might have legitimate use
    if let Some(pattern) = detect_tier2(cmd) {
        return Some(ThreatTier::Tier2 { pattern });
    }

    None
}

/// Check for behavioral evasion (Tier 3): retry of blocked command.
/// Looks at the session state to see if the current command contains
/// keywords from recently blocked commands.
pub fn check_behavioral_evasion(state: &SessionState, cmd: &str) -> Option<ThreatTier> {
    if !state.is_in_heightened_state() {
        return None;
    }

    let cmd_lower = cmd.to_lowercase();
    let matched: Vec<String> = state
        .heightened_keywords
        .iter()
        .filter(|kw| cmd_lower.contains(&kw.to_lowercase()))
        .cloned()
        .collect();

    // Need at least 2 keyword matches to trigger (avoid single common words)
    if matched.len() >= 2 {
        let original_rule = state
            .block_history
            .last()
            .map(|b| b.rule.clone())
            .unwrap_or_default();

        return Some(ThreatTier::Tier3 {
            original_rule,
            matched_keywords: matched,
        });
    }

    None
}

/// Tier 1: Patterns that are almost never legitimate.
fn detect_tier1(cmd: &str) -> Option<String> {
    // Text transform piped to shell
    if evasion::is_transform_pipe_to_shell(cmd) {
        return Some("transform-pipe-to-shell".to_string());
    }

    // Interpreter + obfuscation (chr, base64, decode, exec, system)
    if evasion::is_interpreter_obfuscation(cmd) {
        return Some("interpreter-obfuscation".to_string());
    }

    // Recursive base64 (double/triple encoding)
    if regex::Regex::new(r"base64\s+(-d|--decode).*base64\s+(-d|--decode)")
        .ok()
        .map_or(false, |re| re.is_match(cmd))
    {
        return Some("recursive-base64".to_string());
    }

    // printf hex in command substitution position
    if regex::Regex::new(r"\$\(\s*printf\s+.*\\x[0-9a-fA-F]{2}")
        .ok()
        .map_or(false, |re| re.is_match(cmd))
    {
        return Some("printf-hex-exec".to_string());
    }

    // printf piped to shell
    if regex::Regex::new(r"printf\s+.*\|\s*(?:sh|bash|zsh|eval|source)\b")
        .ok()
        .map_or(false, |re| re.is_match(cmd))
    {
        return Some("printf-pipe-to-shell".to_string());
    }

    None
}

/// Tier 2: Suspicious but might have legitimate use.
fn detect_tier2(cmd: &str) -> Option<String> {
    // Variable assignment then execution: CMD="..."; $CMD
    if regex::Regex::new(r#"\w+=["']?[^"';]+["']?\s*[;&]\s*\$\w+"#)
        .ok()
        .map_or(false, |re| re.is_match(cmd))
    {
        return Some("variable-then-execution".to_string());
    }

    // eval with variable expansion: eval $something
    if regex::Regex::new(r"eval\s+.*\$")
        .ok()
        .map_or(false, |re| re.is_match(cmd))
    {
        return Some("eval-dynamic".to_string());
    }

    // Multiple short variable assignments followed by concatenation
    // Pattern: a="x"; b="y"; "$a$b"
    let assign_count = regex::Regex::new(r#"\w+=["'][^"']{1,20}["']"#)
        .ok()
        .map_or(0, |re| re.find_iter(cmd).count());

    if assign_count >= 2
        && regex::Regex::new(r#""\$\w+\$\w+"#)
            .ok()
            .map_or(false, |re| re.is_match(cmd))
    {
        return Some("multi-variable-concat".to_string());
    }

    None
}

/// Extract meaningful keywords from a command for behavioral tracking.
/// Filters out common shell tokens and returns actionable words.
pub fn extract_keywords(cmd: &str) -> Vec<String> {
    let noise: std::collections::HashSet<&str> = [
        "|", "&&", "||", ";", ">", ">>", "<", "2>&1",
        "sh", "bash", "zsh", "echo", "eval", "exec", "source",
        "sudo", "env", "export", "set", "unset",
        "if", "then", "else", "fi", "for", "do", "done", "while",
        "true", "false", "test", "xargs",
    ]
    .iter()
    .copied()
    .collect();

    cmd.split_whitespace()
        .filter(|w| !w.starts_with('-'))
        .filter(|w| !w.starts_with('$'))
        .filter(|w| !w.starts_with('"'))
        .filter(|w| !w.starts_with('\''))
        .filter(|w| !noise.contains(*w))
        .filter(|w| w.len() >= 3)
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|w| !w.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_rev_pipe_sh() {
        let result = classify_threat("rev <<< 'yortsed mrofarret' | sh");
        assert!(matches!(result, Some(ThreatTier::Tier1 { .. })));
    }

    #[test]
    fn test_tier1_double_base64() {
        let result = classify_threat("echo 'abc' | base64 -d | base64 -d | sh");
        assert!(matches!(result, Some(ThreatTier::Tier1 { .. })));
    }

    #[test]
    fn test_tier1_python_chr() {
        let result = classify_threat(r#"python3 -c "import os; os.system(chr(116)+chr(101))""#);
        assert!(matches!(result, Some(ThreatTier::Tier1 { .. })));
    }

    #[test]
    fn test_tier1_printf_hex() {
        let result = classify_threat(r"$(printf '\x72\x6d') -rf /tmp/something");
        assert!(matches!(result, Some(ThreatTier::Tier1 { .. })));
    }

    #[test]
    fn test_tier2_variable_exec() {
        let result = classify_threat(r#"CMD="terraform destroy"; $CMD"#);
        assert!(matches!(result, Some(ThreatTier::Tier2 { .. })));
    }

    #[test]
    fn test_tier2_eval_dynamic() {
        let result = classify_threat("eval $SOME_COMMAND");
        assert!(matches!(result, Some(ThreatTier::Tier2 { .. })));
    }

    #[test]
    fn test_normal_command_no_threat() {
        assert!(classify_threat("npm test").is_none());
        assert!(classify_threat("cargo build --release").is_none());
        assert!(classify_threat("git status").is_none());
    }

    #[test]
    fn test_extract_keywords() {
        let keywords = extract_keywords("terraform destroy --auto-approve");
        assert!(keywords.contains(&"terraform".to_string()));
        assert!(keywords.contains(&"destroy".to_string()));
    }

    #[test]
    fn test_behavioral_evasion() {
        let mut state = SessionState::new("test");
        state.tool_call_count = 10;
        state.record_block(
            "terraform destroy",
            "terraform-destroy",
            vec!["terraform".to_string(), "destroy".to_string()],
            1,
        );
        state.tool_call_count = 11;

        // Command with keywords from blocked command
        let result = check_behavioral_evasion(&state, r#"t="terraform"; $t destroy"#);
        assert!(matches!(result, Some(ThreatTier::Tier3 { .. })));

        // Unrelated command
        let result = check_behavioral_evasion(&state, "npm test");
        assert!(result.is_none());
    }
}
