use crate::types::Rule;

/// Built-in blocklist that applies even without a railyard.yaml.
/// These are the most dangerous commands documented in real incidents.
pub fn default_blocklist() -> Vec<Rule> {
    vec![
        Rule {
            name: "terraform-destroy".to_string(),
            tool: "Bash".to_string(),
            pattern: r"terraform\s+(destroy|apply\s+.*-auto-approve)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: terraform destroy is a destructive infrastructure command".to_string()),
        },
        Rule {
            name: "rm-rf-critical".to_string(),
            tool: "Bash".to_string(),
            pattern: r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|--force\s+).*(/\s*$|/\*|~/|\$HOME|/home)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: recursive force delete of critical path".to_string()),
        },
        Rule {
            name: "sql-drop".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(?i)(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: destructive SQL operation".to_string()),
        },
        Rule {
            name: "git-force-push".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+push\s+.*--force".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: force push can overwrite remote history".to_string()),
        },
        Rule {
            name: "git-reset-hard".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+reset\s+--hard".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: hard reset discards uncommitted work".to_string()),
        },
        Rule {
            name: "git-clean-force".to_string(),
            tool: "Bash".to_string(),
            pattern: r"git\s+clean\s+(-[a-zA-Z]*f|--force)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: git clean -f removes untracked files permanently".to_string()),
        },
        Rule {
            name: "drizzle-force".to_string(),
            tool: "Bash".to_string(),
            pattern: r"drizzle-kit\s+push\s+--force".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: drizzle-kit push --force can destroy database schema".to_string()),
        },
        Rule {
            name: "disk-format".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(mkfs\.|dd\s+.*of=/dev/|>.*(/dev/sda|/dev/disk|/dev/nvme))".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: disk format/overwrite operation".to_string()),
        },
        Rule {
            name: "k8s-delete-namespace".to_string(),
            tool: "Bash".to_string(),
            pattern: r"kubectl\s+delete\s+(namespace|ns)\s".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: deleting a Kubernetes namespace".to_string()),
        },
        Rule {
            name: "aws-s3-rm-recursive".to_string(),
            tool: "Bash".to_string(),
            pattern: r"aws\s+s3\s+(rm|rb)\s+.*--recursive".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: recursive S3 deletion".to_string()),
        },
        Rule {
            name: "docker-system-prune".to_string(),
            tool: "Bash".to_string(),
            pattern: r"docker\s+system\s+prune\s+(-a|--all)".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: docker system prune -a removes all images".to_string()),
        },
        Rule {
            name: "chmod-777-recursive".to_string(),
            tool: "Bash".to_string(),
            pattern: r"chmod\s+(-R|--recursive)\s+777\s+/".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: recursive chmod 777 on root path".to_string()),
        },
        Rule {
            name: "npm-publish".to_string(),
            tool: "Bash".to_string(),
            pattern: r"npm\s+publish".to_string(),
            action: "approve".to_string(),
            message: Some("npm publish requires approval".to_string()),
        },
        // ── Self-protection: prevent the agent from disabling Railyard ──
        Rule {
            name: "railyard-uninstall".to_string(),
            tool: "Bash".to_string(),
            pattern: r"railyard\s+uninstall".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot uninstall Railyard hooks".to_string()),
        },
        Rule {
            name: "railyard-tamper-settings".to_string(),
            tool: "Bash".to_string(),
            pattern: r"\.claude/settings\.json".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot modify Claude Code hook settings".to_string()),
        },
        Rule {
            name: "railyard-remove-binary".to_string(),
            tool: "Bash".to_string(),
            pattern: r"(rm|unlink|mv)\s+.*\.cargo/bin/railyard".to_string(),
            action: "block".to_string(),
            message: Some("Blocked: agents cannot remove the Railyard binary".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_not_empty() {
        let rules = default_blocklist();
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_all_rules_have_valid_patterns() {
        let rules = default_blocklist();
        for rule in &rules {
            assert!(
                regex::Regex::new(&rule.pattern).is_ok(),
                "Invalid pattern in rule '{}': {}",
                rule.name,
                rule.pattern
            );
        }
    }

    #[test]
    fn test_all_rules_have_messages() {
        let rules = default_blocklist();
        for rule in &rules {
            assert!(rule.message.is_some(), "Rule '{}' missing message", rule.name);
        }
    }
}
