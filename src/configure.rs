use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, MultiSelect, Select};
use std::path::Path;

use crate::policy::defaults;
use crate::types::{FenceConfig, Policy, SnapshotConfig, TraceConfig};

/// Category of protection for display in the configure UI.
struct ProtectionCategory {
    name: &'static str,
    description: &'static str,
    items: Vec<ProtectionItem>,
}

struct ProtectionItem {
    label: String,
    rule_name: String,
    enabled: bool,
}

/// Run the interactive configure UI.
pub fn run_configure() -> i32 {
    println!();
    println!("  {}", "railyard configure".bold());
    println!("  {}", "Interactive policy configuration".dimmed());
    println!();

    // Step 1: Choose mode
    let modes = vec!["chill — block destructive commands only", "hardcore — full lockdown"];
    let mode_idx = match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("  Protection mode")
        .items(&modes)
        .default(0)
        .interact()
    {
        Ok(idx) => idx,
        Err(_) => return 1,
    };
    let mode = if mode_idx == 1 { "hardcore" } else { "chill" };

    println!();

    // Step 2: Show protection categories and let user toggle
    let all_rules = if mode == "hardcore" {
        defaults::hardcore_blocklist()
    } else {
        defaults::chill_blocklist()
    };

    // Organize rules into categories
    let categories = categorize_rules(&all_rules);

    let mut selected_rules: Vec<String> = Vec::new();

    for cat in &categories {
        println!("  {} {}", "●".cyan(), cat.name.bold());
        println!("  {}", cat.description.dimmed());

        let labels: Vec<String> = cat
            .items
            .iter()
            .map(|item| {
                let action_label = if all_rules.iter().any(|r| r.name == item.rule_name && r.action == "approve") {
                    " (approve)".dimmed().to_string()
                } else {
                    " (block)".dimmed().to_string()
                };
                format!("{}{}", item.label, action_label)
            })
            .collect();

        let defaults: Vec<bool> = cat.items.iter().map(|item| item.enabled).collect();

        match MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("  Select protections")
            .items(&labels)
            .defaults(&defaults)
            .interact()
        {
            Ok(selections) => {
                for idx in selections {
                    selected_rules.push(cat.items[idx].rule_name.clone());
                }
            }
            Err(_) => return 1,
        }
        println!();
    }

    // Step 3: Fence configuration
    let fence_enabled = if mode == "hardcore" {
        println!("  {} {}", "●".cyan(), "Path Fence".bold());
        println!("  {}", "Restrict file access to project directory".dimmed());
        match Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("  Enable path fencing?")
            .default(true)
            .interact()
        {
            Ok(v) => v,
            Err(_) => return 1,
        }
    } else {
        match Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("  Enable path fencing? (restricts file access to project dir)")
            .default(false)
            .interact()
        {
            Ok(v) => v,
            Err(_) => return 1,
        }
    };
    println!();

    // Step 4: Trace & Snapshot
    println!("  {} {}", "●".cyan(), "Observability".bold());

    let trace_enabled = match Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("  Enable audit trail? (logs every tool call)")
        .default(true)
        .interact()
    {
        Ok(v) => v,
        Err(_) => return 1,
    };

    let snapshot_enabled = match Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("  Enable file snapshots? (per-edit undo)")
        .default(true)
        .interact()
    {
        Ok(v) => v,
        Err(_) => return 1,
    };
    println!();

    // Step 5: Build the policy
    let policy = build_policy_from_selections(
        mode,
        &selected_rules,
        &all_rules,
        fence_enabled,
        trace_enabled,
        snapshot_enabled,
    );

    // Step 6: Write the file
    let output_path = Path::new("railyard.yaml");
    if output_path.exists() {
        match Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("  railyard.yaml exists. Overwrite?")
            .default(false)
            .interact()
        {
            Ok(true) => {}
            _ => {
                println!("  {}", "Cancelled.".dimmed());
                return 0;
            }
        }
    }

    let yaml = generate_yaml(&policy, mode);
    match std::fs::write(output_path, &yaml) {
        Ok(_) => {
            let mode_label = if mode == "hardcore" {
                "hardcore".red().bold().to_string()
            } else {
                "chill".green().bold().to_string()
            };

            let rule_count = policy.blocklist.len() + policy.approve.len();
            println!();
            println!("  {} Created railyard.yaml", "✓".green().bold());
            println!("       mode: {}", mode_label);
            println!(
                "       {} rules, fence {}, trace {}, snapshot {}",
                rule_count,
                if fence_enabled { "on" } else { "off" },
                if trace_enabled { "on" } else { "off" },
                if snapshot_enabled { "on" } else { "off" },
            );
            println!();

            // Check if hooks are installed
            match crate::install::hooks::check_installed() {
                Ok(true) => {
                    println!("  {} Hooks already installed — config active on next run.", "✓".green().bold());
                }
                _ => {
                    println!(
                        "  Run {} to activate protection.",
                        "railyard install".cyan()
                    );
                }
            }
            println!();
            0
        }
        Err(e) => {
            eprintln!(
                "  {} Failed to write railyard.yaml: {}",
                "✗".red().bold(),
                e
            );
            1
        }
    }
}

fn categorize_rules(rules: &[crate::types::Rule]) -> Vec<ProtectionCategory> {
    let mut categories = Vec::new();

    // Destructive commands
    let destructive_names = [
        "terraform-destroy",
        "rm-rf-critical",
        "sql-drop",
        "git-force-push",
        "git-reset-hard",
        "git-clean-force",
        "drizzle-force",
        "disk-format",
        "k8s-delete-namespace",
        "aws-s3-rm-recursive",
        "docker-system-prune",
        "chmod-777-recursive",
        "npm-publish",
    ];
    let destructive_labels = [
        "terraform destroy / apply -auto-approve",
        "rm -rf on critical paths (/, ~, $HOME)",
        "DROP TABLE / DATABASE / TRUNCATE",
        "git push --force",
        "git reset --hard",
        "git clean -f (remove untracked files)",
        "drizzle-kit push --force",
        "Disk format (mkfs, dd of=/dev/...)",
        "kubectl delete namespace",
        "aws s3 rm --recursive",
        "docker system prune -a",
        "chmod -R 777 /",
        "npm publish (requires approval)",
    ];

    let items: Vec<ProtectionItem> = destructive_names
        .iter()
        .zip(destructive_labels.iter())
        .filter(|(name, _)| rules.iter().any(|r| r.name == **name))
        .map(|(name, label)| ProtectionItem {
            label: label.to_string(),
            rule_name: name.to_string(),
            enabled: true,
        })
        .collect();

    if !items.is_empty() {
        categories.push(ProtectionCategory {
            name: "Destructive Commands",
            description: "Block commands that destroy data or infrastructure",
            items,
        });
    }

    // Self-protection
    let self_protect_names = [
        "railyard-uninstall",
        "railyard-tamper-settings",
        "railyard-remove-binary",
    ];
    let self_protect_labels = [
        "Block railyard uninstall",
        "Block Claude Code settings tampering",
        "Block railyard binary removal",
    ];

    let items: Vec<ProtectionItem> = self_protect_names
        .iter()
        .zip(self_protect_labels.iter())
        .filter(|(name, _)| rules.iter().any(|r| r.name == **name))
        .map(|(name, label)| ProtectionItem {
            label: label.to_string(),
            rule_name: name.to_string(),
            enabled: true,
        })
        .collect();

    if !items.is_empty() {
        categories.push(ProtectionCategory {
            name: "Self-Protection",
            description: "Prevent the agent from disabling its own guardrails",
            items,
        });
    }

    // Network (hardcore only)
    let network_names = [
        "network-curl-pipe-sh",
        "network-nc",
        "network-curl-post",
        "network-wget",
        "network-ssh-scp",
    ];
    let network_labels = [
        "Block curl | sh (remote code execution)",
        "Block netcat (raw sockets)",
        "curl POST (approve, may exfiltrate data)",
        "wget (approve)",
        "ssh/scp/rsync (approve)",
    ];

    let items: Vec<ProtectionItem> = network_names
        .iter()
        .zip(network_labels.iter())
        .filter(|(name, _)| rules.iter().any(|r| r.name == **name))
        .map(|(name, label)| ProtectionItem {
            label: label.to_string(),
            rule_name: name.to_string(),
            enabled: true,
        })
        .collect();

    if !items.is_empty() {
        categories.push(ProtectionCategory {
            name: "Network Policy",
            description: "Control outbound network access",
            items,
        });
    }

    // Credentials (hardcore only)
    let cred_names = ["env-dump", "git-config-global-write"];
    let cred_labels = [
        "env/printenv dump (approve, may expose secrets)",
        "Block git config --global writes",
    ];

    let items: Vec<ProtectionItem> = cred_names
        .iter()
        .zip(cred_labels.iter())
        .filter(|(name, _)| rules.iter().any(|r| r.name == **name))
        .map(|(name, label)| ProtectionItem {
            label: label.to_string(),
            rule_name: name.to_string(),
            enabled: true,
        })
        .collect();

    if !items.is_empty() {
        categories.push(ProtectionCategory {
            name: "Credential Protection",
            description: "Prevent secret and credential leakage",
            items,
        });
    }

    // Evasion detection (hardcore only)
    let evasion_names = [
        "base64-to-shell",
        "eval-dynamic",
        "printf-hex-exec",
        "symlink-to-outside",
    ];
    let evasion_labels = [
        "Block base64 decode | sh",
        "eval with variable expansion (approve)",
        "Block printf hex substitution in commands",
        "Symlink to absolute path (approve)",
    ];

    let items: Vec<ProtectionItem> = evasion_names
        .iter()
        .zip(evasion_labels.iter())
        .filter(|(name, _)| rules.iter().any(|r| r.name == **name))
        .map(|(name, label)| ProtectionItem {
            label: label.to_string(),
            rule_name: name.to_string(),
            enabled: true,
        })
        .collect();

    if !items.is_empty() {
        categories.push(ProtectionCategory {
            name: "Evasion Detection",
            description: "Detect attempts to bypass rules via encoding or indirection",
            items,
        });
    }

    categories
}

fn build_policy_from_selections(
    mode: &str,
    selected_rules: &[String],
    all_rules: &[crate::types::Rule],
    fence_enabled: bool,
    trace_enabled: bool,
    snapshot_enabled: bool,
) -> Policy {
    let mut blocklist = Vec::new();
    let mut approve = Vec::new();

    for rule in all_rules {
        if selected_rules.contains(&rule.name) {
            if rule.action == "approve" {
                approve.push(rule.clone());
            } else {
                blocklist.push(rule.clone());
            }
        }
    }

    let fence = if fence_enabled {
        FenceConfig::default()
    } else {
        FenceConfig {
            enabled: false,
            ..Default::default()
        }
    };

    Policy {
        version: 1,
        mode: mode.to_string(),
        blocklist,
        approve,
        allowlist: vec![],
        fence,
        trace: TraceConfig {
            enabled: trace_enabled,
            ..Default::default()
        },
        snapshot: SnapshotConfig {
            enabled: snapshot_enabled,
            ..Default::default()
        },
    }
}

fn generate_yaml(policy: &Policy, mode: &str) -> String {
    let mut yaml = String::new();

    yaml.push_str("# Railyard Policy Configuration\n");
    yaml.push_str("# https://github.com/railyarddev/railyard\n");
    yaml.push_str("#\n");
    yaml.push_str("# Generated by: railyard configure\n\n");

    yaml.push_str(&format!("version: {}\n", policy.version));
    yaml.push_str(&format!("mode: {}\n\n", mode));

    // Blocklist
    if !policy.blocklist.is_empty() {
        yaml.push_str("blocklist:\n");
        for rule in &policy.blocklist {
            yaml.push_str(&format!("  - name: {}\n", rule.name));
            yaml.push_str(&format!("    tool: {}\n", rule.tool));
            yaml.push_str(&format!("    pattern: \"{}\"\n", escape_yaml_string(&rule.pattern)));
            yaml.push_str(&format!("    action: {}\n", rule.action));
            if let Some(msg) = &rule.message {
                yaml.push_str(&format!("    message: \"{}\"\n", msg));
            }
            yaml.push('\n');
        }
    } else {
        yaml.push_str("blocklist: []\n\n");
    }

    // Approve
    if !policy.approve.is_empty() {
        yaml.push_str("approve:\n");
        for rule in &policy.approve {
            yaml.push_str(&format!("  - name: {}\n", rule.name));
            yaml.push_str(&format!("    tool: {}\n", rule.tool));
            yaml.push_str(&format!("    pattern: \"{}\"\n", escape_yaml_string(&rule.pattern)));
            yaml.push_str(&format!("    action: {}\n", rule.action));
            if let Some(msg) = &rule.message {
                yaml.push_str(&format!("    message: \"{}\"\n", msg));
            }
            yaml.push('\n');
        }
    } else {
        yaml.push_str("approve: []\n\n");
    }

    yaml.push_str("allowlist: []\n\n");

    // Fence
    yaml.push_str("fence:\n");
    yaml.push_str(&format!("  enabled: {}\n", policy.fence.enabled));
    if policy.fence.enabled {
        yaml.push_str("  allowed_paths: []\n");
        yaml.push_str("  denied_paths:\n");
        for path in &policy.fence.denied_paths {
            yaml.push_str(&format!("    - \"{}\"\n", path));
        }
    } else {
        yaml.push_str("  allowed_paths: []\n");
        yaml.push_str("  denied_paths: []\n");
    }

    yaml.push('\n');

    // Trace
    yaml.push_str("trace:\n");
    yaml.push_str(&format!("  enabled: {}\n", policy.trace.enabled));
    yaml.push_str(&format!("  directory: {}\n\n", policy.trace.directory));

    // Snapshot
    yaml.push_str("snapshot:\n");
    yaml.push_str(&format!("  enabled: {}\n", policy.snapshot.enabled));
    yaml.push_str(&format!(
        "  tools: [{}]\n",
        policy.snapshot.tools.join(", ")
    ));
    yaml.push_str(&format!("  directory: {}\n", policy.snapshot.directory));

    yaml
}

fn escape_yaml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
