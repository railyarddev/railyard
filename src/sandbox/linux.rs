use crate::types::FenceConfig;

/// Generate a Linux Landlock enforcement script from FenceConfig.
///
/// Since Landlock requires Rust code (or C syscalls) to enforce,
/// we generate a wrapper script that uses `bwrap` (bubblewrap) as
/// a more portable alternative. If bwrap isn't available, we provide
/// a Landlock-based Rust snippet the user can compile.
pub fn generate_bwrap_command(config: &FenceConfig, cwd: &str) -> String {
    let home = dirs::home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_else(|| "/home/user".to_string());

    let mut args = vec!["bwrap".to_string()];

    // Read-only system mounts
    for sys_path in &["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc"] {
        args.push(format!("--ro-bind {} {}", sys_path, sys_path));
    }

    // Proc and dev
    args.push("--proc /proc".to_string());
    args.push("--dev /dev".to_string());
    args.push("--tmpfs /tmp".to_string());

    // Project directory: read/write bind
    args.push(format!("--bind {} {}", cwd, cwd));

    // Allowed paths from config
    for path in &config.allowed_paths {
        let expanded = expand_path(path, &home);
        args.push(format!("--bind {} {}", expanded, expanded));
    }

    // Home directory: read-only by default, with denied paths simply not mounted
    args.push(format!("--ro-bind {} {}", home, home));

    // Denied paths: use --tmpfs to shadow them (mount empty tmpfs over them)
    for path in &config.denied_paths {
        let expanded = expand_path(path, &home);
        args.push(format!("--tmpfs {}", expanded));
    }
    // Always shadow sensitive dirs
    for sensitive in &[".ssh", ".aws", ".gnupg"] {
        let full = format!("{}/{}", home, sensitive);
        if !config.denied_paths.iter().any(|d| expand_path(d, &home) == full) {
            args.push(format!("--tmpfs {}", full));
        }
    }

    // Unshare network by default
    args.push("--unshare-net".to_string());

    // Working directory
    args.push(format!("--chdir {}", cwd));

    args.push("--".to_string());

    args.join(" \\\n  ")
}

/// Generate Landlock Rust code snippet for the user's reference.
pub fn generate_landlock_snippet(config: &FenceConfig, cwd: &str) -> String {
    let home = dirs::home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_else(|| "/home/user".to_string());

    let mut code = String::new();
    code.push_str("// Landlock enforcement for Railyard\n");
    code.push_str("// Requires: landlock = \"0.4\" in Cargo.toml\n");
    code.push_str("// Requires: Linux kernel 5.13+\n\n");
    code.push_str("use landlock::{\n");
    code.push_str("    Access, AccessFs, PathBeneath, PathFd,\n");
    code.push_str("    Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,\n");
    code.push_str("};\n\n");
    code.push_str("fn enforce_sandbox() -> Result<(), Box<dyn std::error::Error>> {\n");
    code.push_str("    let abi = ABI::V3;\n");
    code.push_str("    let mut ruleset = Ruleset::default()\n");
    code.push_str("        .handle_access(AccessFs::from_all(abi))?\n");
    code.push_str("        .create()?;\n\n");

    // Project directory: full access
    code.push_str(&format!(
        "    // Project directory: full access\n    ruleset.add_rule(PathBeneath::new(\n        PathFd::new(\"{}\")?,\n        AccessFs::from_all(abi),\n    ))?;\n\n",
        cwd
    ));

    // System paths: read-only
    code.push_str("    // System paths: read-only\n");
    for sys_path in &["/usr", "/bin", "/lib", "/opt", "/etc"] {
        code.push_str(&format!(
            "    ruleset.add_rule(PathBeneath::new(\n        PathFd::new(\"{}\")?,\n        AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,\n    ))?;\n",
            sys_path
        ));
    }
    code.push('\n');

    // Allowed paths
    for path in &config.allowed_paths {
        let expanded = expand_path(path, &home);
        code.push_str(&format!(
            "    ruleset.add_rule(PathBeneath::new(\n        PathFd::new(\"{}\")?,\n        AccessFs::from_all(abi),\n    ))?;\n",
            expanded
        ));
    }

    // Note about denied paths
    code.push_str("    // Denied paths (~/.ssh, ~/.aws, etc.) are not in the ruleset\n");
    code.push_str("    // = denied by default (Landlock is default-deny)\n\n");

    code.push_str("    // Enforce — all child processes inherit this sandbox\n");
    code.push_str("    ruleset.restrict_self()?;\n");
    code.push_str("    Ok(())\n");
    code.push_str("}\n");

    code
}

fn expand_path(path: &str, home: &str) -> String {
    if path.starts_with("~/") {
        format!("{}{}", home, &path[1..])
    } else if path.starts_with("$HOME") {
        path.replace("$HOME", home)
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bwrap() {
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec!["~/.ssh".to_string()],
        };
        let cmd = generate_bwrap_command(&config, "/home/user/project");
        assert!(cmd.contains("bwrap"));
        assert!(cmd.contains("/home/user/project"));
        assert!(cmd.contains("--tmpfs"));
    }

    #[test]
    fn test_generate_landlock() {
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec!["~/.ssh".to_string()],
        };
        let code = generate_landlock_snippet(&config, "/home/user/project");
        assert!(code.contains("Landlock"));
        assert!(code.contains("restrict_self"));
    }
}
