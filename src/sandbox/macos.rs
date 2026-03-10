use crate::types::FenceConfig;

/// Generate a macOS sandbox profile (.sb) from FenceConfig.
///
/// The profile uses Apple's Sandbox Profile Language (SBPL/Scheme).
/// sandbox-exec wraps a process: `sandbox-exec -f profile.sb -- command`
///
/// The generated profile:
/// - Denies everything by default
/// - Allows read/write in the project directory
/// - Allows read-only access to system paths
/// - Explicitly denies sensitive directories (~/.ssh, ~/.aws, etc.)
/// - Controls network and process execution
pub fn generate_profile(config: &FenceConfig, cwd: &str) -> String {
    let home = dirs::home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_else(|| "/Users/unknown".to_string());

    let mut profile = String::new();

    // Header
    profile.push_str(";; Railyard OS-level sandbox profile\n");
    profile.push_str(";; Generated from railyard.yaml fence config\n");
    profile.push_str(";; Usage: sandbox-exec -f this-file.sb -- sh -c \"command\"\n");
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n\n");

    // Allow basic process operations
    profile.push_str(";; Allow process execution and signals\n");
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow sysctl-read)\n\n");

    // Allow mach and IPC (needed for most programs to function)
    profile.push_str(";; Allow IPC (required for process communication)\n");
    profile.push_str("(allow mach-lookup)\n");
    profile.push_str("(allow ipc-posix-shm-read-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-data)\n\n");

    // Allow read-only system paths
    profile.push_str(";; Read-only system paths\n");
    for sys_path in &[
        "/usr", "/bin", "/sbin", "/opt/homebrew",
        "/Library/Frameworks", "/System",
        "/private/var/db", "/private/etc",
    ] {
        profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", sys_path));
    }
    profile.push('\n');

    // Allow /dev access
    profile.push_str(";; Device access\n");
    profile.push_str("(allow file-read* file-write* (subpath \"/dev\"))\n\n");

    // Allow temp directories
    profile.push_str(";; Temporary files\n");
    profile.push_str("(allow file-read* file-write* (subpath \"/tmp\"))\n");
    profile.push_str("(allow file-read* file-write* (subpath \"/private/tmp\"))\n");
    profile.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{}/Library/Caches\"))\n\n",
        home
    ));

    // Allow cargo/rustup paths (for toolchain access)
    profile.push_str(";; Development toolchains\n");
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{}/.cargo\"))\n",
        home
    ));
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{}/.rustup\"))\n",
        home
    ));
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{}/.nvm\"))\n\n",
        home
    ));

    // Project directory: full read/write
    profile.push_str(";; Project directory (full access)\n");
    profile.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{}\"))\n\n",
        cwd
    ));

    // Allowed paths from config
    if !config.allowed_paths.is_empty() {
        profile.push_str(";; Additional allowed paths from config\n");
        for path in &config.allowed_paths {
            let expanded = expand_path(path, &home);
            profile.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n",
                expanded
            ));
        }
        profile.push('\n');
    }

    // Denied paths: explicit deny AFTER allows (deny takes precedence in SBPL)
    profile.push_str(";; Denied paths (sensitive directories)\n");
    for path in &config.denied_paths {
        let expanded = expand_path(path, &home);
        profile.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{}\"))\n",
            expanded
        ));
    }
    // Always deny SSH and AWS even if not in config
    let always_deny = vec![
        format!("{}/.ssh", home),
        format!("{}/.aws", home),
        format!("{}/.gnupg", home),
    ];
    for path in &always_deny {
        if !config
            .denied_paths
            .iter()
            .any(|d| expand_path(d, &home) == *path)
        {
            profile.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{}\"))\n",
                path
            ));
        }
    }
    profile.push('\n');

    // Network: deny by default in hardcore mode
    profile.push_str(";; Network policy (deny by default, allow specific)\n");
    profile.push_str("(deny network*)\n");
    profile.push_str("(allow network-outbound (remote tcp \"*:443\"))\n");
    profile.push_str("(allow network-outbound (remote tcp \"*:80\"))\n");
    profile.push_str("(allow network-inbound (local tcp \"localhost:*\"))\n");
    profile.push_str("(allow network-bind (local tcp \"localhost:*\"))\n");

    profile
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

/// Generate the sandbox-exec command to wrap a given command.
pub fn wrap_command(profile_path: &str, command: &str) -> String {
    format!(
        "sandbox-exec -f {} -- sh -c {}",
        shell_escape(profile_path),
        shell_escape(command)
    )
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_profile() {
        let config = FenceConfig {
            enabled: true,
            allowed_paths: vec![],
            denied_paths: vec!["~/.ssh".to_string(), "~/.aws".to_string()],
        };
        let profile = generate_profile(&config, "/Users/test/project");
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("/Users/test/project"));
        assert!(profile.contains(".ssh"));
    }

    #[test]
    fn test_wrap_command() {
        let wrapped = wrap_command("/path/to/profile.sb", "npm test");
        assert!(wrapped.contains("sandbox-exec"));
        assert!(wrapped.contains("npm test"));
    }
}
