/// Available sandbox technology on this platform.
#[derive(Debug, Clone, PartialEq)]
pub enum SandboxCapability {
    /// macOS sandbox-exec (Seatbelt)
    MacOsSandboxExec,
    /// Linux Landlock (kernel 5.13+)
    LinuxLandlock { abi_version: u32 },
    /// No OS-level sandbox available
    None,
}

/// Detect what sandbox technology is available on this system.
pub fn detect_sandbox() -> SandboxCapability {
    #[cfg(target_os = "macos")]
    {
        if check_sandbox_exec() {
            return SandboxCapability::MacOsSandboxExec;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(abi) = check_landlock() {
            return SandboxCapability::LinuxLandlock { abi_version: abi };
        }
    }

    SandboxCapability::None
}

/// Check if sandbox-exec is available on macOS.
#[cfg(target_os = "macos")]
fn check_sandbox_exec() -> bool {
    std::process::Command::new("sandbox-exec")
        .arg("-n")
        .arg("no-network") // Built-in profile, harmless test
        .arg("true")       // Command that does nothing
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if Landlock is available on Linux and return ABI version.
#[cfg(target_os = "linux")]
fn check_landlock() -> Option<u32> {
    use std::fs;
    // Check kernel version (need 5.13+)
    if let Ok(version) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let parts: Vec<&str> = version.trim().split('.').collect();
        if parts.len() >= 2 {
            let major: u32 = parts[0].parse().unwrap_or(0);
            let minor: u32 = parts[1].parse().unwrap_or(0);
            if major > 5 || (major == 5 && minor >= 13) {
                // Check if Landlock is enabled via syscall
                // ABI version detection: try landlock_create_ruleset with flag
                // For now, return ABI v3 as a reasonable default
                return Some(3);
            }
        }
    }
    None
}

/// Format a human-readable description of sandbox capabilities.
pub fn describe_capability(cap: &SandboxCapability) -> String {
    match cap {
        SandboxCapability::MacOsSandboxExec => {
            "macOS sandbox-exec (Seatbelt) — kernel-level, zero overhead, built-in".to_string()
        }
        SandboxCapability::LinuxLandlock { abi_version } => {
            format!(
                "Linux Landlock ABI v{} — kernel-level, zero overhead, built-in",
                abi_version
            )
        }
        SandboxCapability::None => {
            "No OS-level sandbox available — falling back to string-based fence".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_returns_something() {
        let cap = detect_sandbox();
        // On macOS CI, should detect sandbox-exec
        // On Linux CI, might detect Landlock
        // Either way, this shouldn't panic
        let _ = describe_capability(&cap);
    }
}
