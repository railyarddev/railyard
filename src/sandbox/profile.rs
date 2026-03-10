use std::fs;
use std::path::Path;

use crate::sandbox::detect::{detect_sandbox, SandboxCapability};
use crate::sandbox::{linux, macos};
use crate::types::Policy;

/// Generate sandbox profiles from the policy's fence config.
/// Writes platform-appropriate profile to `.railyard/`.
pub fn generate_profiles(policy: &Policy, cwd: &str) -> Result<String, String> {
    let sandbox_dir = Path::new(cwd).join(".railyard");
    fs::create_dir_all(&sandbox_dir).map_err(|e| format!("create sandbox dir: {}", e))?;

    let capability = detect_sandbox();

    match capability {
        SandboxCapability::MacOsSandboxExec => {
            let profile = macos::generate_profile(&policy.fence, cwd);
            let profile_path = sandbox_dir.join("sandbox.sb");
            fs::write(&profile_path, &profile)
                .map_err(|e| format!("write sandbox profile: {}", e))?;

            Ok(format!(
                "Generated macOS sandbox profile: {}\n\
                 Usage: sandbox-exec -f {} -- sh -c \"your-command\"",
                profile_path.display(),
                profile_path.display()
            ))
        }

        SandboxCapability::LinuxLandlock { abi_version } => {
            // Generate both bwrap wrapper and Landlock snippet
            let bwrap_cmd = linux::generate_bwrap_command(&policy.fence, cwd);
            let bwrap_path = sandbox_dir.join("sandbox-bwrap.sh");
            let bwrap_script = format!(
                "#!/bin/sh\n# Railyard sandbox wrapper (bubblewrap)\n# Usage: .railyard/sandbox-bwrap.sh your-command\n\n{} \"$@\"\n",
                bwrap_cmd
            );
            fs::write(&bwrap_path, &bwrap_script)
                .map_err(|e| format!("write bwrap script: {}", e))?;

            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&bwrap_path, fs::Permissions::from_mode(0o755));
            }

            let landlock_code = linux::generate_landlock_snippet(&policy.fence, cwd);
            let landlock_path = sandbox_dir.join("sandbox-landlock.rs");
            fs::write(&landlock_path, &landlock_code)
                .map_err(|e| format!("write landlock snippet: {}", e))?;

            Ok(format!(
                "Generated Linux sandbox profiles (Landlock ABI v{}):\n\
                 \x20 Bubblewrap: {} -- your-command\n\
                 \x20 Landlock:   {} (Rust reference code)",
                abi_version,
                bwrap_path.display(),
                landlock_path.display()
            ))
        }

        SandboxCapability::None => Err(
            "No OS-level sandbox available on this platform.\n\
             macOS: requires sandbox-exec (built-in on all macOS versions)\n\
             Linux: requires kernel 5.13+ for Landlock"
                .to_string(),
        ),
    }
}

/// Run a command inside the sandbox.
pub fn run_sandboxed(policy: &Policy, cwd: &str, command: &[String]) -> Result<i32, String> {
    let capability = detect_sandbox();
    let cmd_str = command.join(" ");

    match capability {
        SandboxCapability::MacOsSandboxExec => {
            // Generate profile to temp location
            let profile = macos::generate_profile(&policy.fence, cwd);
            let profile_path = Path::new(cwd).join(".railyard/sandbox.sb");
            fs::create_dir_all(profile_path.parent().unwrap())
                .map_err(|e| format!("create dir: {}", e))?;
            fs::write(&profile_path, &profile)
                .map_err(|e| format!("write profile: {}", e))?;

            let status = std::process::Command::new("sandbox-exec")
                .arg("-f")
                .arg(&profile_path)
                .arg("--")
                .arg("sh")
                .arg("-c")
                .arg(&cmd_str)
                .current_dir(cwd)
                .status()
                .map_err(|e| format!("sandbox-exec failed: {}", e))?;

            Ok(status.code().unwrap_or(1))
        }

        SandboxCapability::LinuxLandlock { .. } => {
            // Try bubblewrap first
            let bwrap_check = std::process::Command::new("which")
                .arg("bwrap")
                .output();

            if let Ok(output) = bwrap_check {
                if output.status.success() {
                    // Use bwrap
                    let bwrap_args = linux::generate_bwrap_command(&policy.fence, cwd);
                    let full_cmd = format!("{} {}", bwrap_args, cmd_str);
                    let status = std::process::Command::new("sh")
                        .arg("-c")
                        .arg(&full_cmd)
                        .current_dir(cwd)
                        .status()
                        .map_err(|e| format!("bwrap failed: {}", e))?;
                    return Ok(status.code().unwrap_or(1));
                }
            }

            Err("bubblewrap (bwrap) not found. Install: apt install bubblewrap".to_string())
        }

        SandboxCapability::None => {
            Err("No sandbox available. Running unsandboxed is not supported.".to_string())
        }
    }
}
