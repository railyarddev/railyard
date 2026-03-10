use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, Duration};

const REMOTE_URL: &str = "https://github.com/railyarddev/railyard.git";
const CHECK_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 1 week
const BUILD_HASH: &str = env!("RAILYARD_GIT_HASH");

/// Check for updates. Two checks:
/// 1. Security tag — every session, <100ms. For emergency patches.
/// 2. Main branch — once per week. For normal updates.
/// Returns a message if an update exists.
pub fn check_for_update(cwd: &Path) -> Option<String> {
    // Always check for emergency security patches
    if let Some(msg) = check_security_tag() {
        return Some(msg);
    }

    // Weekly check for normal updates
    check_main_branch(cwd)
}

/// Check if a `security` tag exists on the remote that doesn't match our build.
/// Runs every session — single ref lookup is <100ms.
fn check_security_tag() -> Option<String> {
    if BUILD_HASH == "unknown" {
        return None;
    }

    let output = Command::new("git")
        .args(["ls-remote", REMOTE_URL, "refs/tags/security"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let security_hash = stdout.split_whitespace().next()?;

    // No security tag on remote — no emergency
    if security_hash.is_empty() {
        return None;
    }

    // If our build matches the security tag, we're already patched
    if security_hash.starts_with(BUILD_HASH) || BUILD_HASH.starts_with(security_hash) {
        return None;
    }

    Some(
        "⚠ A security patch for Railyard is available. \
         Run `cargo install --git https://github.com/railyarddev/railyard.git` to update immediately."
            .to_string(),
    )
}

/// Check if main branch has moved ahead of our build. Rate-limited to once per week.
fn check_main_branch(cwd: &Path) -> Option<String> {
    let marker = cwd.join(".railyard/last-update-check");

    // Rate limit: skip if checked recently
    if let Ok(meta) = fs::metadata(&marker) {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                if elapsed < CHECK_INTERVAL {
                    return None;
                }
            }
        }
    }

    // Touch the marker file regardless of outcome
    let _ = fs::create_dir_all(cwd.join(".railyard"));
    let _ = fs::write(&marker, "");

    if BUILD_HASH == "unknown" {
        return None;
    }

    let output = Command::new("git")
        .args(["ls-remote", REMOTE_URL, "refs/heads/main"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let remote_hash = String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .next()?
        .to_string();

    if remote_hash.starts_with(BUILD_HASH) || BUILD_HASH.starts_with(&remote_hash) {
        return None;
    }

    Some(
        "A new version of Railyard is available. \
         Run `cargo install --git https://github.com/railyarddev/railyard.git` to update."
            .to_string(),
    )
}
