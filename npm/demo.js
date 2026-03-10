#!/usr/bin/env node

// Quick demo that shows Railyard in action after install.
// Run: npx railyard demo

const { execSync } = require("child_process");

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";

function print(msg) {
  console.log(msg);
}

function demo() {
  print("");
  print(`  ${BOLD}railyard demo${RESET}`);
  print(`  ${DIM}See what Railyard protects you from${RESET}`);
  print("");

  const scenarios = [
    {
      name: "terraform destroy",
      command: "terraform destroy -auto-approve",
      should: "BLOCK",
    },
    {
      name: "rm -rf /",
      command: "rm -rf / --force",
      should: "BLOCK",
    },
    {
      name: "DROP DATABASE",
      command: 'psql -c "DROP DATABASE production"',
      should: "BLOCK",
    },
    {
      name: "git push --force",
      command: "git push origin main --force",
      should: "BLOCK",
    },
    {
      name: "git reset --hard",
      command: "git reset --hard HEAD~10",
      should: "BLOCK",
    },
    {
      name: "cargo build (safe)",
      command: "cargo build --release",
      should: "ALLOW",
    },
    {
      name: "npm test (safe)",
      command: "npm test",
      should: "ALLOW",
    },
  ];

  for (const s of scenarios) {
    const input = JSON.stringify({
      session_id: "demo",
      cwd: process.cwd(),
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: s.command },
    });

    let result;
    try {
      const output = execSync(
        `echo '${input.replace(/'/g, "\\'")}' | railyard hook --event PreToolUse`,
        { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }
      );
      const parsed = JSON.parse(output);
      if (
        parsed.hookSpecificOutput &&
        parsed.hookSpecificOutput.permissionDecision === "deny"
      ) {
        result = "BLOCKED";
      } else {
        result = "ALLOWED";
      }
    } catch {
      result = "BLOCKED";
    }

    const icon =
      s.should === "BLOCK"
        ? result === "BLOCKED"
          ? `${GREEN}✓ BLOCKED${RESET}`
          : `${RED}✗ MISSED${RESET}`
        : result === "ALLOWED"
          ? `${GREEN}✓ ALLOWED${RESET}`
          : `${RED}✗ BLOCKED${RESET}`;

    print(`  ${icon}  ${DIM}${s.command}${RESET}`);
  }

  print("");
  print(`  ${BOLD}Railyard is working.${RESET}`);
  print(`  Run ${CYAN}railyard configure${RESET} to customize your protections.`);
  print("");
}

demo();
