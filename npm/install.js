#!/usr/bin/env node

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

const VERSION = "0.1.0";
const REPO = "railyarddev/railyard";
const BIN_DIR = path.join(__dirname, "bin");
const BIN_PATH = path.join(BIN_DIR, "railyard");

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();

  if (platform === "darwin" && arch === "arm64") return "aarch64-apple-darwin";
  if (platform === "darwin" && arch === "x64") return "x86_64-apple-darwin";
  if (platform === "linux" && arch === "x64") return "x86_64-unknown-linux-gnu";
  if (platform === "linux" && arch === "arm64")
    return "aarch64-unknown-linux-gnu";

  return null;
}

function tryCargoInstall() {
  console.log("  Building from source with cargo...");
  try {
    execSync("cargo install --git https://github.com/railyarddev/railyard.git", {
      stdio: "inherit",
    });

    // Find the cargo-installed binary and symlink it
    const cargobin = path.join(os.homedir(), ".cargo", "bin", "railyard");
    if (fs.existsSync(cargobin)) {
      fs.mkdirSync(BIN_DIR, { recursive: true });
      fs.symlinkSync(cargobin, BIN_PATH);
      return true;
    }
  } catch {
    // cargo install failed
  }
  return false;
}

function downloadRelease(target) {
  return new Promise((resolve, reject) => {
    const filename = `railyard-v${VERSION}-${target}.tar.gz`;
    const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${filename}`;

    console.log(`  Downloading ${filename}...`);

    const tmpFile = path.join(os.tmpdir(), filename);

    function follow(url, redirects) {
      if (redirects > 5) return reject(new Error("Too many redirects"));

      https
        .get(url, { headers: { "User-Agent": "railyard-npm" } }, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            return follow(res.headers.location, redirects + 1);
          }
          if (res.statusCode !== 200) {
            return reject(new Error(`Download failed: HTTP ${res.statusCode}`));
          }

          const file = fs.createWriteStream(tmpFile);
          res.pipe(file);
          file.on("finish", () => {
            file.close();
            resolve(tmpFile);
          });
        })
        .on("error", reject);
    }

    follow(url, 0);
  });
}

async function main() {
  console.log();
  console.log("  railyard install");
  console.log();

  // Check if already installed
  if (fs.existsSync(BIN_PATH)) {
    console.log("  Already installed.");
    return;
  }

  fs.mkdirSync(BIN_DIR, { recursive: true });

  const target = getPlatform();

  // Try downloading a prebuilt binary first
  if (target) {
    try {
      const tarball = await downloadRelease(target);
      execSync(`tar xzf "${tarball}" -C "${BIN_DIR}"`, { stdio: "pipe" });
      fs.chmodSync(BIN_PATH, 0o755);
      fs.unlinkSync(tarball);
      console.log("  Binary installed successfully.");
      postInstall();
      return;
    } catch (e) {
      console.log(`  No prebuilt binary available (${e.message})`);
    }
  }

  // Fallback: build from source
  if (tryCargoInstall()) {
    console.log("  Built from source successfully.");
    postInstall();
    return;
  }

  console.error();
  console.error("  Failed to install railyard.");
  console.error();
  console.error("  To install manually:");
  console.error("    cargo install --git https://github.com/railyarddev/railyard.git");
  console.error();
  process.exit(1);
}

function postInstall() {
  console.log();
  console.log("  Next steps:");
  console.log("    railyard install     — register hooks with Claude Code");
  console.log("    railyard configure   — interactive protection setup");
  console.log("    railyard status      — check current protection");
  console.log();
}

main().catch((e) => {
  console.error("  Install error:", e.message);
  process.exit(1);
});
