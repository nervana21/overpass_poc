// src/zkp/bitcoind_path.rs

use std::process::Command;

/// Returns a usable path to `bitcoind`, either from the `BITCOIND_PATH` env variable or by calling `which bitcoind`.
pub fn resolve_bitcoind_path() -> anyhow::Result<String> {
    if let Ok(path) = std::env::var("BITCOIND_PATH") {
        return Ok(path);
    }

    #[cfg(unix)]
    {
        if let Ok(output) = Command::new("which").arg("bitcoind").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(path);
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "`bitcoind` not found. Please set BITCOIND_PATH or install it and ensure it's in your PATH."
    ))
}
