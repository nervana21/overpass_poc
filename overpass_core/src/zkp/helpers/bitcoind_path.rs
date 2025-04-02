// overpass_core/src/zkp/helpers/bitcoind_path.rs

use std::env;

/// Returns the BITCOIND_PATH environment variable or an error with helpful context.
/// Uses BITCOIND_VERSION_ALIAS if available to include a suggested startup command.
pub fn require_bitcoind_path() -> Result<String, String> {
    let alias = env::var("BITCOIND_VERSION_ALIAS").unwrap_or_else(|_| "<VERSION_ALIAS>".into());

    env::var("BITCOIND_PATH").map_err(|_| {
        format!(
            "BITCOIND_PATH environment variable must be set.\nHint: run ./run-bitcoind.sh start {} to start the node and see the export command.",
            alias
        )
    })
}
