// overpass_core/src/zkp/helpers/bitcoind_path.rs

/// Returns the hardcoded path to the bitcoind binary.
pub fn require_bitcoind_path() -> Result<String, String> {
    Ok("/Users/bitnode/bitcoin-versions/v28/bitcoin-28.1/bin/bitcoind".to_string())
}
