// File: overpass_core/src/node.rs

use crate::{
    storage::PersistentStateStorage,
    network::ChannelNetwork,
    bitcoin::BitcoinNetworkClient,
};
use anyhow::Result;
use std::time::Duration;
use tokio::select;

pub struct NodeConfig {
    pub storage_path: String,
    pub bitcoin_config: BitcoinConfig,
    pub network_config: NetworkConfig,
}

pub struct OverpassNode {
    storage: PersistentStateStorage,
    network: ChannelNetwork,
    bitcoin: BitcoinNetworkClient,
}

// Implementation continues as shown above...