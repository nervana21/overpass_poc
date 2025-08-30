// File: src/storage_node/node.rs
use crate::bitcoin::BitcoinClient;

#[derive(Debug, Clone)]
pub struct BitcoinConfig {
    pub rpc_url: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub port: u16,
    pub max_connections: usize,
}

pub struct NodeConfig {
    pub storage_path: String,
    pub bitcoin_config: BitcoinConfig,
    pub network_config: NetworkConfig,
}

pub struct OverpassNode {
    _bitcoin: BitcoinClient,
}
