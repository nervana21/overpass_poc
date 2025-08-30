pub mod node;

use std::fs;
use std::path::Path;

use anyhow::Result;
pub use node::{NodeConfig, OverpassNode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ClientStorage {
    storage_path: String,
}

impl ClientStorage {
    pub fn new(storage_path: impl AsRef<Path>) -> Result<Self> {
        let path = storage_path.as_ref().to_string_lossy().to_string();

        // Create storage directory if it doesn't exist
        if let Some(parent) = Path::new(&path).parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(Self { storage_path: path })
    }

    pub fn save_state<T: Serialize>(&self, channel_id: &str, state: &T) -> Result<()> {
        let state_string = serde_json::to_string_pretty(state)?;
        let file_path = format!("{}/channel-{}.json", self.storage_path, channel_id);
        fs::write(file_path, state_string)?;
        Ok(())
    }

    pub fn load_state<T: for<'de> Deserialize<'de>>(&self, channel_id: &str) -> Result<Option<T>> {
        let file_path = format!("{}/channel-{}.json", self.storage_path, channel_id);

        if !Path::new(&file_path).exists() {
            return Ok(None);
        }

        let state_string = fs::read_to_string(file_path)?;
        let state: T = serde_json::from_str(&state_string)?;
        Ok(Some(state))
    }

    pub fn list_channels(&self) -> Result<Vec<String>> {
        let mut channels = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.storage_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    if file_name.starts_with("channel-") && file_name.ends_with(".json") {
                        // Extract channel ID from filename
                        let channel_id = file_name
                            .strip_prefix("channel-")
                            .and_then(|s| s.strip_suffix(".json"))
                            .unwrap_or(&file_name)
                            .to_string();
                        channels.push(channel_id);
                    }
                }
            }
        }

        Ok(channels)
    }

    pub fn delete_channel(&self, channel_id: &str) -> Result<()> {
        let file_path = format!("{}/channel-{}.json", self.storage_path, channel_id);
        if Path::new(&file_path).exists() {
            fs::remove_file(file_path)?;
        }
        Ok(())
    }
}
