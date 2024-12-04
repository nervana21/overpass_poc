use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use toml;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub log_file: String,
}

impl Config {
    /// Creates a new `Config` with default values.
    pub fn new() -> Self {
        Self {
            log_level: "info".to_string(),
            log_file: "./log/log.txt".to_string(),
        }
    }

    /// Loads the configuration from `config.toml`. If the file doesn't exist,
    /// it returns the default configuration.
    pub fn load() -> io::Result<Self> {
        let path = Path::new("./config.toml");
        if path.exists() {
            let contents = fs::read_to_string(path)?;
            let config = toml::from_str(&contents).unwrap_or_else(|_| {
                eprintln!("Failed to parse config.toml, using default config.");
                Self::new()
            });
            Ok(config)
        } else {
            Ok(Self::new())
        }
    }

    /// Saves the current configuration to `config.toml`.
    pub fn save(&self) -> io::Result<()> {
        let path = Path::new("./config.toml");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?; // Ensure directory exists.
        }

        let contents = toml::to_string(self).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(path, contents)
    }

    /// Sets the log level.
    pub fn set_log_level(&mut self, log_level: &str) {
        self.log_level = log_level.to_string();
    }

    /// Sets the log file path.
    pub fn set_log_file(&mut self, log_file: &str) {
        self.log_file = log_file.to_string();
    }

    /// Gets the current log level.
    pub fn get_log_level(&self) -> &str {
        &self.log_level
    }

    /// Gets the current log file path.
    pub fn get_log_file(&self) -> &str {
        &self.log_file
    }
}

/// A thread-safe logger implementation.
pub struct Logger {
    config: Arc<Mutex<Config>>,
}

impl Logger {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
        }
    }

    /// Logs a message with a specified log level.
    pub fn log(&self, level: &str, message: &str) {
        let config = self.config.lock().unwrap();
        let log_file = Path::new(&config.log_file);
        if let Some(parent) = log_file.parent() {
            fs::create_dir_all(parent).ok(); // Ensure directory exists.
        }

        let log_entry = format!("[{}] {}\n", level.to_uppercase(), message);
        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(log_entry.as_bytes()) {
                    eprintln!("Failed to write to log file: {}", e);
                }
            }
            Err(e) => eprintln!("Failed to open log file: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_load_default() {
        let config = Config::new();
        assert_eq!(config.get_log_level(), "info");
        assert_eq!(config.get_log_file(), "./log/log.txt");
    }

    #[test]
    fn test_config_save_and_load() {
        let mut config = Config::new();
        config.set_log_level("debug");
        config.set_log_file("./log/debug.log");
        config.save().unwrap();

        let loaded_config = Config::load().unwrap();
        assert_eq!(loaded_config.get_log_level(), "debug");
        assert_eq!(loaded_config.get_log_file(), "./log/debug.log");
    }

    #[test]
    fn test_logger_log() {
        let config = Config::new();
        let logger = Logger::new(config);
        logger.log("info", "Test log message");
        assert!(Path::new("./log/log.txt").exists());
    }
}
