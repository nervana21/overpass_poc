// ./src/logging/logger.rs

use log::{Level, LevelFilter, Metadata, SetLoggerError};

pub trait Logger {
    fn log(&self, level: &str, message: &str);
}

/// Custom Logger implementation that integrates with the `log` crate.
pub struct CustomLogger;

impl log::Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!(
                "[{}] {}: {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

impl Logger for CustomLogger {
    fn log(&self, level: &str, message: &str) {
        let log_level = match level.to_lowercase().as_str() {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => Level::Info,
        };

        log::logger().log(
            &log::Record::builder()
                .level(log_level)
                .target("ovp-client")
                .args(format_args!("{}", message))
                .build(),
        );
    }
}

/// Initializes the custom logger with the given level filter.
pub fn init_logger(level_filter: LevelFilter) -> Result<(), SetLoggerError> {
    log::set_logger(&CustomLogger).map(|()| log::set_max_level(level_filter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::LevelFilter;

    #[test]
    fn test_logger_log() {
        init_logger(LevelFilter::Debug).unwrap();
        let logger = CustomLogger;
        logger.log("info", "This is an info-level log");
        logger.log("debug", "This is a debug-level log");
        logger.log("warn", "This is a warn-level log");
        logger.log("error", "This is an error-level log");
        logger.log("trace", "This is a trace-level log");
    }

    #[test]
    fn test_custom_logger_integration() {
        init_logger(LevelFilter::Info).unwrap();
        log::info!("Testing info log through `log` crate");
        log::debug!("This debug log should not appear");
        log::warn!("Testing warn log through `log` crate");
    }
}

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::Local;

pub trait LogConfig {
    fn log_file(&self) -> &str;
}

pub struct FileLogger {
    config: Arc<Mutex<Box<dyn LogConfig>>>,
}

impl FileLogger {
    pub fn new(config: impl LogConfig + 'static) -> Self {
        Self {
            config: Arc::new(Mutex::new(Box::new(config))),
        }
    }

    /// Logs a message with a specified log level.
    pub fn log(&self, level: &str, message: &str) -> io::Result<()> {
        let config = self.config.lock().unwrap();
        let log_file = Path::new(config.log_file());
        if let Some(parent) = log_file.parent() {
            fs::create_dir_all(parent)?; // Ensure directory exists.
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_entry = format!("[{}][{}] {}\n", timestamp, level.to_uppercase(), message);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
        file.write_all(log_entry.as_bytes())
    }

    /// Convenience methods for different log levels
    pub fn info(&self, message: &str) {
        let _ = self.log("info", message);
    }

    pub fn warn(&self, message: &str) {
        let _ = self.log("warn", message);
    }

    pub fn error(&self, message: &str) {
        let _ = self.log("error", message);
    }
}
