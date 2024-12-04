// ./src/services/overpass_db.rs
use sled::{self, Db};
use anyhow::{Result, Context};

/// Wrapper around the sled database for managing Overpass states and transactions.
pub struct OverpassDB {
    db: Db,
}

impl OverpassDB {
    /// Creates a new instance of the OverpassDB.
    /// 
    /// # Arguments
    /// 
    /// * `path` - Path to the database directory.
    /// 
    /// # Panics
    /// 
    /// Will panic if the database cannot be opened.
    pub fn new(path: &str) -> Self {
        let db = sled::open(path).expect("Failed to open database");
        Self { db }
    }

    /// Retrieves a value from the database by key.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to look up.
    /// 
    /// # Returns
    /// 
    /// * `Some(Vec<u8>)` if the key exists.
    /// * `None` if the key does not exist or an error occurs.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .get(key)
            .context("Database get operation failed")
            .map(|opt| opt.map(|ivec| ivec.to_vec()))
    }

    /// Inserts a key-value pair into the database.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to insert.
    /// * `value` - The value to associate with the key.
    /// 
    /// # Returns
    /// 
    /// * `Some(Vec<u8>)` if the key previously existed, containing the old value.
    /// * `None` if the key is new.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .insert(key, value)
            .context("Database put operation failed")
            .map(|opt| opt.map(|ivec| ivec.to_vec()))
    }

    /// Deletes a key from the database.
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to delete.
    /// 
    /// # Returns
    /// 
    /// * `Some(Vec<u8>)` if the key existed, containing the old value.
    /// * `None` if the key did not exist.
    pub fn delete(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .remove(key)
            .context("Database delete operation failed")
            .map(|opt| opt.map(|ivec| ivec.to_vec()))
    }

    /// Retrieves a range of keys and their associated values.
    /// 
    /// # Arguments
    /// 
    /// * `start` - The starting key (inclusive).
    /// * `end` - The ending key (exclusive).
    /// 
    /// # Returns
    /// 
    /// An iterator over the keys and values within the range.
    pub fn scan(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut result = Vec::new();
        for item in self.db.range(start..end) {
            let (key, value) = item.context("Database range scan failed")?;
            result.push((key.to_vec(), value.to_vec()));
        }
        Ok(result)
    }

    /// Flushes all changes to disk.
    /// 
    /// Ensures that all changes made to the database are durable.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().context("Database flush failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DB_PATH: &str = "./test_db";

    fn setup_db() -> OverpassDB {
        // Ensure a clean state for tests
        let _ = std::fs::remove_dir_all(TEST_DB_PATH);
        OverpassDB::new(TEST_DB_PATH)
    }

    #[test]
    fn test_put_get_delete() {
        let db = setup_db();

        // Test put
        db.put(b"key1", b"value1").unwrap();
        db.put(b"key2", b"value2").unwrap();

        // Test get
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(b"key2").unwrap(), Some(b"value2".to_vec()));
        assert!(db.get(b"key3").unwrap().is_none());

        // Test delete
        assert_eq!(db.delete(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert!(db.get(b"key1").unwrap().is_none());
    }

    #[test]
    fn test_scan() {
        let db = setup_db();

        db.put(b"key1", b"value1").unwrap();
        db.put(b"key2", b"value2").unwrap();
        db.put(b"key3", b"value3").unwrap();

        let scanned = db.scan(b"key1", b"key3").unwrap();
        assert_eq!(scanned.len(), 2);
        assert_eq!(scanned[0], (b"key1".to_vec(), b"value1".to_vec()));
        assert_eq!(scanned[1], (b"key2".to_vec(), b"value2".to_vec()));
    }

    #[test]
    fn test_flush() {
        let db = setup_db();
        db.put(b"key", b"value").unwrap();
        db.flush().unwrap();
    }
}