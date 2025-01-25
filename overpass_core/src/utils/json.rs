// ./src/utils/json.rs
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonValue {
    pub(crate) value: serde_json::Value,
}

impl JsonValue {
    pub fn new(value: serde_json::Value) -> Self {
        Self { value }
    }

    pub fn as_str(&self) -> Option<&str> {
        self.value.as_str()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.value.as_u64()
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.value.as_i64()
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.value.as_f64()
    }

    pub fn as_bool(&self) -> Option<bool> {
        self.value.as_bool()
    }

    pub fn as_array(&self) -> Option<&Vec<serde_json::Value>> {
        self.value.as_array()
    }
}
