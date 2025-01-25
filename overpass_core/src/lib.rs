// ./core/src/lib.rs

pub mod bitcoin;

pub mod rng;

pub mod api_ovp;
pub mod contracts;
pub mod db;
pub mod error;
pub mod logging;
pub mod models;
pub mod network;
pub mod services;
pub mod types;
pub mod utils;
pub mod zkp; // Add this line to expose the ZKP module
