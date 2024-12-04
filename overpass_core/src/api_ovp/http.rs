use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
struct ChannelConfig {
    initial_balance: u64,
    security_bits: usize,
}

#[derive(Serialize, Deserialize)]
struct StateUpdate {
    nonce: u64,
    balance: u64,
    merkle_root: [u8; 32],
    cell_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct OtherHTLCParameters {
    amount: u64,
    receiver: [u8; 20],
    hash_lock: [u8; 32],
    timeout_height: u32,
}

#[derive(Serialize, Deserialize)]
struct HTLCState {
    lock_amount: u64,
    lock_script_hash: [u8; 32],
    lock_height: u64,
    pubkey_hash: [u8; 20],
    sequence: u32,
    nonce: u64,
    htlc_params: String,
    stealth_address: String,
}

#[derive(Serialize, Deserialize)]
struct OtherWalletState {
    encrypted: bool,
    network: String,
    stealth_keys: Option<StealthKeyPair>,
}

#[derive(Serialize, Deserialize)]
struct StealthKeyPair {
    scan_key: String,
    spend_key: String,
}

#[derive(Serialize, Deserialize)]
struct OtherChannelState {
    balances: Vec<u64>,
    nonce: u64,
}


/// A module for handling HTTP requests.
pub mod http {
    use axum::{
        body::{Body, Bytes},
        http::{Response, StatusCode, HeaderName, HeaderValue},
        response::IntoResponse,
    };
    use std::collections::HashMap;

    /// A struct representing an HTTP response with a status code, headers, and a body.
    #[derive(Debug, Clone, PartialEq)]
    pub struct HttpResponse {
        pub status_code: StatusCode,
        pub headers: HashMap<String, String>,
        pub body: Bytes,
    }

    impl HttpResponse {
        /// Creates a new `HttpResponse` with the given status code, headers, and body.
        pub fn new(status_code: StatusCode, headers: HashMap<String, String>, body: Bytes) -> Self {
            Self {
                status_code,
                headers,
                body,
            }
        }

        // Creates a new `HttpResponse` with the given status code, headers, and body.
        pub fn ok(body: Bytes) -> Self {
            Self {
                status_code: StatusCode::OK,
                headers: HashMap::new(),
                body,
            }
        }
    }

    impl IntoResponse for HttpResponse {
        fn into_response(self) -> Response<Body> {
            let mut response = Response::new(Body::from(self.body));
            *response.status_mut() = self.status_code;
            for (key, value) in self.headers {
                response.headers_mut().insert(
                    HeaderName::from_bytes(key.as_bytes()).unwrap(),
                    HeaderValue::from_str(&value).unwrap()
                );
            }
            response
        }
    }
}