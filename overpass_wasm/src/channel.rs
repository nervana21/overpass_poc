use rand::RngCore;
use serde::Serialize;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature, Verifier};
use wasm_bindgen::prelude::*;
use serde_wasm_bindgen;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use rand::rngs::OsRng;

#[derive(Clone, Debug, PartialEq)]
pub struct Channel {
    pub nonce: u64,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[wasm_bindgen]
pub struct ChannelWrapper(Channel);

impl Serialize for Channel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Channel", 3)?;
        state.serialize_field("nonce", &self.nonce)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("signature", &self.signature)?;
        state.end()
    }
}

impl Channel {
    pub fn new(data: Vec<u8>) -> Self {
        let mut csprng = OsRng;
        let nonce = csprng.next_u64();
        Channel {
            nonce,
            data,
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, private_key: &[u8]) -> Result<(), JsValue> {
        let key_array: [u8; 32] = private_key.try_into()
            .map_err(|_| JsValue::from_str("Invalid private key length"))?;
        
        let signing_key = SigningKey::from_bytes(&key_array);
        let message = self.serialize_for_signing();
        self.signature = signing_key.sign(&message).to_bytes().to_vec();
        Ok(())
    }

    fn serialize_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn verify(&self, public_key: &[u8]) -> Result<bool, JsValue> {
        let key_array: [u8; 32] = public_key.try_into()
            .map_err(|_| JsValue::from_str("Invalid public key length"))?;
            
        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| JsValue::from_str("Invalid signature"))?;
            
        Ok(verifying_key.verify(&self.serialize_for_signing(), &signature).is_ok())
    }

    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.serialize_for_signing());
        hasher.finalize().to_vec()
    }
}

#[wasm_bindgen]
impl ChannelWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>) -> Self {
        ChannelWrapper(Channel::new(data))
    }

    #[wasm_bindgen]
    pub fn sign(&mut self, private_key: &[u8]) -> Result<(), JsValue> {
        self.0.sign(private_key)
    }

    #[wasm_bindgen]
    pub fn verify(&self, public_key: &[u8]) -> Result<bool, JsValue> {
        self.0.verify(public_key)
    }

    #[wasm_bindgen]
    pub fn hash(&self) -> Vec<u8> {
        self.0.hash()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u64 {
        self.0.nonce
    }

    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.0.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signature.clone()
    }
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let secret_bytes: [u8; 32] = {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    };
    
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    
    let keypair = (
        verifying_key.to_bytes().to_vec(),
        signing_key.to_bytes().to_vec()
    );
    
    serde_wasm_bindgen::to_value(&keypair)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}