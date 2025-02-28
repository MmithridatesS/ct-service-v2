use prism_keys::SigningKey;
use keystore_rs::{KeyChain, KeyStore};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

pub struct KeyManager {
    signing_keys: HashMap<String, SigningKey>
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            signing_keys: HashMap::new()
        }
    }

    pub fn add_key(&mut self, id: String, signing_key: SigningKey) -> Option<SigningKey> {
        self.signing_keys.insert(id, signing_key)
    }
    pub fn get_key(&self, id: String) -> Option<&SigningKey> {
        self.signing_keys.get(&id)
    }
}
