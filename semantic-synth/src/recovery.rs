//! In-process recovery store for the ReAct loop, mirroring the router recovery store.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Thread-safe in-memory store for recovering text elided during synthesis.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRecoveryStore {
    entries: Arc<RwLock<HashMap<String, String>>>,
}

impl InMemoryRecoveryStore {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store an elided text span under a recovery handle.
    pub fn store(&self, handle: &str, text: String) {
        if let Ok(mut map) = self.entries.write() {
            map.insert(handle.to_string(), text);
        }
    }

    /// Retrieve an original elided text span by handle.
    pub fn recover(&self, handle: &str) -> Option<String> {
        self.entries.read().ok()?.get(handle).cloned()
    }

    /// Check if a handle exists.
    pub fn contains(&self, handle: &str) -> bool {
        self.entries
            .read()
            .ok()
            .map(|m| m.contains_key(handle))
            .unwrap_or(false)
    }

    /// Number of stored originals.
    pub fn len(&self) -> usize {
        self.entries.read().ok().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
