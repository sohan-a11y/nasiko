//! Encrypted vault storage for Homomorph session symbol mappings.
//!
//! Never logs mappings in plaintext. Encrypted at rest using AES-256-GCM via `nasiko-secrets`.

use crate::surrogates::SessionSymbolTable;
use nasiko_secrets::{SecretsCrypto, SecretsError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Errors during vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("crypto error: {0}")]
    Crypto(#[from] SecretsError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Encrypted vault record ready for database persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    /// Session identifier.
    pub session_id: Uuid,
    /// Flow identifier (W3C traceparent trace-id).
    pub flow_id: String,
    /// Owner ID for multi-tenant isolation.
    pub owner_id: Uuid,
    /// Optional agent ID.
    pub agent_id: Option<Uuid>,
    /// Base64 AES-256-GCM encrypted serialized `SessionSymbolTable`.
    pub encrypted_mapping: String,
}

/// Encrypt a session symbol table into a vault record.
pub fn encrypt_session_table(
    session_id: Uuid,
    flow_id: &str,
    owner_id: Uuid,
    agent_id: Option<Uuid>,
    table: &SessionSymbolTable,
    crypto: &SecretsCrypto,
) -> Result<VaultRecord, VaultError> {
    let serialized = serde_json::to_string(table)?;
    let encrypted_mapping = crypto.encrypt(&serialized);

    Ok(VaultRecord {
        session_id,
        flow_id: flow_id.to_string(),
        owner_id,
        agent_id,
        encrypted_mapping,
    })
}

/// Decrypt an encrypted vault record back into a session symbol table.
pub fn decrypt_session_table(
    record: &VaultRecord,
    crypto: &SecretsCrypto,
) -> Result<SessionSymbolTable, VaultError> {
    let decrypted = crypto.decrypt(&record.encrypted_mapping)?;
    let table = serde_json::from_str(&decrypted)?;
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::SymbolKind;

    #[test]
    fn test_vault_encryption_roundtrip() {
        // Safe explicit 32-byte key derivation for unit testing
        let crypto =
            SecretsCrypto::for_backup_canary("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .expect("valid test key");
        let mut table = SessionSymbolTable::new();
        table.intern(
            "internal_api_secret_key",
            SymbolKind::Variable,
            b"salt-vault",
        );

        let session_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();

        let record = encrypt_session_table(
            session_id,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            owner_id,
            None,
            &table,
            &crypto,
        )
        .expect("encryption succeeded");

        // Ciphertext never contains plaintext symbol names
        assert!(!record.encrypted_mapping.contains("internal_api_secret_key"));

        let restored = decrypt_session_table(&record, &crypto).expect("decryption succeeded");
        assert_eq!(table, restored);
    }
}
