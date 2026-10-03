//! Policy definitions for Homomorph identifier pseudonymization and privacy filtering.

use serde::{Deserialize, Serialize};

/// Action to take on sensitive items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransformAction {
    /// Transform with reversible pseudonymization.
    #[default]
    Transform,
    /// Preserve the original verbatim.
    Preserve,
}

/// Action to take on code comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CommentAction {
    /// Preserve comments as-is.
    #[default]
    Preserve,
    /// Pseudonymize identifiers inside comments.
    Transform,
    /// Strip comments entirely from egress payloads.
    Strip,
}

/// Action to take when hardcoded secrets or credentials are discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecretAction {
    /// Block the request immediately with an audit finding.
    #[default]
    Block,
    /// Replace the secret with an irreversible `[REDACTED:kind]` token.
    Redact,
}

/// Policy governing Homomorph identifier pseudonymization, paths, literals, and secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomomorphPolicy {
    /// Action for internal functions, classes, types, and variables.
    #[serde(default)]
    pub internal_symbols: TransformAction,

    /// Action for database table and column names.
    #[serde(default)]
    pub database_schema: TransformAction,

    /// Public API names or glob patterns that must NEVER be renamed (e.g. `std::*`, `serde::*`).
    #[serde(default)]
    pub public_api: Vec<String>,

    /// Action for string literals in code.
    #[serde(default = "default_preserve_action")]
    pub string_literals: TransformAction,

    /// Action for comments in code.
    #[serde(default)]
    pub comments: CommentAction,

    /// Action when credentials / private keys are detected.
    #[serde(default)]
    pub secrets: SecretAction,

    /// Action for file paths.
    #[serde(default = "default_preserve_action")]
    pub paths: TransformAction,
}

fn default_preserve_action() -> TransformAction {
    TransformAction::Preserve
}

impl Default for HomomorphPolicy {
    fn default() -> Self {
        Self {
            internal_symbols: TransformAction::Transform,
            database_schema: TransformAction::Transform,
            public_api: vec![
                "std::*".into(),
                "core::*".into(),
                "alloc::*".into(),
                "serde::*".into(),
                "tokio::*".into(),
                "axum::*".into(),
                "sqlx::*".into(),
                "os.*".into(),
                "sys.*".into(),
                "json.*".into(),
                "math.*".into(),
                "react".into(),
                "express".into(),
                "fmt.*".into(),
                "net.*".into(),
                "http.*".into(),
            ],
            string_literals: TransformAction::Preserve,
            comments: CommentAction::Preserve,
            secrets: SecretAction::Block,
            paths: TransformAction::Preserve,
        }
    }
}

impl HomomorphPolicy {
    /// Check whether a symbol name is protected by public API rules.
    pub fn is_public_api(&self, name: &str) -> bool {
        for pattern in &self.public_api {
            if pattern == name {
                return true;
            }
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                if name.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = HomomorphPolicy::default();
        assert_eq!(policy.internal_symbols, TransformAction::Transform);
        assert_eq!(policy.database_schema, TransformAction::Transform);
        assert_eq!(policy.secrets, SecretAction::Block);
        assert!(policy.is_public_api("std::collections::HashMap"));
        assert!(!policy.is_public_api("internal_billing_secret"));
    }
}
