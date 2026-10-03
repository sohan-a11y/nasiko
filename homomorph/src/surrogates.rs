//! Deterministic surrogate generation with casing preservation and collision checking.

use crate::symbols::SymbolKind;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

/// Surrogate information for an identifier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SurrogateInfo {
    /// Original symbol name.
    pub original: String,
    /// Generated surrogate pseudonym.
    pub surrogate: String,
    /// Symbol kind.
    pub kind: String,
}

/// Bidirectional symbol mapping table for a session or repository.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionSymbolTable {
    /// Mapping from original identifier to surrogate.
    pub forward: HashMap<String, SurrogateInfo>,
    /// Reverse mapping from surrogate to original identifier.
    pub reverse: HashMap<String, String>,
}

impl SessionSymbolTable {
    /// Create a new empty session symbol table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of mapped symbols.
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Lookup surrogate for an original identifier.
    pub fn get_surrogate(&self, original: &str) -> Option<&str> {
        self.forward
            .get(original)
            .map(|info| info.surrogate.as_str())
    }

    /// Lookup original identifier for a surrogate.
    pub fn get_original(&self, surrogate: &str) -> Option<&str> {
        self.reverse.get(surrogate).map(|s| s.as_str())
    }

    /// Check if a name is a known surrogate in this session.
    pub fn is_surrogate(&self, token: &str) -> bool {
        self.reverse.contains_key(token)
    }

    /// Intern a symbol, generating or returning its deterministic surrogate.
    pub fn intern(&mut self, original: &str, kind: SymbolKind, salt: &[u8]) -> &SurrogateInfo {
        if self.forward.contains_key(original) {
            return self.forward.get(original).unwrap_or_else(|| unreachable!());
        }

        let mut counter = 0usize;
        let surrogate = loop {
            let candidate = generate_surrogate(original, kind, salt, counter);
            // Collision check: cannot collide with an existing surrogate or known original
            if !self.reverse.contains_key(&candidate) && !self.forward.contains_key(&candidate) {
                break candidate;
            }
            counter += 1;
        };

        let kind_str = match kind {
            SymbolKind::Function => "function",
            SymbolKind::Type => "type",
            SymbolKind::Variable => "variable",
            SymbolKind::Table => "table",
        };

        let info = SurrogateInfo {
            original: original.to_string(),
            surrogate: surrogate.clone(),
            kind: kind_str.to_string(),
        };

        self.reverse.insert(surrogate, original.to_string());
        self.forward.insert(original.to_string(), info);

        self.forward.get(original).unwrap_or_else(|| unreachable!())
    }
}

/// Generate a deterministic, syntactically valid surrogate preserving casing style and kind.
pub fn generate_surrogate(original: &str, kind: SymbolKind, salt: &[u8], counter: usize) -> String {
    let mut mac = HmacSha256::new_from_slice(salt).unwrap_or_else(|_| {
        HmacSha256::new_from_slice(b"nasiko-default-homomorph-salt-2026")
            .unwrap_or_else(|_| unreachable!())
    });

    mac.update(original.as_bytes());
    if counter > 0 {
        mac.update(&counter.to_le_bytes());
    }
    let result = mac.finalize().into_bytes();
    let hash_hex = hex::encode(result);
    let short_hash = &hash_hex[..6];

    let style = detect_casing_style(original);

    match style {
        CasingStyle::ScreamingSnake => {
            let prefix = match kind {
                SymbolKind::Function => "FN_",
                SymbolKind::Type => "TY_",
                SymbolKind::Variable => "VAR_",
                SymbolKind::Table => "TBL_",
            };
            format!("{prefix}{}", short_hash.to_ascii_uppercase())
        }
        CasingStyle::PascalCase => {
            let prefix = match kind {
                SymbolKind::Function => "Fn",
                SymbolKind::Type => "Ty",
                SymbolKind::Variable => "Var",
                SymbolKind::Table => "Tbl",
            };
            format!("{prefix}{short_hash}")
        }
        CasingStyle::CamelCase => {
            let prefix = match kind {
                SymbolKind::Function => "fn",
                SymbolKind::Type => "ty",
                SymbolKind::Variable => "var",
                SymbolKind::Table => "tbl",
            };
            let capitalized = capitalize_first(short_hash);
            format!("{prefix}{capitalized}")
        }
        CasingStyle::SnakeCase | CasingStyle::Other => {
            let prefix = kind.prefix();
            format!("{prefix}{short_hash}")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CasingStyle {
    SnakeCase,
    ScreamingSnake,
    PascalCase,
    CamelCase,
    Other,
}

fn detect_casing_style(s: &str) -> CasingStyle {
    if s.is_empty() {
        return CasingStyle::Other;
    }

    let has_underscore = s.contains('_');
    let has_uppercase = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = s.chars().any(|c| c.is_ascii_lowercase());

    if has_underscore && !has_lowercase && has_uppercase {
        CasingStyle::ScreamingSnake
    } else if has_underscore || (!has_uppercase && has_lowercase) {
        CasingStyle::SnakeCase
    } else if has_uppercase && has_lowercase {
        if s.chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
        {
            CasingStyle::PascalCase
        } else {
            CasingStyle::CamelCase
        }
    } else {
        CasingStyle::Other
    }
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_surrogate_generation_and_casing() {
        let salt = b"test-salt-secret-123";

        // snake_case function -> fn_xxxxxx
        let s1 = generate_surrogate("calculate_discount", SymbolKind::Function, salt, 0);
        assert!(s1.starts_with("fn_"));

        // PascalCase type -> TyXxxxxx
        let s2 = generate_surrogate("BillingManager", SymbolKind::Type, salt, 0);
        assert!(s2.starts_with("Ty"));

        // SCREAMING_SNAKE variable -> VAR_XXXXXX
        let s3 = generate_surrogate("MAX_RETRIES", SymbolKind::Variable, salt, 0);
        assert!(s3.starts_with("VAR_"));

        // Deterministic across multiple calls
        let s1_again = generate_surrogate("calculate_discount", SymbolKind::Function, salt, 0);
        assert_eq!(s1, s1_again);
    }

    #[test]
    fn test_session_symbol_table() {
        let salt = b"session-salt-abc";
        let mut table = SessionSymbolTable::new();

        let info = table.intern("secret_billing_func", SymbolKind::Function, salt);
        let surrogate = info.surrogate.clone();

        assert_eq!(
            table.get_surrogate("secret_billing_func"),
            Some(surrogate.as_str())
        );
        assert_eq!(table.get_original(&surrogate), Some("secret_billing_func"));
        assert!(table.is_surrogate(&surrogate));
    }
}
