//! Egress forward transform pseudonymizing identifiers and protecting secrets.

use crate::policy::{HomomorphPolicy, SecretAction, TransformAction};
use crate::secrets::{SecretFinding, redact_secrets, scan_secrets};
use crate::surrogates::SessionSymbolTable;
use crate::symbols::extract_symbols;
use regex::Regex;

/// Outcome of a forward transform.
#[derive(Debug, Clone)]
pub struct ForwardResult {
    /// Transformed text safe for external model egress.
    pub text: String,
    /// Number of identifier replacements performed.
    pub replacements: usize,
    /// Secret findings detected.
    pub secrets: Vec<SecretFinding>,
    /// Whether the request should be blocked due to policy violations.
    pub blocked: bool,
}

/// Apply forward pseudonymization to payload text.
pub fn forward_transform(
    text: &str,
    table: &mut SessionSymbolTable,
    policy: &HomomorphPolicy,
    salt: &[u8],
) -> ForwardResult {
    // 1. Scan for secrets
    let secrets = scan_secrets(text);
    if !secrets.is_empty() && policy.secrets == SecretAction::Block {
        return ForwardResult {
            text: String::new(),
            replacements: 0,
            secrets,
            blocked: true,
        };
    }

    let intermediate = if !secrets.is_empty() && policy.secrets == SecretAction::Redact {
        redact_secrets(text, &secrets)
    } else {
        text.to_string()
    };

    if policy.internal_symbols == TransformAction::Preserve {
        return ForwardResult {
            text: intermediate,
            replacements: 0,
            secrets,
            blocked: false,
        };
    }

    // 2. Extract code symbols and intern them into the session symbol table
    let extracted = extract_symbols(&intermediate, policy);
    for sym in extracted {
        table.intern(&sym.name, sym.kind, salt);
    }

    if table.is_empty() {
        return ForwardResult {
            text: intermediate,
            replacements: 0,
            secrets,
            blocked: false,
        };
    }

    // 3. Word-boundary replacement of known symbols with surrogates
    // To prevent sub-word collisions, sort symbols by length descending
    let mut symbols_to_replace: Vec<(&String, &String)> = table
        .forward
        .iter()
        .map(|(k, v)| (k, &v.surrogate))
        .collect();
    symbols_to_replace.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

    let mut transformed = intermediate;
    let mut total_replacements = 0usize;

    for (original, surrogate) in symbols_to_replace {
        let pattern = format!(r"\b{}\b", regex::escape(original));
        if let Ok(re) = Regex::new(&pattern) {
            let count = re.find_iter(&transformed).count();
            if count > 0 {
                transformed = re.replace_all(&transformed, surrogate.as_str()).to_string();
                total_replacements += count;
            }
        }
    }

    ForwardResult {
        text: transformed,
        replacements: total_replacements,
        secrets,
        blocked: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_transform_replaces_symbols_not_substrings() {
        let policy = HomomorphPolicy::default();
        let mut table = SessionSymbolTable::new();
        let salt = b"salt-123";

        let code = r#"
            pub fn compute_subtotal(amount: f64) -> f64 {
                let factor = 1.05;
                amount * factor
            }
        "#;

        let res = forward_transform(code, &mut table, &policy, salt);
        assert!(!res.blocked);
        assert!(res.replacements > 0);

        // Substring check: 'factor' replaced, but not if inside another word
        assert!(!res.text.contains("compute_subtotal"));
        assert!(!res.text.contains("factor"));
        assert!(res.text.contains("fn_"));
        assert!(res.text.contains("var_"));
    }

    #[test]
    fn test_forward_transform_blocks_secrets() {
        let policy = HomomorphPolicy::default(); // defaults to SecretAction::Block
        let mut table = SessionSymbolTable::new();
        let salt = b"salt-123";

        let code = "let api_key = \"sk-1234567890abcdef1234567890abcdef\";";
        let res = forward_transform(code, &mut table, &policy, salt);
        assert!(res.blocked);
        assert_eq!(res.secrets.len(), 1);
    }
}
