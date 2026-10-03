//! Claude Code Edit tool fidelity and patch validation.

use crate::reverse::{ReverseError, reverse_transform};
use crate::surrogates::SessionSymbolTable;
use serde::{Deserialize, Serialize};

/// Arguments for Claude Code's Edit tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeEditArgs {
    /// File path to edit.
    pub path: String,
    /// Exact string in original file to be replaced.
    pub old_string: String,
    /// Replacement string.
    pub new_string: String,
}

/// Errors during patch application and validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EditError {
    #[error("reverse transform failed: {0}")]
    Reverse(#[from] ReverseError),
    #[error("old_string was not found verbatim in original file content")]
    OldStringNotFound,
    #[error("old_string occurs multiple times ({0} matches) in file")]
    AmbiguousMatch(usize),
    #[error("patch validation failed: residual surrogates detected in patched code: {0}")]
    ResidualSurrogates(String),
}

/// Audit record for an applied edit (hashes and counts only, never plaintext secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditAuditRecord {
    pub path: String,
    pub old_hash: String,
    pub new_hash: String,
    pub replacements_count: usize,
    pub passed_validation: bool,
}

/// Reverse surrogate-space Claude Edit tool arguments back to original-space arguments.
pub fn reverse_claude_edit(
    surrogate_args: &ClaudeEditArgs,
    table: &SessionSymbolTable,
) -> Result<ClaudeEditArgs, EditError> {
    let reversed_old = reverse_transform(&surrogate_args.old_string, table)?;
    let reversed_new = reverse_transform(&surrogate_args.new_string, table)?;

    Ok(ClaudeEditArgs {
        path: surrogate_args.path.clone(),
        old_string: reversed_old,
        new_string: reversed_new,
    })
}

/// Apply a reversed Claude Edit call to original file content and validate.
///
/// Ensures:
/// 1. `old_string` matches the original file byte-for-byte (unique occurrence).
/// 2. The patched content contains NO residual surrogates.
/// 3. Returns the patched content and an audit record.
pub fn apply_and_validate_edit(
    original_file_content: &str,
    reversed_edit: &ClaudeEditArgs,
    table: &SessionSymbolTable,
) -> Result<(String, EditAuditRecord), EditError> {
    let matches: Vec<_> = original_file_content
        .match_indices(&reversed_edit.old_string)
        .collect();

    if matches.is_empty() {
        return Err(EditError::OldStringNotFound);
    }
    if matches.len() > 1 {
        return Err(EditError::AmbiguousMatch(matches.len()));
    }

    let patched =
        original_file_content.replacen(&reversed_edit.old_string, &reversed_edit.new_string, 1);

    // Validate that no residual surrogates from the model remain in the patched code
    for surrogate in table.reverse.keys() {
        if patched.contains(surrogate.as_str()) {
            return Err(EditError::ResidualSurrogates(surrogate.clone()));
        }
    }

    use sha2::{Digest, Sha256};
    let old_hash = hex::encode(Sha256::digest(original_file_content.as_bytes()));
    let new_hash = hex::encode(Sha256::digest(patched.as_bytes()));

    let audit = EditAuditRecord {
        path: reversed_edit.path.clone(),
        old_hash,
        new_hash,
        replacements_count: 1,
        passed_validation: true,
    };

    Ok((patched, audit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::forward_transform;
    use crate::policy::HomomorphPolicy;

    #[test]
    fn test_claude_edit_tool_fidelity() {
        let policy = HomomorphPolicy::default();
        let mut table = SessionSymbolTable::new();
        let salt = b"claude-edit-salt";

        let original_file = r#"
            pub fn compute_interest(principal: f64, rate: f64) -> f64 {
                let interest_rate = rate * 0.01;
                principal * interest_rate
            }
        "#;

        // Forward transform the file so the model receives surrogate names
        let _fwd = forward_transform(original_file, &mut table, &policy, salt);

        // Find the surrogate names created for `compute_interest` and `interest_rate`
        let fn_surrogate = table.get_surrogate("compute_interest").unwrap();
        let var_surrogate = table.get_surrogate("interest_rate").unwrap();

        // Model emits a Claude Code Edit call in surrogate space:
        let model_edit_call = ClaudeEditArgs {
            path: "finance.rs".into(),
            old_string: format!("principal * {var_surrogate}"),
            new_string: format!("(principal * {var_surrogate}) + 1.0"),
        };

        // Router ingress: reverse edit call back to original names
        let reversed_edit = reverse_claude_edit(&model_edit_call, &table).expect("reversed edit");

        assert_eq!(reversed_edit.old_string, "principal * interest_rate");
        assert_eq!(
            reversed_edit.new_string,
            "(principal * interest_rate) + 1.0"
        );

        // Apply to original file: old_string matches byte-for-byte!
        let (patched, audit) = apply_and_validate_edit(original_file, &reversed_edit, &table)
            .expect("applied and validated");

        assert!(audit.passed_validation);
        assert!(patched.contains("(principal * interest_rate) + 1.0"));
        assert!(!patched.contains(fn_surrogate));
        assert!(!patched.contains(var_surrogate));
    }
}
