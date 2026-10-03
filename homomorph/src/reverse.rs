//! Ingress reverse transform restoring original identifiers and handling streaming chunks.

use crate::surrogates::SessionSymbolTable;
use regex::Regex;
use std::sync::LazyLock;

/// Errors during reverse transformation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReverseError {
    /// Detected a surrogate-looking pattern that has no mapping in the session table.
    #[error("unmapped surrogate token detected: {0}")]
    UnmappedSurrogate(String),
}

static SURROGATE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:fn_|ty_|var_|tbl_|FN_|TY_|VAR_|TBL_|Fn|Ty|Var|Tbl)[0-9a-fA-F]{12}\b")
        .unwrap_or_else(|_| unreachable!())
});

/// Reverse all surrogates in text back to original identifiers.
///
/// Fail closed: if any surrogate pattern is unmapped in the session table,
/// returns `ReverseError::UnmappedSurrogate`.
pub fn reverse_transform(text: &str, table: &SessionSymbolTable) -> Result<String, ReverseError> {
    if text.is_empty() {
        return Ok(String::new());
    }

    // 1. Check for unmapped surrogates (fail closed)
    for m in SURROGATE_PATTERN.find_iter(text) {
        let token = m.as_str();
        if !table.reverse.contains_key(token) {
            return Err(ReverseError::UnmappedSurrogate(token.to_string()));
        }
    }

    if table.is_empty() {
        return Ok(text.to_string());
    }

    // 2. Replace surrogates with original identifiers
    // Sort by surrogate length descending to prevent prefix collisions
    let mut surrogates: Vec<(&String, &String)> = table.reverse.iter().collect();
    surrogates.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

    let mut result = text.to_string();
    for (surrogate, original) in surrogates {
        let pattern = format!(r"\b{}\b", regex::escape(surrogate));
        if let Ok(re) = Regex::new(&pattern) {
            result = re.replace_all(&result, original.as_str()).to_string();
        }
    }

    Ok(result)
}

/// Streaming holdback buffer to ensure surrogates split across SSE chunk boundaries
/// are not prematurely emitted before completion.
#[derive(Debug, Clone)]
pub struct StreamingHoldbackBuffer {
    buffer: String,
    max_holdback: usize,
}

impl Default for StreamingHoldbackBuffer {
    fn default() -> Self {
        Self::new(32) // Surrogates are typically 15-18 chars (e.g. `fn_123456789abc`)
    }
}

impl StreamingHoldbackBuffer {
    /// Create a new holdback buffer with the given maximum window.
    pub fn new(max_holdback: usize) -> Self {
        Self {
            buffer: String::new(),
            max_holdback,
        }
    }

    /// Push an incoming SSE text chunk and return the safe-to-emit reversed text.
    pub fn push(
        &mut self,
        chunk: &str,
        table: &SessionSymbolTable,
    ) -> Result<String, ReverseError> {
        self.buffer.push_str(chunk);

        if self.buffer.len() <= self.max_holdback {
            return Ok(String::new());
        }

        // Find a safe word boundary to split behind the max_holdback window
        let raw_target = self.buffer.len().saturating_sub(self.max_holdback);
        let mut split_target = raw_target;
        while split_target > 0 && !self.buffer.is_char_boundary(split_target) {
            split_target -= 1;
        }

        let mut split_point = split_target;

        // Walk backwards to find whitespace or punctuation
        while split_point > 0 {
            if let Some(c) = self
                .buffer
                .get(..split_point)
                .and_then(|s| s.chars().next_back())
            {
                if c.is_whitespace()
                    || c == ';'
                    || c == ','
                    || c == '.'
                    || c == '('
                    || c == ')'
                    || c == '{'
                    || c == '}'
                    || c == '['
                    || c == ']'
                    || c == ':'
                    || c == '\n'
                    || c == '\r'
                {
                    break;
                }
                split_point = split_point.saturating_sub(c.len_utf8());
                while split_point > 0 && !self.buffer.is_char_boundary(split_point) {
                    split_point -= 1;
                }
            } else {
                break;
            }
        }

        if split_point == 0 {
            // No convenient whitespace boundary found yet, hold until buffer grows further
            if self.buffer.len() > self.max_holdback * 3 {
                split_point = split_target;
            } else {
                return Ok(String::new());
            }
        }

        let ready = match self.buffer.get(..split_point) {
            Some(r) => r,
            None => return Ok(String::new()),
        };
        let reversed = reverse_transform(ready, table)?;
        self.buffer = self.buffer.get(split_point..).unwrap_or("").to_string();

        Ok(reversed)
    }

    /// Flush all remaining content at the end of the stream.
    pub fn finish(mut self, table: &SessionSymbolTable) -> Result<String, ReverseError> {
        let reversed = reverse_transform(&self.buffer, table)?;
        self.buffer.clear();
        Ok(reversed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::forward_transform;
    use crate::policy::HomomorphPolicy;

    #[test]
    fn test_round_trip_reversibility() {
        let policy = HomomorphPolicy::default();
        let mut table = SessionSymbolTable::new();
        let salt = b"salt-rev-123";

        let original_code = r#"
            pub fn execute_transaction(balance: u64) -> u64 {
                let fee = 5;
                balance + fee
            }
        "#;

        let fwd = forward_transform(original_code, &mut table, &policy, salt);
        assert!(!fwd.text.contains("execute_transaction"));

        let rev = reverse_transform(&fwd.text, &table).expect("reverse succeeded");
        assert_eq!(rev.trim(), original_code.trim());
    }

    #[test]
    fn test_unmapped_surrogate_fails_closed() {
        let table = SessionSymbolTable::new();
        let fake_surrogate = "let res = fn_abcdef012345();";

        let err = reverse_transform(fake_surrogate, &table).unwrap_err();
        assert_eq!(
            err,
            ReverseError::UnmappedSurrogate("fn_abcdef012345".to_string())
        );
    }

    #[test]
    fn test_streaming_holdback_buffer_splits() {
        let policy = HomomorphPolicy::default();
        let mut table = SessionSymbolTable::new();
        let salt = b"streaming-salt";

        let code = "pub fn secret_worker() { let counter = 1; }";
        let fwd = forward_transform(code, &mut table, &policy, salt);

        // Feed chunks that split a surrogate right in the middle
        let mut stream = StreamingHoldbackBuffer::new(16);
        let mut reconstructed = String::new();

        for chunk in fwd.text.as_bytes().chunks(4) {
            let chunk_str = std::str::from_utf8(chunk).unwrap();
            let out = stream.push(chunk_str, &table).expect("push succeeded");
            reconstructed.push_str(&out);
        }
        let final_chunk = stream.finish(&table).expect("finish succeeded");
        reconstructed.push_str(&final_chunk);

        assert_eq!(reconstructed, code);
    }
}
