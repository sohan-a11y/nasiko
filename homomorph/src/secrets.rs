//! Secret and credential detection with redaction and blocking.

use regex::Regex;
use std::sync::LazyLock;

/// Finding of a hardcoded credential or secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFinding {
    /// Kind of secret detected.
    pub kind: &'static str,
    /// Byte range in the original text.
    pub start: usize,
    pub end: usize,
    /// Masked snippet for audit logs (never full secret).
    pub audit_snippet: String,
}

static API_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // sk-..., ghp_..., AKIA..., glpat-..., xoxb-...
    Regex::new(r"(?i)\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16}|glpat-[a-zA-Z0-9_-]{20,}|xoxb-[a-zA-Z0-9_-]{20,})\b")
        .unwrap_or_else(|_| unreachable!())
});

static PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN ([A-Z ]+)?PRIVATE KEY-----[\s\S]*?-----END ([A-Z ]+)?PRIVATE KEY-----")
        .unwrap_or_else(|_| unreachable!())
});

static ENV_SECRET_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[:=]\s*([^\s\r\n]{8,})")
        .unwrap_or_else(|_| unreachable!())
});

/// Scan text for secrets and credentials.
pub fn scan_secrets(text: &str) -> Vec<SecretFinding> {
    let mut findings = Vec::new();

    // 1. Private keys
    for m in PRIVATE_KEY_REGEX.find_iter(text) {
        findings.push(SecretFinding {
            kind: "private_key",
            start: m.start(),
            end: m.end(),
            audit_snippet: "-----BEGIN PRIVATE KEY...-----".to_string(),
        });
    }

    // 2. Known API key provider formats
    for m in API_KEY_REGEX.find_iter(text) {
        let snippet = format!("{}...", &m.as_str()[..8.min(m.as_str().len())]);
        findings.push(SecretFinding {
            kind: "api_key",
            start: m.start(),
            end: m.end(),
            audit_snippet: snippet,
        });
    }

    // 3. .env and assignment secrets
    for caps in ENV_SECRET_REGEX.captures_iter(text) {
        if let Some(val_match) = caps.get(2) {
            let val = val_match.as_str();
            // Filter out obvious false positives like dummy defaults
            if val != "true"
                && val != "false"
                && val != "null"
                && val != "undefined"
                && !val.starts_with("${")
            {
                let snippet = format!("{}...", &val[..4.min(val.len())]);
                findings.push(SecretFinding {
                    kind: "env_secret",
                    start: val_match.start(),
                    end: val_match.end(),
                    audit_snippet: snippet,
                });
            }
        }
    }

    // Sort by start position and deduplicate overlapping spans
    findings.sort_by_key(|f| f.start);
    let mut deduped: Vec<SecretFinding> = Vec::new();
    for f in findings {
        if deduped.last().is_some_and(|last| f.start < last.end) {
            continue;
        }
        deduped.push(f);
    }
    deduped
}

/// Redact secrets in text, replacing each with `[REDACTED:kind]`.
pub fn redact_secrets(text: &str, findings: &[SecretFinding]) -> String {
    if findings.is_empty() {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut cursor = 0usize;

    for finding in findings {
        if finding.start < cursor {
            continue; // Skip overlapping
        }
        if finding.start > cursor {
            result.push_str(&text[cursor..finding.start]);
        }
        result.push_str(&format!("[REDACTED:{}]", finding.kind));
        cursor = finding.end;
    }

    if cursor < text.len() {
        result.push_str(&text[cursor..]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_detection_and_redaction() {
        let payload = r#"
            DATABASE_PASSWORD=SuperSecretDbPassword123!
            export STRIPE_API_KEY=sk-test123456789012345678901234567890
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3
            -----END PRIVATE KEY-----
            regular_text = 42
        "#;

        let findings = scan_secrets(payload);
        assert!(!findings.is_empty());

        let redacted = redact_secrets(payload, &findings);
        assert!(!redacted.contains("SuperSecretDbPassword123!"));
        assert!(!redacted.contains("sk-test1234567890"));
        assert!(!redacted.contains("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3"));
        assert!(redacted.contains("[REDACTED:env_secret]"));
        assert!(redacted.contains("[REDACTED:api_key]"));
        assert!(redacted.contains("[REDACTED:private_key]"));
    }
}
