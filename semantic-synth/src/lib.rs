//! Semantic Synthesizer — ledger-verified context synthesis with fail-closed guarantees.
//!
//! Replaces blind truncation and lossy elision with semantic-ledger verified synthesis.
//! Facts that must be kept (anchors, symbol signatures, guard assertions, causal logs,
//! critical business rules) are extracted into a semantic ledger before compression.
//! The output is verified to contain every ledger item verbatim; if any item is dropped,
//! the engine fails closed and emits the untouched original payload.
//!
//! Every elided span is given a counted marker and a deterministic recovery handle
//! compatible with Nasiko's recovery store.

#![forbid(unsafe_code)]
#![deny(
    clippy::string_slice,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod anchors;
pub mod ledger;
pub mod recovery;
pub mod slice;
pub mod synthesize;
pub mod types;

pub use anchors::extract_anchors;
pub use ledger::extract_ledger;
pub use recovery::InMemoryRecoveryStore;
pub use synthesize::synthesize;
pub use types::{ElidedSpan, LedgerItem, LedgerKind, RecallReport, SynthPolicy, Synthesized};

#[cfg(test)]
mod tests {
    use super::*;
    use nasiko_compress::{Level, Policy, TypeMask};

    fn test_policy<'a>() -> SynthPolicy<'a> {
        SynthPolicy {
            compress: Policy {
                enabled: true,
                min_bytes: 50,
                types: TypeMask::ALL,
                level: Level::Aggressive,
                dry_run: false,
                max_input_bytes: 500_000,
                recovery_ref: None,
            },
            enable_code_synth: true,
            recovery_prefix: Some("test_rec".into()),
        }
    }

    #[test]
    fn test_regression_diff_business_rule_comment_preserved() {
        // Verified failure from CONTEXT: a business-rule comment 15 lines from diff change
        // is dropped by nasiko-compress at all levels.
        let mut diff_payload = String::from(
            "--- a/billing.rs\n+++ b/billing.rs\n@@ -10,35 +10,35 @@ impl Billing {\n",
        );
        diff_payload.push_str(
            "     // NOTE: Critical invariant - never allow discount > 50% for standard tier\n",
        );
        for i in 1..=20 {
            diff_payload.push_str(&format!("     let line_{i} = calculate_subtotal({i});\n"));
        }
        diff_payload.push_str("-    let total = apply_discount(subtotal, 0.10);\n");
        diff_payload.push_str("+    let total = apply_discount(subtotal, 0.15);\n");
        for i in 21..=35 {
            diff_payload.push_str(&format!("     audit_entry({i});\n"));
        }

        let anchors = vec!["apply_discount".to_string(), "invariant".to_string()];
        let policy = test_policy();
        let res = synthesize(&diff_payload, &anchors, &policy);

        assert!(
            res.text
                .contains("Critical invariant - never allow discount > 50%")
        );
        assert!(res.text.contains("apply_discount"));
        assert!(res.recall_report.verified);
    }

    #[test]
    fn test_regression_log_causal_info_preserved() {
        // Verified failure from CONTEXT: a causal INFO log line mid-log is dropped by nasiko-compress.
        let mut log_payload = String::new();
        log_payload.push_str("2026-10-02T10:00:00Z [INFO] system started cleanly\n");
        for i in 1..=40 {
            log_payload.push_str(&format!(
                "2026-10-02T10:00:{:02}Z [DEBUG] worker heartbeat id={i}\n",
                i % 60
            ));
        }
        log_payload.push_str(
            "2026-10-02T10:01:00Z [INFO] session cache invalidated for user_9876 after timeout\n",
        );
        for i in 41..=80 {
            log_payload.push_str(&format!(
                "2026-10-02T10:01:{:02}Z [DEBUG] worker heartbeat id={i}\n",
                i % 60
            ));
        }

        let anchors = vec!["user_9876".to_string(), "invalidated".to_string()];
        let policy = test_policy();
        let res = synthesize(&log_payload, &anchors, &policy);

        assert!(res.text.contains("session cache invalidated for user_9876"));
        assert!(res.recall_report.verified);
    }

    #[test]
    fn test_regression_json_middle_anchor_preserved() {
        // Verified failure from CONTEXT: the middle object of a homogeneous JSON array is dropped by nasiko-compress.
        let mut json_payload = String::from("[\n");
        for i in 1..=30 {
            if i == 15 {
                json_payload.push_str("  {\"id\": 15, \"name\": \"target_tenant_special\", \"status\": \"critical_alert\"},\n");
            } else {
                json_payload.push_str(&format!(
                    "  {{\"id\": {i}, \"name\": \"tenant_{i}\", \"status\": \"active\"}},\n"
                ));
            }
        }
        json_payload
            .push_str("  {\"id\": 31, \"name\": \"tenant_31\", \"status\": \"active\"}\n]\n");

        let anchors = vec![
            "target_tenant_special".to_string(),
            "critical_alert".to_string(),
        ];
        let policy = test_policy();
        let res = synthesize(&json_payload, &anchors, &policy);

        assert!(res.text.contains("target_tenant_special"));
        assert!(res.text.contains("critical_alert"));
        assert!(res.recall_report.verified);
    }

    #[test]
    fn test_idempotence() {
        let text = "[⋯ 12 lines elided · recover: synth_12345678 ⋯]\nfn example() {}";
        let anchors = vec!["example".to_string()];
        let policy = test_policy();
        let res = synthesize(text, &anchors, &policy);

        assert_eq!(res.text, text);
        assert!(!res.was_synthesized);
    }

    #[test]
    fn test_code_skeleton_synthesis() {
        let code = r#"
use std::collections::HashMap;

// IMPORTANT: Do not modify this constant without audit approval
pub const MAX_RETRIES: usize = 5;

pub struct Engine {
    state: HashMap<String, u32>,
}

impl Engine {
    pub fn new() -> Self {
        let mut state = HashMap::new();
        state.insert("alpha_0".to_string(), 0);
        state.insert("alpha_1".to_string(), 1);
        state.insert("alpha_2".to_string(), 2);
        state.insert("alpha_3".to_string(), 3);
        state.insert("alpha_4".to_string(), 4);
        state.insert("alpha_5".to_string(), 5);
        state.insert("alpha_6".to_string(), 6);
        state.insert("alpha_7".to_string(), 7);
        state.insert("alpha_8".to_string(), 8);
        state.insert("alpha_9".to_string(), 9);
        state.insert("beta_0".to_string(), 10);
        state.insert("beta_1".to_string(), 11);
        state.insert("beta_2".to_string(), 12);
        state.insert("beta_3".to_string(), 13);
        state.insert("beta_4".to_string(), 14);
        Self { state }
    }

    pub fn process(&self, key: &str) -> Option<u32> {
        if key.is_empty() {
            return None;
        }
        self.state.get(key).copied()
    }
}
"#;
        let anchors = vec!["MAX_RETRIES".to_string(), "process".to_string()];
        let policy = test_policy();
        let res = synthesize(code, &anchors, &policy);
        assert!(res.was_synthesized);
        assert!(res.text.contains("pub const MAX_RETRIES: usize = 5;"));
        assert!(res.text.contains("pub fn process"));
        assert!(res.text.contains("IMPORTANT: Do not modify this constant"));
        assert!(res.text.contains("lines elided"));
        assert!(res.text.len() < code.len());
    }
}
