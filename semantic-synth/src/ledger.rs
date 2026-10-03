//! Semantic ledger extraction across code, diff, log, and JSON payloads.

use crate::types::{LedgerItem, LedgerKind};
use nasiko_compress::ContentType;
use std::collections::HashSet;

/// Build the semantic ledger of must-preserve facts from the input payload.
pub fn extract_ledger(
    payload: &str,
    content_type: ContentType,
    anchors: &[String],
    enable_code_synth: bool,
) -> Vec<LedgerItem> {
    match content_type {
        ContentType::Code if enable_code_synth => extract_code_ledger(payload, anchors),
        ContentType::Diff => extract_diff_ledger(payload, anchors),
        ContentType::Log => extract_log_ledger(payload, anchors),
        ContentType::Json => extract_json_ledger(payload, anchors),
        _ => extract_generic_ledger(payload, anchors),
    }
}

/// Extract must-keep items from source code.
fn extract_code_ledger(code: &str, anchors: &[String]) -> Vec<LedgerItem> {
    let mut ledger = Vec::new();

    for (idx, line) in code.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // 1. Comments containing critical markers
        if (trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*'))
            && contains_marker_comment(trimmed)
        {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::MarkerComment,
            });
            continue;
        }

        // 2. Any line referencing an anchor
        if line_matches_any_anchor(line, anchors) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::AnchorMatch,
            });
            continue;
        }

        // 3. Imports and includes
        if is_code_import(trimmed) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::Import,
            });
            continue;
        }

        // 4. Definitions and signatures (fn, struct, enum, trait, class, def, interface)
        if is_code_signature(trimmed) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::Signature,
            });
            continue;
        }

        // 5. Guard / condition lines (if, match, assert, require, early return)
        if is_code_guard(trimmed) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::Guard,
            });
            continue;
        }

        // 6. Constants / static literals
        if is_code_constant(trimmed) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::Constant,
            });
        }
    }

    ledger
}

/// Extract must-keep items from unified diffs.
fn extract_diff_ledger(diff: &str, anchors: &[String]) -> Vec<LedgerItem> {
    let mut ledger = Vec::new();

    for (idx, line) in diff.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        // Hunk headers and enclosing function/class signatures
        if line.starts_with("@@") {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::DiffContext,
            });
            continue;
        }

        // Marker comments in diff hunks
        if contains_marker_comment(trimmed) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::MarkerComment,
            });
            continue;
        }

        // Any hunk line mentioning an anchor
        if line_matches_any_anchor(line, anchors) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::AnchorMatch,
            });
        }
    }

    ledger
}

/// Extract must-keep items from structured/unstructured logs.
fn extract_log_ledger(logs: &str, anchors: &[String]) -> Vec<LedgerItem> {
    let mut ledger = Vec::new();
    let mut seen_templates = HashSet::new();

    for (idx, line) in logs.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // 1. Any line referencing an anchor
        if line_matches_any_anchor(line, anchors) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::AnchorMatch,
            });
            continue;
        }

        // 2. State-change verbs
        if contains_state_change_verb(trimmed) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::StateChange,
            });
            continue;
        }

        // 3. Error and Warning log lines
        let upper = trimmed.to_ascii_uppercase();
        if upper.contains("ERROR")
            || upper.contains("WARN")
            || upper.contains("FATAL")
            || upper.contains("PANIC")
        {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::Guard,
            });
            continue;
        }

        // 4. Distinct message templates
        let template_sig = compute_log_template(trimmed);
        if seen_templates.insert(template_sig) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::MessageTemplate,
            });
        }
    }

    ledger
}

/// Extract must-keep items from JSON payloads.
fn extract_json_ledger(json_text: &str, anchors: &[String]) -> Vec<LedgerItem> {
    let mut ledger = Vec::new();

    for (idx, line) in json_text.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Retain structural boundaries and keys
        if trimmed == "{"
            || trimmed == "}"
            || trimmed == "["
            || trimmed == "]"
            || trimmed.ends_with('{')
            || trimmed.ends_with('[')
        {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::JsonStructure,
            });
            continue;
        }

        // Any array element or string containing an anchor
        if line_matches_any_anchor(line, anchors) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::AnchorMatch,
            });
        }
    }

    ledger
}

/// Generic ledger fallback for prose or mixed payloads.
fn extract_generic_ledger(text: &str, anchors: &[String]) -> Vec<LedgerItem> {
    let mut ledger = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        let line_num = idx + 1;
        if line_matches_any_anchor(line, anchors) {
            ledger.push(LedgerItem {
                line_number: line_num,
                content: line.to_string(),
                kind: LedgerKind::AnchorMatch,
            });
        }
    }

    ledger
}

fn line_matches_any_anchor(line: &str, anchors: &[String]) -> bool {
    for anchor in anchors {
        if !anchor.is_empty() && line.contains(anchor.as_str()) {
            return true;
        }
    }
    false
}

fn contains_marker_comment(s: &str) -> bool {
    let upper = s.to_ascii_uppercase();
    upper.contains("IMPORTANT")
        || upper.contains("NOTE")
        || upper.contains("WARNING")
        || upper.contains("SAFETY")
        || upper.contains("INVARIANT")
        || upper.contains("TODO")
        || upper.contains("FIXME")
        || upper.contains("MUST")
        || upper.contains("NEVER")
        || upper.contains("DO NOT")
}

fn contains_state_change_verb(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    for verb in [
        "started",
        "stopped",
        "invalidated",
        "evicted",
        "evict",
        "retry",
        "retrying",
        "timeout",
        "timed out",
        "rollback",
        "rolling back",
        "failed",
        "failure",
        "connected",
        "disconnected",
        "reloaded",
        "reload",
        "reloading",
        "reconfigured",
        "reconfig",
        "reindexing",
        "reindex",
    ] {
        if lower.contains(verb) {
            return true;
        }
    }
    false
}

fn is_code_import(s: &str) -> bool {
    s.starts_with("use ")
        || s.starts_with("import ")
        || s.starts_with("from ")
        || s.starts_with("require(")
        || s.starts_with("#include")
        || s.starts_with("package ")
}

fn is_code_signature(s: &str) -> bool {
    s.starts_with("fn ")
        || s.starts_with("pub fn ")
        || s.starts_with("pub async fn ")
        || s.starts_with("async fn ")
        || s.starts_with("struct ")
        || s.starts_with("pub struct ")
        || s.starts_with("enum ")
        || s.starts_with("pub enum ")
        || s.starts_with("trait ")
        || s.starts_with("pub trait ")
        || s.starts_with("impl ")
        || s.starts_with("class ")
        || s.starts_with("def ")
        || s.starts_with("async def ")
        || s.starts_with("interface ")
        || s.starts_with("type ")
        || s.starts_with("export function ")
        || s.starts_with("export const ")
        || s.starts_with("export class ")
        || s.starts_with("export interface ")
        || s.starts_with("func ")
}

fn is_code_guard(s: &str) -> bool {
    s.starts_with("if ")
        || s.starts_with("if (")
        || s.starts_with("else if ")
        || s.starts_with("match ")
        || s.starts_with("assert!(")
        || s.starts_with("assert_eq!(")
        || s.starts_with("assert ")
        || s.starts_with("require(")
        || s.starts_with("return ")
        || s.starts_with("return;")
        || s.starts_with("throw ")
        || s.starts_with("panic!(")
        || s.starts_with("bail!(")
}

fn is_code_constant(s: &str) -> bool {
    s.starts_with("const ")
        || s.starts_with("pub const ")
        || s.starts_with("static ")
        || s.starts_with("pub static ")
}

/// Compute a normalized template signature by masking variable numbers, IDs and timestamps (B2).
fn compute_log_template(line: &str) -> String {
    let mut template = String::with_capacity(line.len());
    for token in line.split_whitespace() {
        if is_timestamp(token) {
            template.push_str("<TS> ");
        } else if let Some((k, v)) = token.split_once('=') {
            if is_number(v) || is_id_token(v) || (v.len() >= 4 && (v.contains(':') || v.contains('-'))) {
                template.push_str(k);
                template.push_str("=<VAL> ");
            } else {
                template.push_str(token);
                template.push(' ');
            }
        } else if is_number(token) {
            template.push_str("<NUM> ");
        } else if token.len() >= 8 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            template.push_str("<HEX> ");
        } else if is_id_token(token) {
            template.push_str("<ID> ");
        } else {
            template.push_str(token);
            template.push(' ');
        }
    }
    template
}

fn is_timestamp(token: &str) -> bool {
    let t = token.trim_matches(|c: char| c == '[' || c == ']' || c == '(' || c == ')');
    if t.len() >= 8 {
        let first_is_digit = t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false);
        if first_is_digit {
            // ISO 8601: 2026-01-01... or time 12:00:00...
            if (t.contains('-') && t.contains(':'))
                || (t.contains('T') && t.contains(':'))
                || (t.len() == 10 && t.chars().filter(|&c| c == '-').count() == 2)
                || (t.chars().filter(|&c| c == ':').count() >= 2)
            {
                return true;
            }
        }
    }
    false
}

fn is_number(token: &str) -> bool {
    let t = token.trim_matches(|c: char| c == '[' || c == ']' || c == '(' || c == ')' || c == ',');
    !t.is_empty()
        && t.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-')
        && t.chars().any(|c| c.is_ascii_digit())
}

fn is_id_token(token: &str) -> bool {
    let t = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-');
    if t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        let has_digit = t.chars().any(|c| c.is_ascii_digit());
        let has_alpha = t.chars().any(|c| c.is_ascii_alphabetic());
        if has_digit && has_alpha {
            return true;
        }
    }
    false
}
