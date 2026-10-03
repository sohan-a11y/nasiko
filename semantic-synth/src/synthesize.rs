//! Core synthesis and fail-closed verification pipeline.

use crate::ledger::extract_ledger;
use crate::types::{ElidedSpan, LedgerItem, RecallReport, SynthPolicy, Synthesized};
use nasiko_compress::{ContentType, contains_marker, detect};
use std::collections::HashSet;

/// Execute semantic synthesis over a payload with ledger guarantees.
pub fn synthesize<'a>(
    payload: &'a str,
    anchors: &[String],
    policy: &SynthPolicy<'a>,
) -> Synthesized {
    let content_type = detect(payload);
    let ledger = extract_ledger(payload, content_type, anchors, policy.enable_code_synth);

    // Idempotency: payloads already carrying an elision marker are returned untouched
    if contains_marker(payload)
        || !policy.compress.enabled
        || payload.len() < policy.compress.min_bytes
    {
        return unchanged(payload, ledger, anchors, false);
    }

    let mut elided_spans = Vec::new();
    let candidate = match content_type {
        ContentType::Code if policy.enable_code_synth => {
            synthesize_code_skeleton(payload, &ledger, &mut elided_spans, policy)
        }
        _ => synthesize_structured(payload, &ledger, content_type, &mut elided_spans, policy),
    };

    // Verification step (the core fail-closed property):
    // 1. Every ledger item must appear verbatim in the candidate output
    let mut preserved_items = 0;
    for item in &ledger {
        if candidate.contains(&item.content) {
            preserved_items += 1;
        }
    }
    let all_ledger_preserved = preserved_items == ledger.len();

    // 2. Every anchor present in input must be present in output
    let mut anchors_in_input = 0;
    let mut anchors_preserved = 0;
    for anchor in anchors {
        if !anchor.is_empty() && payload.contains(anchor.as_str()) {
            anchors_in_input += 1;
            if candidate.contains(anchor.as_str()) {
                anchors_preserved += 1;
            }
        }
    }
    let all_anchors_preserved = anchors_preserved == anchors_in_input;

    let shrunk = candidate.len() < payload.len();

    // If verification passes, return synthesized result
    if all_ledger_preserved && all_anchors_preserved && shrunk {
        Synthesized {
            text: candidate,
            ledger,
            recall_report: RecallReport {
                total_ledger_items: preserved_items,
                preserved_items,
                anchors_input: anchors_in_input,
                anchors_preserved,
                verified: true,
            },
            elided_spans,
            was_synthesized: true,
            was_fallback: false,
        }
    } else {
        // Fail-closed fallback: return original untouched
        unchanged(payload, ledger, anchors, true)
    }
}

/// Synthesize a code skeleton keeping signatures, imports, markers, and guards.
fn synthesize_code_skeleton(
    code: &str,
    ledger: &[LedgerItem],
    elided_spans: &mut Vec<ElidedSpan>,
    policy: &SynthPolicy<'_>,
) -> String {
    let mut kept_line_indices = HashSet::new();
    for item in ledger {
        kept_line_indices.insert(item.line_number);
    }

    let mut out = String::with_capacity(code.len() / 2);
    let mut eliding_lines = Vec::new();
    let mut elision_start_line = 0;

    for (idx, line) in code.lines().enumerate() {
        let line_num = idx + 1;
        if kept_line_indices.contains(&line_num) {
            // Flush any pending elision block
            if !eliding_lines.is_empty() {
                let elision_text = eliding_lines.join("\n");
                let handle = mint_handle(policy, elision_start_line, code, &elision_text);
                let marker = format!(
                    "[⋯ {} lines elided · recover: {} ⋯]\n",
                    eliding_lines.len(),
                    handle
                );
                if marker.len() < elision_text.len() {
                    elided_spans.push(ElidedSpan {
                        handle: handle.clone(),
                        start_line: elision_start_line,
                        end_line: line_num - 1,
                        original_text: elision_text,
                    });
                    out.push_str(&marker);
                } else {
                    out.push_str(&elision_text);
                    out.push('\n');
                }
                eliding_lines.clear();
            }
            out.push_str(line);
            out.push('\n');
        } else {
            if eliding_lines.is_empty() {
                elision_start_line = line_num;
            }
            eliding_lines.push(line);
        }
    }

    // Flush trailing elision block
    if !eliding_lines.is_empty() {
        let elision_text = eliding_lines.join("\n");
        let handle = mint_handle(policy, elision_start_line, code, &elision_text);
        let marker = format!(
            "[⋯ {} lines elided · recover: {} ⋯]\n",
            eliding_lines.len(),
            handle
        );
        if marker.len() < elision_text.len() {
            elided_spans.push(ElidedSpan {
                handle: handle.clone(),
                start_line: elision_start_line,
                end_line: code.lines().count(),
                original_text: elision_text,
            });
            out.push_str(&marker);
        } else {
            out.push_str(&elision_text);
        }
    }

    out
}

/// Synthesize diff, log, JSON, or search results via structural compression + ledger re-injection.
fn synthesize_structured(
    payload: &str,
    ledger: &[LedgerItem],
    _kind: ContentType,
    elided_spans: &mut Vec<ElidedSpan>,
    policy: &SynthPolicy<'_>,
) -> String {
    // Run base structural compression
    let compressed = nasiko_compress::compress(payload, &policy.compress);
    if !compressed.is_changed() {
        return payload.to_string();
    }
    let comp_text = compressed.text();

    let payload_lines: Vec<&str> = payload.lines().collect();
    let comp_lines: Vec<&str> = comp_text.lines().collect();

    let mut out = String::with_capacity(comp_text.len());
    let mut p_idx = 0;

    for (c_idx, c_line) in comp_lines.iter().enumerate() {
        let trimmed = c_line.trim();
        if trimmed.starts_with("[⋯ ") && trimmed.ends_with(" ⋯]") {
            // Find the next kept line in comp_lines to know where this elision ends in payload_lines
            let mut next_kept = None;
            for next_c in &comp_lines[c_idx + 1..] {
                let next_trimmed = next_c.trim();
                if !(next_trimmed.starts_with("[⋯ ") && next_trimmed.ends_with(" ⋯]")) {
                    next_kept = Some(*next_c);
                    break;
                }
            }

            let end_p_idx = match next_kept {
                Some(target) => {
                    let mut found = payload_lines.len();
                    for (idx, line) in payload_lines.iter().enumerate().skip(p_idx) {
                        if line == &target {
                            found = idx;
                            break;
                        }
                    }
                    found
                }
                None => payload_lines.len(),
            };

            let start_line = p_idx + 1;
            let end_line = end_p_idx.max(start_line);
            let elision_text = if p_idx < end_p_idx && p_idx < payload_lines.len() {
                payload_lines[p_idx..end_p_idx.min(payload_lines.len())].join("\n")
            } else {
                String::new()
            };

            let handle = mint_handle(policy, start_line, payload, &elision_text);
            elided_spans.push(ElidedSpan {
                handle: handle.clone(),
                start_line,
                end_line,
                original_text: elision_text,
            });

            // Extract the base marker description without any prior recover handle
            let inner = trimmed
                .strip_prefix("[⋯ ")
                .and_then(|s| s.strip_suffix(" ⋯]"))
                .unwrap_or(trimmed);
            let clean_desc = inner.split(" · recover:").next().unwrap_or(inner);
            let indent = c_line.strip_suffix(trimmed).unwrap_or("");
            out.push_str(&format!("{indent}[⋯ {clean_desc} · recover: {handle} ⋯]\n"));

            p_idx = end_p_idx;
        } else {
            // Find where this kept line is in payload_lines and advance p_idx past it
            for (idx, line) in payload_lines.iter().enumerate().skip(p_idx) {
                if line == c_line {
                    p_idx = idx + 1;
                    break;
                }
            }
            out.push_str(c_line);
            out.push('\n');
        }
    }

    // Now check which ledger items are missing in output
    let missing_items: Vec<&LedgerItem> = ledger
        .iter()
        .filter(|item| !out.contains(&item.content))
        .collect();

    if !missing_items.is_empty() {
        out.push_str("\n[⋯ Semantic Ledger Re-injections ⋯]\n");
        for item in missing_items {
            let handle = mint_handle(policy, item.line_number, payload, &item.content);
            elided_spans.push(ElidedSpan {
                handle: handle.clone(),
                start_line: item.line_number,
                end_line: item.line_number,
                original_text: item.content.clone(),
            });
            out.push_str(&format!(
                "[⋯ line {}: {} · recover: {} ⋯]\n",
                item.line_number, item.content, handle
            ));
        }
    }

    if !payload.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }

    out
}

fn unchanged(
    payload: &str,
    ledger: Vec<LedgerItem>,
    anchors: &[String],
    was_fallback: bool,
) -> Synthesized {
    let mut anchors_in_input = 0;
    for anchor in anchors {
        if !anchor.is_empty() && payload.contains(anchor.as_str()) {
            anchors_in_input += 1;
        }
    }

    Synthesized {
        text: payload.to_string(),
        ledger: ledger.clone(),
        recall_report: RecallReport {
            total_ledger_items: ledger.len(),
            preserved_items: ledger.len(),
            anchors_input: anchors_in_input,
            anchors_preserved: anchors_in_input,
            verified: true,
        },
        elided_spans: Vec::new(),
        was_synthesized: false,
        was_fallback,
    }
}

fn mint_handle(policy: &SynthPolicy<'_>, line: usize, payload: &str, content: &str) -> String {
    if let Some(ref prefix) = policy.recovery_prefix {
        // FNV-1a hash of prefix, line, payload hash, and content hash (B4: prevent collision across entries)
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in prefix.as_bytes().iter().chain(line.to_string().as_bytes()) {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        // Incorporate payload length and hash so distinct payloads/entries never collide
        hash ^= payload.len() as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
        for byte in payload.as_bytes().iter().step_by(16.max(payload.len() / 64)) {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        for byte in content.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        format!("{prefix}_{:08x}", hash as u32)
    } else {
        // Router-compatible UUID handle
        uuid::Uuid::new_v4().to_string()
    }
}
