//! Offline deterministic evaluation of needle survival across compression approaches.
//!
//! Generates 500 realistic payloads across Diffs, Logs, JSON, Code, and Multi-turn turns,
//! each containing planted task-critical "needles" (business-rule comments, causal state changes,
//! critical tenant JSON records, constraint definitions).
//!
//! Evaluates:
//! (a) Uncompressed baseline
//! (b) nasiko-compress structural compression
//! (c) nasiko-semantic-synth ledger-verified synthesis

use nasiko_compress::{Level, Policy, TypeMask};
use nasiko_semantic_synth::{SynthPolicy, extract_anchors, synthesize};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PayloadType {
    Diff,
    Log,
    Json,
    Code,
    MultiTurn,
}

impl PayloadType {
    fn as_label(self) -> &'static str {
        match self {
            PayloadType::Diff => "Diff",
            PayloadType::Log => "Log",
            PayloadType::Json => "JSON",
            PayloadType::Code => "Code",
            PayloadType::MultiTurn => "MultiTurn",
        }
    }
}

struct EvalCase {
    payload_type: PayloadType,
    payload: String,
    needle: String,
    anchors: Vec<String>,
}

fn generate_corpus(_rng: &mut StdRng, total_cases: usize) -> Vec<EvalCase> {
    let mut cases = Vec::with_capacity(total_cases);

    for i in 0..total_cases {
        let p_type = match i % 5 {
            0 => PayloadType::Diff,
            1 => PayloadType::Log,
            2 => PayloadType::Json,
            3 => PayloadType::Code,
            _ => PayloadType::MultiTurn,
        };

        match p_type {
            PayloadType::Diff => {
                // Real git diff: business-rule comment 16 lines above change so structural compress elides it.
                let needle = format!("// INVARIANT: Max discount rate strictly capped at 25% for tier {i}");
                let mut p = format!(
                    "diff --git a/pricing_{i}.rs b/pricing_{i}.rs\nindex abc123..def456 100644\n--- a/pricing_{i}.rs\n+++ b/pricing_{i}.rs\n@@ -1,60 +1,60 @@\n"
                );
                p.push_str(&format!(" {needle}\n"));
                for d in 0..16 {
                    p.push_str(&format!(" let intermediate_{d} = buffer[{d}];\n"));
                }
                p.push_str("-let rate = 0.05;\n+let rate = 0.10;\n");
                for d in 0..16 {
                    p.push_str(&format!(" post_process_{d}();\n"));
                }
                // Realistic query that does not quote the needle ID
                let query = "Review this change to the pricing discount rate calculation";
                let anchors = extract_anchors(query);
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: format!("Max discount rate strictly capped at 25% for tier {i}"),
                    anchors,
                });
            }
            PayloadType::Log => {
                // Background logs + causal state-change event + downstream error.
                let needle = format!("2026-10-02 12:35:00 INFO cache entry evicted by job=nightly-reindex-{i}");
                let mut p = String::new();
                for l in 0..30 {
                    p.push_str(&format!(
                        "2026-10-02 12:{:02}:{:02} INFO handled request id={l} status=200\n",
                        l % 60,
                        (l * 2) % 60
                    ));
                }
                p.push_str(&format!("{needle}\n"));
                for l in 31..65 {
                    p.push_str(&format!(
                        "2026-10-02 12:{:02}:{:02} INFO handled request id={l} status=200\n",
                        l % 60,
                        (l * 2) % 60
                    ));
                }
                p.push_str(&format!(
                    "2026-10-02 12:59:00 ERROR stale read on key=user:{i}\n"
                ));
                // Realistic query about the symptom that does not quote the needle or causal event
                let query = format!("Why did user {i} get a stale read?");
                let anchors = extract_anchors(&query);
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: format!("cache entry evicted by job=nightly-reindex-{i}"),
                    anchors,
                });
            }
            PayloadType::Json => {
                // Large JSON array where needle is in the middle elided slice; query targets domain role.
                let needle = format!("\"target_id\": \"privileged_record_{i}\"");
                let mut p = String::from("[\n");
                for idx in 0..35 {
                    if idx == 17 {
                        p.push_str(&format!(
                            "  {{\"index\": {idx}, {needle}, \"role\": \"administrator\", \"status\": \"active\"}},\n"
                        ));
                    } else {
                        p.push_str(&format!(
                            "  {{\"index\": {idx}, \"target_id\": \"regular_{idx}\", \"role\": \"operator\", \"status\": \"active\"}},\n"
                        ));
                    }
                }
                p.push_str("  {\"index\": 36, \"target_id\": \"tail\", \"role\": \"guest\", \"status\": \"inactive\"}\n]\n");
                // Realistic query asking about administrator privileges; does not quote the needle ID
                let query = "Audit access permissions for administrator accounts";
                let anchors = extract_anchors(query);
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: needle.clone(),
                    anchors,
                });
            }
            PayloadType::Code => {
                // Source code with critical safety invariant and functions with multi-line bodies.
                let needle = format!("// SAFETY: Memory barrier must be acquired before updating driver state {i}");
                let mut p = String::from("pub struct DriverState {\n");
                p.push_str(&format!("    {needle}\n"));
                p.push_str("    flags: u32,\n");
                p.push_str("}\n\nimpl DriverState {\n");
                for m in 0..25 {
                    p.push_str(&format!(
                        "    pub fn operation_{m}(&self) -> u32 {{\n        let mut accumulator = self.flags;\n        for step in 0..10 {{\n            accumulator = accumulator.wrapping_add(step * {m});\n        }}\n        accumulator\n    }}\n"
                    ));
                }
                p.push_str("}\n");
                // Realistic query asking about synchronization without quoting needle ID
                let query = "Explain how DriverState manages concurrent access and synchronization";
                let anchors = extract_anchors(query);
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: format!("Memory barrier must be acquired before updating driver state {i}"),
                    anchors,
                });
            }
            PayloadType::MultiTurn => {
                // Agent conversation history where needle is a system/user policy constraint.
                let needle = format!("CONSTRAINT: Agent must not write outside user workspace directory /app/data_{i}");
                let mut p = format!("Turn 1: User says: {needle}\n");
                for t in 2..20 {
                    p.push_str(&format!(
                        "Turn {t}: Assistant answered step {t} output and ran tool\n"
                    ));
                }
                // Realistic query asking about restrictions without quoting needle ID
                let query = "What are the sandbox workspace restrictions?";
                let anchors = extract_anchors(query);
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: format!("workspace directory /app/data_{i}"),
                    anchors,
                });
            }
        }
    }

    cases
}

#[derive(Default)]
struct TypeStats {
    total: usize,
    orig_bytes: usize,
    comp_bytes: usize,
    comp_needles: usize,
    synth_bytes: usize,
    synth_needles: usize,
    synth_fallbacks: usize,
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    let cases = generate_corpus(&mut rng, 500);

    let compress_policy = Policy {
        enabled: true,
        min_bytes: 20,
        types: TypeMask::ALL,
        level: Level::Balanced,
        dry_run: false,
        max_input_bytes: 500_000,
        recovery_ref: None,
    };

    let synth_policy = SynthPolicy {
        compress: compress_policy,
        enable_code_synth: true,
        recovery_prefix: Some("eval_rec".into()),
    };

    let mut uncompressed_bytes = 0usize;
    let mut compress_bytes = 0usize;
    let mut synth_bytes = 0usize;

    let mut uncompressed_needles = 0usize;
    let mut compress_needles = 0usize;
    let mut synth_needles = 0usize;
    let mut synth_fallbacks = 0usize;

    let mut type_stats: std::collections::BTreeMap<PayloadType, TypeStats> =
        std::collections::BTreeMap::new();

    for case in &cases {
        let orig_len = case.payload.len();
        uncompressed_bytes += orig_len;
        uncompressed_needles += 1;

        // (b) nasiko-compress
        let compressed = nasiko_compress::compress(&case.payload, &compress_policy);
        let comp_text = compressed.text();
        compress_bytes += comp_text.len();
        let comp_has_needle = comp_text.contains(&case.needle);
        if comp_has_needle {
            compress_needles += 1;
        }

        // (c) nasiko-semantic-synth
        let synthesized = synthesize(&case.payload, &case.anchors, &synth_policy);
        synth_bytes += synthesized.text.len();
        let synth_has_needle = synthesized.text.contains(&case.needle);
        if synth_has_needle {
            synth_needles += 1;
        }
        if synthesized.was_fallback {
            synth_fallbacks += 1;
        }

        let entry = type_stats.entry(case.payload_type).or_default();
        entry.total += 1;
        entry.orig_bytes += orig_len;
        entry.comp_bytes += comp_text.len();
        if comp_has_needle {
            entry.comp_needles += 1;
        }
        entry.synth_bytes += synthesized.text.len();
        if synth_has_needle {
            entry.synth_needles += 1;
        }
        if synthesized.was_fallback {
            entry.synth_fallbacks += 1;
        }
    }

    println!("=== SEMANTIC SYNTHESIZER NEEDLE EVALUATION (500 CASES) ===");
    println!(
        "{:<10} | {:<5} | {:<20} | {:<10} | {:<20} | {:<10} | {:<14}",
        "Type", "Cases", "Compress Recall", "Comp Red.", "Synth Recall", "Synth Red.", "Synth Fallback"
    );
    println!("{:-<10}-|-{:-<5}-|-{:-<20}-|-{:-<10}-|-{:-<20}-|-{:-<10}-|-{:-<14}", "", "", "", "", "", "", "");

    for (p_type, stats) in &type_stats {
        let comp_rec_pct = (stats.comp_needles as f64 / stats.total as f64) * 100.0;
        let comp_red_pct = (1.0 - (stats.comp_bytes as f64 / stats.orig_bytes as f64)) * 100.0;
        let synth_rec_pct = (stats.synth_needles as f64 / stats.total as f64) * 100.0;
        let synth_red_pct = (1.0 - (stats.synth_bytes as f64 / stats.orig_bytes as f64)) * 100.0;
        let synth_fb_pct = (stats.synth_fallbacks as f64 / stats.total as f64) * 100.0;

        println!(
            "{:<10} | {:<5} | {:>5}/{} ({:>5.1}%) | {:>8.1}% | {:>5}/{} ({:>5.1}%) | {:>8.1}% | {:>4}/{} ({:>4.1}%)",
            p_type.as_label(),
            stats.total,
            stats.comp_needles,
            stats.total,
            comp_rec_pct,
            comp_red_pct,
            stats.synth_needles,
            stats.total,
            synth_rec_pct,
            synth_red_pct,
            stats.synth_fallbacks,
            stats.total,
            synth_fb_pct,
        );
    }

    println!("{:-<102}", "");
    println!("OVERALL RESULTS (500 cases):");
    println!(
        "- Baseline (Uncompressed): Recall: 100.0% ({uncompressed_needles}/500), Bytes: {uncompressed_bytes}, Reduction: 0.0%"
    );
    println!(
        "- nasiko-compress:        Recall: {:>5.1}% ({}/500), Bytes: {compress_bytes}, Reduction: {:.1}%",
        (compress_needles as f64 / 500.0) * 100.0,
        compress_needles,
        (1.0 - (compress_bytes as f64 / uncompressed_bytes as f64)) * 100.0
    );
    println!(
        "- Semantic Synthesizer:   Recall: {:>5.1}% ({}/500), Bytes: {synth_bytes}, Reduction: {:.1}%, Fallback Rate: {:.1}% ({}/{})",
        (synth_needles as f64 / 500.0) * 100.0,
        synth_needles,
        (1.0 - (synth_bytes as f64 / uncompressed_bytes as f64)) * 100.0,
        (synth_fallbacks as f64 / 500.0) * 100.0,
        synth_fallbacks,
        500
    );
    println!("======================================================================================================");
}
