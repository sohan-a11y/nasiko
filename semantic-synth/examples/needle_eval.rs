//! Offline deterministic evaluation of needle survival across compression approaches.
//!
//! Generates 500+ realistic payloads across Diffs, Logs, JSON, Code, and Multi-turn turns,
//! each containing planted task-critical "needles" (business-rule comments, causal INFO lines,
//! critical tenant JSON records, constraint definitions).
//!
//! Evaluates:
//! (a) Uncompressed baseline
//! (b) nasiko-compress structural compression
//! (c) nasiko-semantic-synth ledger-verified synthesis

use nasiko_compress::{Level, Policy, TypeMask};
use nasiko_semantic_synth::{SynthPolicy, synthesize};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Debug, Clone, Copy)]
enum PayloadType {
    Diff,
    Log,
    Json,
    Code,
    MultiTurn,
}

struct EvalCase {
    payload_type: PayloadType,
    payload: String,
    needle: String,
    anchors: Vec<String>,
}

fn generate_corpus(rng: &mut StdRng, total_cases: usize) -> Vec<EvalCase> {
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
                let needle = format!("// INVARIANT_RULE_{i}: Max discount strictly capped at 25%");
                let distance = rng.gen_range(5..40);
                let mut p =
                    String::from("--- a/pricing.rs\n+++ b/pricing.rs\n@@ -20,60 +20,60 @@\n");
                p.push_str(&format!("    {needle}\n"));
                for d in 0..distance {
                    p.push_str(&format!("    let intermediate_{d} = buffer[{d}];\n"));
                }
                p.push_str("-   let rate = 0.05;\n+   let rate = 0.10;\n");
                for d in 0..20 {
                    p.push_str(&format!("    post_process_{d}();\n"));
                }
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: needle.clone(),
                    anchors: vec![format!("INVARIANT_RULE_{i}"), "discount".into()],
                });
            }
            PayloadType::Log => {
                let needle =
                    format!("INFO [auth] token invalidation triggered for session_user_{i}");
                let mut p = String::new();
                for l in 0..30 {
                    p.push_str(&format!(
                        "2026-10-02 12:{:02}:{:02} DEBUG worker thread {l} idle\n",
                        l % 60,
                        (l * 2) % 60
                    ));
                }
                p.push_str(&format!("2026-10-02 12:35:00 {needle}\n"));
                for l in 31..65 {
                    p.push_str(&format!(
                        "2026-10-02 12:{:02}:{:02} DEBUG worker thread {l} idle\n",
                        l % 60,
                        (l * 2) % 60
                    ));
                }
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: needle.clone(),
                    anchors: vec![format!("session_user_{i}"), "invalidation".into()],
                });
            }
            PayloadType::Json => {
                let needle = format!("\"target_id\": \"critical_record_{i}\"");
                let mut p = String::from("[\n");
                for idx in 0..35 {
                    if idx == 17 {
                        p.push_str(&format!(
                            "  {{\"index\": {idx}, {needle}, \"role\": \"admin\"}},\n"
                        ));
                    } else {
                        p.push_str(&format!("  {{\"index\": {idx}, \"target_id\": \"regular_{idx}\", \"role\": \"user\"}},\n"));
                    }
                }
                p.push_str("  {\"index\": 36, \"target_id\": \"tail\", \"role\": \"guest\"}\n]\n");
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: needle.clone(),
                    anchors: vec![format!("critical_record_{i}")],
                });
            }
            PayloadType::Code => {
                let needle = format!("// SAFETY_CONSTRAINT_{i}: do not bypass memory barrier");
                let mut p = String::from("pub struct Driver {\n");
                p.push_str(&format!("    {needle}\n"));
                p.push_str("    flags: u32,\n");
                p.push_str("}\n\nimpl Driver {\n");
                for m in 0..25 {
                    p.push_str(&format!(
                        "    pub fn op_{m}(&self) -> u32 {{ self.flags + {m} }}\n"
                    ));
                }
                p.push_str("}\n");
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: needle.clone(),
                    anchors: vec![format!("SAFETY_CONSTRAINT_{i}"), "barrier".into()],
                });
            }
            PayloadType::MultiTurn => {
                let needle = format!(
                    "CONSTRAINT: Agent must not write to /tmp or outside user workspace {i}"
                );
                let mut p = format!("Turn 1: User says: {needle}\n");
                for t in 2..20 {
                    p.push_str(&format!(
                        "Turn {t}: Assistant answered step {t} output and ran tool\n"
                    ));
                }
                cases.push(EvalCase {
                    payload_type: p_type,
                    payload: p,
                    needle: needle.clone(),
                    anchors: vec![format!("workspace {i}"), "CONSTRAINT".into()],
                });
            }
        }
    }

    cases
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

    let mut type_stats: std::collections::BTreeMap<&'static str, (usize, usize, usize, usize)> =
        std::collections::BTreeMap::new();

    for case in &cases {
        let type_label = match case.payload_type {
            PayloadType::Diff => "Diff",
            PayloadType::Log => "Log",
            PayloadType::Json => "JSON",
            PayloadType::Code => "Code",
            PayloadType::MultiTurn => "MultiTurn",
        };

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

        let entry = type_stats.entry(type_label).or_insert((0, 0, 0, 0));
        entry.0 += 1; // total
        if comp_has_needle {
            entry.1 += 1;
        }
        if synth_has_needle {
            entry.2 += 1;
        }
        entry.3 += orig_len - synthesized.text.len(); // bytes saved
    }

    println!("=== SEMANTIC SYNTHESIZER NEEDLE EVALUATION (500 CASES) ===");
    println!(
        "{:<12} | {:<12} | {:<22} | {:<22}",
        "Payload Type", "Total Cases", "nasiko-compress Recall", "Synthesizer Recall"
    );
    println!("{:-<12}-|-{:-<12}-|-{:-<22}-|-{:-<22}", "", "", "", "");

    for (label, stats) in &type_stats {
        let (total, comp_rec, synth_rec, _) = *stats;
        println!(
            "{:<12} | {:<12} | {:>6} / {:<4} ({:>5.1}%) | {:>6} / {:<4} ({:>5.1}%)",
            label,
            total,
            comp_rec,
            total,
            (comp_rec as f64 / total as f64) * 100.0,
            synth_rec,
            total,
            (synth_rec as f64 / total as f64) * 100.0,
        );
    }

    println!("{:-<75}", "");
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
        "- Semantic Synthesizer:   Recall: {:>5.1}% ({}/500), Bytes: {synth_bytes}, Reduction: {:.1}%",
        (synth_needles as f64 / 500.0) * 100.0,
        synth_needles,
        (1.0 - (synth_bytes as f64 / uncompressed_bytes as f64)) * 100.0
    );
    println!("==========================================================");
}
