use nasiko_compress::{Level, Policy, TypeMask};
use nasiko_semantic_synth::*;

fn pol(prefix: &str) -> SynthPolicy<'static> {
    SynthPolicy {
        compress: Policy {
            enabled: true,
            min_bytes: 0,
            types: TypeMask::ALL,
            level: Level::Balanced,
            ..Default::default()
        },
        enable_code_synth: true,
        recovery_prefix: Some(prefix.to_string()),
    }
}

#[test]
fn test_verification_probes() {
    // 1. Fair needle: anchors come from a realistic query that does NOT name the needle.
    let mut log = String::new();
    for i in 0..100 {
        log.push_str(&format!("2026-01-01T00:00:00Z INFO handled request {i}\n"));
    }
    log.push_str("2026-01-01T00:00:01Z INFO cache entry evicted by job=nightly-reindex\n");
    for i in 0..100 {
        log.push_str(&format!("2026-01-01T00:00:02Z INFO handled request b{i}\n"));
    }
    log.push_str("2026-01-01T00:00:03Z ERROR stale read on key=user:42\n");
    let anchors = extract_anchors("Why did user 42 get a stale read?");
    let s = synthesize(&log, &anchors, &pol("p"));
    println!(
        "PROBE fair_log anchors={anchors:?} needle_kept={} synthesized={} fallback={} bytes {}->{}",
        s.text.contains("nightly-reindex"),
        s.was_synthesized,
        s.was_fallback,
        log.len(),
        s.text.len()
    );

    assert!(s.text.contains("nightly-reindex"), "needle must be kept");
    assert!(s.was_synthesized, "must synthesize");
    assert!(!s.was_fallback, "must not fallback");
    assert!(
        s.text.len() < log.len() / 4,
        "must compress significantly (actual: {} -> {})",
        log.len(),
        s.text.len()
    );
    assert!(!anchors.contains(&"Why".to_string()), "Why is a stop word");
    assert!(!anchors.contains(&"did".to_string()), "did is a stop word");
    assert!(!anchors.contains(&"get".to_string()), "get is a stop word");

    let mut log2 = String::new();
    for i in 0..100 {
        log2.push_str(&format!("2026-01-01T00:00:00Z INFO handled request {i}\n"));
    }
    log2.push_str("2026-01-01T00:00:01Z INFO config reloaded: max_conn=2\n");
    for i in 0..100 {
        log2.push_str(&format!("2026-01-01T00:00:02Z INFO handled request b{i}\n"));
    }
    log2.push_str("2026-01-01T00:00:03Z ERROR connection pool exhausted\n");
    let s2 = synthesize(
        &log2,
        &extract_anchors("Why is the connection pool exhausted?"),
        &pol("p"),
    );
    println!(
        "PROBE fair_log2 needle_kept={} synthesized={} fallback={}",
        s2.text.contains("max_conn=2"),
        s2.was_synthesized,
        s2.was_fallback
    );
    assert!(s2.text.contains("max_conn=2"));
    assert!(s2.was_synthesized);
    assert!(!s2.was_fallback);

    // 2. Real diff with business-rule comment 15 lines above change, realistic query.
    let mut d = String::from(
        "diff --git a/P.java b/P.java\nindex 1..2 100644\n--- a/P.java\n+++ b/P.java\n@@ -1,40 +1,40 @@\n",
    );
    d.push_str(" // IMPORTANT: premium customers from region X are excluded\n");
    for i in 0..15 {
        d.push_str(&format!(" int v{i} = {i};\n"));
    }
    d.push_str("-if (c.isPremium() && !r.equals(\"X\")) {\n+if (c.isPremium()) {\n");
    for i in 0..15 {
        d.push_str(&format!(" int w{i} = {i};\n"));
    }
    let s3 = synthesize(
        &d,
        &extract_anchors("review this change to the discount check"),
        &pol("p"),
    );
    println!(
        "PROBE diff_rule_kept={} synthesized={} fallback={}",
        s3.text.contains("region X are excluded"),
        s3.was_synthesized,
        s3.was_fallback
    );
    assert!(s3.text.contains("region X are excluded"));
    assert!(s3.was_synthesized);
    assert!(!s3.was_fallback);

    // 3. Recovery handle uniqueness across different payloads with same prefix.
    let a = synthesize(&log, &[], &pol("ctx_rec"));
    let b = synthesize(&log2, &[], &pol("ctx_rec"));
    let ha: Vec<_> = a.elided_spans.iter().map(|x| x.handle.clone()).collect();
    let hb: Vec<_> = b.elided_spans.iter().map(|x| x.handle.clone()).collect();
    let collide: Vec<_> = ha.iter().filter(|h| hb.contains(h)).collect();
    println!(
        "PROBE handles_a={ha:?} handles_b={hb:?} collisions={}",
        collide.len()
    );
    assert!(!ha.is_empty(), "handles_a must not be empty");
    assert!(!hb.is_empty(), "handles_b must not be empty");
    assert_eq!(collide.len(), 0, "no collisions between handles_a and handles_b");
}
