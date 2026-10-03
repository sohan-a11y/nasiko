use nasiko_compress::{Level, Policy, TypeMask};
use nasiko_semantic_synth::{SynthPolicy, synthesize};
use proptest::prelude::*;

fn arbitrary_policy<'a>() -> SynthPolicy<'a> {
    SynthPolicy {
        compress: Policy {
            enabled: true,
            min_bytes: 20,
            types: TypeMask::ALL,
            level: Level::Balanced,
            dry_run: false,
            max_input_bytes: 500_000,
            recovery_ref: None,
        },
        enable_code_synth: true,
        recovery_prefix: Some("prop_rec".into()),
    }
}

proptest! {
    #[test]
    fn prop_never_grows(payload in "\\PC{20,1000}") {
        let anchors = vec!["target_fn".to_string(), "error_code".to_string()];
        let policy = arbitrary_policy();
        let res = synthesize(&payload, &anchors, &policy);

        prop_assert!(res.text.len() <= payload.len(), "Synthesized text must never grow");
    }

    #[test]
    fn prop_idempotent(payload in "\\PC{20,1000}") {
        let anchors = vec!["anchor_1".to_string()];
        let policy = arbitrary_policy();
        let res1 = synthesize(&payload, &anchors, &policy);
        let res2 = synthesize(&res1.text, &anchors, &policy);

        prop_assert_eq!(res1.text, res2.text, "Synthesizer must be idempotent");
    }

    #[test]
    fn prop_ledger_subset_or_fallback(payload in "\\PC{20,1000}") {
        let anchors = vec!["must_keep".to_string(), "foo".to_string()];
        let policy = arbitrary_policy();
        let res = synthesize(&payload, &anchors, &policy);

        if res.was_synthesized {
            for item in &res.ledger {
                prop_assert!(res.text.contains(&item.content), "All ledger items must be preserved in synthesized output");
            }
        } else {
            prop_assert_eq!(&res.text, &payload, "Fallback must return original payload bit-for-bit");
        }
    }
}
