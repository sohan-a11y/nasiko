//! Full showcase pipeline integration test proving egress and ingress ordering:
//!
//! Egress:  synth/compress -> Homomorph forward -> compact-tools encode -> provider
//! Ingress: provider -> compact-tools decode -> Homomorph reverse -> client

use nasiko_homomorph::{HomomorphPolicy, SessionSymbolTable, forward_transform, reverse_transform};
use nasiko_semantic_synth::{SynthPolicy, synthesize};
use nasiko_tool_compact::{ToolDef, decode_calls, encode_tools};
use serde_json::json;

#[test]
fn test_full_pipeline_egress_and_ingress_order() {
    let homomorph_policy = HomomorphPolicy::default();
    let synth_policy = SynthPolicy {
        compress: nasiko_compress::Policy::default(),
        enable_code_synth: true,
        recovery_prefix: Some("rec".into()),
    };
    let salt = b"pipeline-salt-2026";
    let mut table = SessionSymbolTable::new();

    // 1. Initial Request containing proprietary code, tool call intent, and anchors
    let initial_user_message = r#"
        Please update customer billing rate:
        pub fn update_customer_rate(account_id: u64, rate: f64) -> f64 {
            let internal_fee = 2.5;
            rate + internal_fee
        }
    "#;

    // Defined tools
    let raw_tool = ToolDef {
        name: "apply_rate_change".into(),
        description: Some("Apply rate changes to account".into()),
        parameters: Some(json!({
            "type": "object",
            "required": ["account_id", "new_rate"],
            "properties": {
                "account_id": {"type": "integer"},
                "new_rate": {"type": "number"}
            }
        })),
    };
    let tools = vec![raw_tool.clone()];

    // ── EGRESS STEP 1: Semantic Synthesizer ──────────────────────────────────
    let anchors = vec!["account_id".to_string(), "update_customer_rate".to_string()];
    let synth_res = synthesize(initial_user_message, &anchors, &synth_policy);
    assert!(synth_res.recall_report.verified);

    // ── EGRESS STEP 2: Homomorph Forward Transform ──────────────────────────
    let homomorph_egress = forward_transform(&synth_res.text, &mut table, &homomorph_policy, salt);
    assert!(!homomorph_egress.blocked);
    // Proprietary symbols are pseudonymized
    assert!(!homomorph_egress.text.contains("update_customer_rate"));
    assert!(!homomorph_egress.text.contains("internal_fee"));
    assert!(homomorph_egress.text.contains("fn_"));

    // ── EGRESS STEP 3: Compact Tools Encode ──────────────────────────────────
    let compact_tools = encode_tools(&tools).expect("encode tools");
    // Native schemas are compacted into concise grammar
    assert!(
        compact_tools
            .text
            .contains("apply_rate_change(account_id:int, new_rate:num)")
    );

    // ── PROVIDER DISPATCH (Simulated deterministic mock provider) ───────────
    // Model emits call in compact grammar using the surrogate space:
    let surrogate_fn = table.get_surrogate("update_customer_rate").unwrap();
    let model_raw_reply = format!(
        "Executing requested modification for {surrogate_fn}:\n<<call apply_rate_change {{\"account_id\":123,\"new_rate\":15.5}}>>"
    );

    // ── INGRESS STEP 1: Compact Tools Decode ─────────────────────────────────
    let decoded_calls = decode_calls(&model_raw_reply, &tools).expect("decode calls");
    assert_eq!(decoded_calls.len(), 1);
    assert_eq!(decoded_calls[0].name, "apply_rate_change");
    assert_eq!(
        decoded_calls[0].arguments,
        json!({"account_id": 123, "new_rate": 15.5})
    );

    // ── INGRESS STEP 2: Homomorph Reverse Transform ──────────────────────────
    let client_text = reverse_transform(&model_raw_reply, &table).expect("reverse text");
    // Restores original identifier names for client application
    assert!(client_text.contains("update_customer_rate"));
    assert!(!client_text.contains(surrogate_fn));
}
