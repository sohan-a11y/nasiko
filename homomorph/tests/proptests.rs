//! Property-based tests for Homomorph reversibility and streaming holdback.

use nasiko_homomorph::{
    HomomorphPolicy, SessionSymbolTable, StreamingHoldbackBuffer, forward_transform,
    reverse_transform,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_roundtrip_reversibility(
        fn_name in "[a-z][a-z0-9_]{3,12}",
        var_name in "[a-z][a-z0-9_]{3,12}",
        ty_name in "[A-Z][a-zA-Z0-9]{3,12}",
        val in 1u32..1000u32,
    ) {
        let code = format!(
            "pub fn {fn_name}(param: {ty_name}) -> u32 {{\n    let {var_name} = {val};\n    {var_name}\n}}"
        );

        let policy = HomomorphPolicy::default();
        let mut table = SessionSymbolTable::new();
        let salt = b"proptest-salt-homomorph";

        let fwd = forward_transform(&code, &mut table, &policy, salt);
        if !fwd.blocked && fwd.replacements > 0 {
            let rev = reverse_transform(&fwd.text, &table).expect("reverse must succeed");
            prop_assert_eq!(rev, code);
        }
    }

    #[test]
    fn prop_streaming_chunking_invariance(
        chunk_size in 1usize..8usize,
    ) {
        let code = "pub fn compute_hash_rate(base: u64) -> u64 { let multiplier = 2; base * multiplier }";
        let policy = HomomorphPolicy::default();
        let mut table = SessionSymbolTable::new();
        let salt = b"streaming-salt-proptest";

        let fwd = forward_transform(code, &mut table, &policy, salt);
        let mut stream = StreamingHoldbackBuffer::new(16);
        let mut reconstructed = String::new();

        for chunk in fwd.text.as_bytes().chunks(chunk_size) {
            if let Ok(chunk_str) = std::str::from_utf8(chunk) {
                let out = stream.push(chunk_str, &table).expect("push must succeed");
                reconstructed.push_str(&out);
            }
        }
        let final_chunk = stream.finish(&table).expect("finish must succeed");
        reconstructed.push_str(&final_chunk);

        prop_assert_eq!(reconstructed, code);
    }

    #[test]
    fn prop_streaming_multibyte_utf8_invariance(
        chunk_chars in 1usize..6usize,
    ) {
        let code = "fn compute_résumé(val: €uro) -> String { let 日本語 = \"こんにちは\"; 日本語 }";
        let policy = HomomorphPolicy::default();
        let mut table = SessionSymbolTable::new();
        let salt = b"streaming-multibyte-salt";

        let fwd = forward_transform(code, &mut table, &policy, salt);
        let mut stream = StreamingHoldbackBuffer::new(16);
        let mut reconstructed = String::new();

        let chars: Vec<char> = fwd.text.chars().collect();
        for char_chunk in chars.chunks(chunk_chars) {
            let s: String = char_chunk.iter().collect();
            let out = stream.push(&s, &table).expect("push must not panic on multibyte");
            reconstructed.push_str(&out);
        }
        let final_chunk = stream.finish(&table).expect("finish must succeed");
        reconstructed.push_str(&final_chunk);

        prop_assert_eq!(reconstructed, code);
    }
}
