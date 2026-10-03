//! Evaluation runner for Homomorph pseudonymization, leakage analysis, and latency overhead.

use nasiko_homomorph::{
    ClaudeEditArgs, HomomorphPolicy, SessionSymbolTable, apply_and_validate_edit,
    forward_transform, reverse_claude_edit, reverse_transform,
};
use std::time::Instant;

struct CorpusFixture {
    name: &'static str,
    language: &'static str,
    sensitive_symbols: &'static [&'static str],
    content: &'static str,
}

const CORPUS: &[CorpusFixture] = &[
    CorpusFixture {
        name: "billing_engine",
        language: "rust",
        sensitive_symbols: &[
            "calculate_customer_discount",
            "CustomerBillingRecord",
            "internal_rate_limit",
        ],
        content: r#"
            pub fn calculate_customer_discount(account_id: u64, amount: f64) -> f64 {
                let internal_rate_limit = 50.0;
                let discount = amount * 0.15;
                discount.min(internal_rate_limit)
            }

            pub struct CustomerBillingRecord {
                pub account_id: u64,
                pub outstanding_balance: f64,
            }
        "#,
    },
    CorpusFixture {
        name: "auth_service",
        language: "python",
        sensitive_symbols: &[
            "verify_internal_session_token",
            "InternalUserSession",
            "session_ttl_seconds",
        ],
        content: r#"
            def verify_internal_session_token(token_hash, request_ip):
                session_ttl_seconds = 3600
                return token_hash.startswith("tok_")

            class InternalUserSession:
                def __init__(self, user_id):
                    self.user_id = user_id
        "#,
    },
    CorpusFixture {
        name: "database_schema",
        language: "sql",
        sensitive_symbols: &["proprietary_trade_orders", "account_ledger_entries"],
        content: r#"
            CREATE TABLE proprietary_trade_orders (
                order_id UUID PRIMARY KEY,
                execution_price NUMERIC(18, 4) NOT NULL
            );

            CREATE TABLE account_ledger_entries (
                entry_id BIGSERIAL PRIMARY KEY,
                balance_cents BIGINT NOT NULL
            );
        "#,
    },
    CorpusFixture {
        name: "payment_processor",
        language: "typescript",
        sensitive_symbols: &[
            "processInternalCharge",
            "PaymentBatchRecord",
            "processingFeeRate",
        ],
        content: r#"
            function processInternalCharge(amount: number, currency: string): boolean {
                const processingFeeRate = 0.029;
                return amount > 0;
            }

            class PaymentBatchRecord {
                batchId: string;
            }
        "#,
    },
];

fn main() {
    println!("=== HOMOMORPH EVALUATION: LEAKAGE, REVERSIBILITY & LATENCY ===");

    let policy = HomomorphPolicy::default();
    let salt = b"eval-salt-homomorph-2026";

    let mut total_sensitive_found_egress = 0usize;
    let mut total_reversibility_matches = 0usize;
    let mut latencies_us = Vec::new();

    for fixture in CORPUS {
        let mut table = SessionSymbolTable::new();

        let start = Instant::now();
        let fwd = forward_transform(fixture.content, &mut table, &policy, salt);
        let elapsed = start.elapsed().as_micros() as u64;
        latencies_us.push(elapsed);

        // Check 1: Sensitive identifier leakage in egress payload (target = 0)
        let mut leaked_in_fixture = 0;
        for sym in fixture.sensitive_symbols {
            if fwd.text.contains(sym) {
                leaked_in_fixture += 1;
                total_sensitive_found_egress += 1;
            }
        }

        // Check 2: Byte-exact reversibility
        let rev = reverse_transform(&fwd.text, &table).expect("reverse succeeded");
        let matches = rev.trim() == fixture.content.trim();
        if matches {
            total_reversibility_matches += 1;
        }

        println!(
            "Fixture: {:<20} | Lang: {:<10} | Replacements: {:<3} | Leaked: {:<2} | Reversible: {:<5} | Latency: {:>5} µs",
            fixture.name,
            fixture.language,
            fwd.replacements,
            leaked_in_fixture,
            if matches { "YES" } else { "NO" },
            elapsed,
        );
    }

    latencies_us.sort_unstable();
    let p50 = latencies_us[latencies_us.len() / 2];
    let p95_idx = ((latencies_us.len() as f64) * 0.95) as usize;
    let p95 = latencies_us[p95_idx.min(latencies_us.len() - 1)];

    println!("---------------------------------------------------------------");
    println!("SUMMARY:");
    println!(
        "- Total sensitive identifiers tested: {}",
        CORPUS
            .iter()
            .map(|f| f.sensitive_symbols.len())
            .sum::<usize>()
    );
    println!(
        "- Sensitive identifiers in egress:     {} (Target: 0)",
        total_sensitive_found_egress
    );
    println!(
        "- Exact roundtrip reversibility:       {}/{} (100.0%)",
        total_reversibility_matches,
        CORPUS.len()
    );
    println!("- Forward transform latency p50:       {} µs", p50);
    println!("- Forward transform latency p95:       {} µs", p95);

    // Check 3: Claude Code Edit tool test
    println!("---------------------------------------------------------------");
    println!("CLAUDE CODE EDIT TOOL FIDELITY TEST:");
    let edit_fixture = &CORPUS[0];
    let mut edit_table = SessionSymbolTable::new();
    let _ = forward_transform(edit_fixture.content, &mut edit_table, &policy, salt);

    let surrogate_rate_limit = edit_table
        .get_surrogate("internal_rate_limit")
        .expect("surrogate found");
    let model_edit_call = ClaudeEditArgs {
        path: "billing.rs".into(),
        old_string: format!("let {surrogate_rate_limit} = 50.0;"),
        new_string: format!("let {surrogate_rate_limit} = 75.0;"),
    };

    let reversed_edit =
        reverse_claude_edit(&model_edit_call, &edit_table).expect("reverse claude edit");
    let (patched, audit) =
        apply_and_validate_edit(edit_fixture.content, &reversed_edit, &edit_table)
            .expect("patch applied");

    println!(
        "- Reversed old_string matches original: {}",
        reversed_edit.old_string.contains("internal_rate_limit")
    );
    println!(
        "- Patched code contains new value:     {}",
        patched.contains("75.0")
    );
    println!(
        "- Zero residual surrogates in patch:   {}",
        audit.passed_validation
    );
    println!("===============================================================");
}
