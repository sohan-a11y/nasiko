//! Data models for the Semantic Synthesizer.

use serde::{Deserialize, Serialize};

/// Type classification of must-keep semantic facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LedgerKind {
    /// Function, struct, class, trait, or method signature.
    Signature,
    /// Import or module inclusion.
    Import,
    /// Comment containing an important marker (NOTE, WARNING, SAFETY, INVARIANT, MUST, NEVER).
    MarkerComment,
    /// Control flow guard, condition, early return, or assertion.
    Guard,
    /// Constant or literal definition.
    Constant,
    /// Specific line matching a critical anchor (identifier, error code, file path).
    AnchorMatch,
    /// Causal state change verb in logs (started, stopped, retry, timeout, rollback, etc.).
    StateChange,
    /// Distinct structured log template line.
    MessageTemplate,
    /// Essential JSON structure element.
    JsonStructure,
    /// Hunk header or context line in a diff.
    DiffContext,
}

/// A specific fact preserved in the semantic ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerItem {
    pub line_number: usize,
    pub content: String,
    pub kind: LedgerKind,
}

/// Summary report comparing facts before and after synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallReport {
    pub total_ledger_items: usize,
    pub preserved_items: usize,
    pub anchors_input: usize,
    pub anchors_preserved: usize,
    pub verified: bool,
}

/// Information about an elided text span, assigned a recovery handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElidedSpan {
    pub handle: String,
    pub start_line: usize,
    pub end_line: usize,
    pub original_text: String,
}

/// Result returned from semantic synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Synthesized {
    pub text: String,
    pub ledger: Vec<LedgerItem>,
    pub recall_report: RecallReport,
    pub elided_spans: Vec<ElidedSpan>,
    pub was_synthesized: bool,
    pub was_fallback: bool,
}

/// Execution policy for synthesis.
#[derive(Debug, Clone, Default)]
pub struct SynthPolicy<'a> {
    /// Underlying structural compression policy.
    pub compress: nasiko_compress::Policy<'a>,
    /// Whether to generate code skeletons (signatures + ledger lines) for pure source files.
    pub enable_code_synth: bool,
    /// Optional handle prefix for recovery tokens.
    pub recovery_prefix: Option<String>,
}
