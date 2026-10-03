//! # Homomorph
//!
//! Reversible, policy-driven identifier pseudonymization for coding-agent traffic.
//!
//! > **Important Notice**: Homomorph is structure-preserving renaming, not homomorphic encryption;
//! > it gives no cryptographic guarantee.
//!
//! ## Overview
//!
//! Homomorph inspects code payloads traversing the LLM router, detects sensitive internal identifiers
//! (functions, types, variables, database schemas), and replaces them with deterministic, syntactically valid
//! surrogates before they leave the platform. Ingress responses, tool call arguments, and streaming
//! chunks are reversed back into their original identifiers, guaranteeing byte-exact compatibility with
//! tools like Claude Code's Edit tool.

#![forbid(unsafe_code)]
#![deny(clippy::string_slice)]

pub mod edit_tool;
pub mod forward;
pub mod policy;
pub mod reverse;
pub mod secrets;
pub mod slice;
pub mod surrogates;
pub mod symbols;
pub mod vault;

pub use edit_tool::{
    ClaudeEditArgs, EditAuditRecord, EditError, apply_and_validate_edit, reverse_claude_edit,
};
pub use forward::{ForwardResult, forward_transform};
pub use policy::{CommentAction, HomomorphPolicy, SecretAction, TransformAction};
pub use reverse::{ReverseError, StreamingHoldbackBuffer, reverse_transform};
pub use secrets::{SecretFinding, redact_secrets, scan_secrets};
pub use surrogates::{SessionSymbolTable, SurrogateInfo, generate_surrogate};
pub use symbols::{ExtractedSymbol, SymbolKind, extract_symbols};
pub use vault::{VaultError, VaultRecord, decrypt_session_table, encrypt_session_table};
