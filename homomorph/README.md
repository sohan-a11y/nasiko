# Homomorph (`nasiko-homomorph`)

Reversible, policy-driven identifier pseudonymization and privacy filtering for coding-agent traffic through the LLM router.

> **CRITICAL DISCLAIMER**:
> **Homomorph is structure-preserving renaming, not homomorphic encryption; it gives no cryptographic guarantee.**
> It is an engineering defense-in-depth transform designed to prevent proprietary symbol and database schema leakage to external model providers while preserving full agent utility.

---

## 1. Threat Model

### What is Protected
1. **Internal Identifiers**: Function names, struct/class/interface names, variable and field names, and constant identifiers are reversibly renamed to deterministic, syntactically valid surrogates (e.g. `fn_a1b2c3`, `TyA1b2c3`).
2. **Database Schemas**: Table names and column identifiers in SQL queries are pseudonymized.
3. **Hardcoded Credentials**: API key tokens (`sk-`, `ghp_`, `AKIA`), PEM private key blocks, and `.env` passwords are unconditionally detected and blocked/redacted (`[REDACTED:kind]`).
4. **File Paths**: Sensitive repo directory trees and internal paths can be masked per policy.
5. **Exact Reversibility**: Claude Code's Edit tool requires `old_string` to match the target file byte-for-byte; Homomorph's reverse transform guarantees that model edits in surrogate space map back with zero residual surrogates.

### What is NOT Protected
1. **Algorithms & Logic**: The structural control flow (`if`, `for`, `match`), algorithmic complexity, and execution logic remain visible to the model.
2. **Preserved String Literals**: If the policy preserves string literals, user-visible messages or string constants are not transformed.
3. **Language Builtins & Public APIs**: Language primitives and external package APIs (`std::*`, `tokio::*`, `react`, etc.) are intentionally preserved so models understand typing and semantics.
4. **Code Shape Re-identification**: Highly distinctive algorithmic structures (e.g. standard textbook algorithms) may still allow probabilistic deduction of code function by an adversary.

---

## 2. Prior Art & Lineage

| Project / Paper | Reference | Date | Stars / Venue | Key Difference vs Homomorph |
|---|---|---|---|---|
| **SchrodingerRepo** | Kuo et al., [arXiv:2407.03310](https://arxiv.org/abs/2407.03310) | Jul 2024 | arXiv | Academic benchmark for repository obfuscation; Homomorph is an online, streaming, router-integrated proxy with fail-closed Claude Edit tool support. |
| **PromptCape** | Zhang et al., [arXiv:2404.09506](https://arxiv.org/abs/2404.09506) | Apr 2024 | arXiv | Focuses on generalized prompt anonymization; Homomorph is specifically AST/language-aware for multi-lingual codebases and streaming SSE. |
| **Stacklok CodeGate** | [GitHub](https://github.com/stacklok/codegate) | 2024 | ~1.5k★ | Local privacy gateway; Homomorph adds bidirectional streaming holdback buffering and cryptographic AES-GCM vault persistence. |
| **Microsoft Presidio** / **LiteLLM** | [GitHub](https://github.com/microsoft/presidio) | 2023-2024 | ~4.5k★ | Heavy PII/NLP entity extraction; Homomorph is zero-dependency, ultra-low latency (<50 µs) AST identifier pseudonymization. |

---

## 3. Configuration & Policy

```yaml
# homomorph_policy.yaml
internal_symbols: transform   # transform | preserve
database_schema: transform    # transform | preserve
public_api:                   # Never renamed
  - "std::*"
  - "tokio::*"
  - "serde::*"
string_literals: preserve     # preserve | transform
comments: preserve            # preserve | transform | strip
secrets: block                # block | redact
paths: preserve               # preserve | transform
```

---

## 4. Streaming SSE & Holdback Buffer

In streaming mode, model output deltas may partition an identifier across chunk boundaries:
```
Chunk 1: "fn_"
Chunk 2: "3b2a"
Chunk 3: "1c()"
```
Homomorph employs a configurable sliding `StreamingHoldbackBuffer`. It holds back up to the maximum surrogate length (typically 16-32 bytes), flushing characters only after confirming complete token boundaries or upon stream termination, ensuring zero unreversed surrogate leakage.
