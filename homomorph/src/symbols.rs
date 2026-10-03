//! Symbol extraction and keyword protection across languages.

use crate::policy::HomomorphPolicy;
use std::collections::HashSet;

/// Kind of symbol for prefixing and categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Function or method. Prefix: `fn_`
    Function,
    /// Type, struct, class, interface, enum. Prefix: `ty_`
    Type,
    /// Variable, field, constant. Prefix: `var_`
    Variable,
    /// Database table or collection. Prefix: `tbl_`
    Table,
}

impl SymbolKind {
    /// Identifier prefix for surrogates.
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Function => "fn_",
            Self::Type => "ty_",
            Self::Variable => "var_",
            Self::Table => "tbl_",
        }
    }
}

/// Extracted code symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSymbol {
    /// Symbol name.
    pub name: String,
    /// Kind of symbol.
    pub kind: SymbolKind,
}

/// Standard language keywords and builtins to never rename.
fn get_protected_keywords() -> HashSet<&'static str> {
    let mut s = HashSet::new();

    // Common programming keywords & primitives across Rust, Python, JS/TS, Go, Java
    const KEYWORDS: &[&str] = &[
        // Rust
        "as",
        "break",
        "const",
        "continue",
        "crate",
        "else",
        "enum",
        "extern",
        "false",
        "fn",
        "for",
        "if",
        "impl",
        "in",
        "let",
        "loop",
        "match",
        "mod",
        "move",
        "mut",
        "pub",
        "ref",
        "return",
        "self",
        "Self",
        "static",
        "struct",
        "super",
        "trait",
        "true",
        "type",
        "unsafe",
        "use",
        "where",
        "while",
        "async",
        "await",
        "dyn",
        "abstract",
        "become",
        "box",
        "do",
        "final",
        "macro",
        "override",
        "priv",
        "typeof",
        "unsized",
        "virtual",
        "yield",
        "try",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "f32",
        "f64",
        "bool",
        "char",
        "str",
        "Option",
        "Some",
        "None",
        "Result",
        "Ok",
        "Err",
        "Vec",
        "String",
        "Box",
        "Rc",
        "Arc",
        "Cell",
        "RefCell",
        "HashMap",
        "HashSet",
        "BTreeMap",
        // Python
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "try",
        "while",
        "with",
        "yield",
        "True",
        "False",
        "None",
        "int",
        "float",
        "complex",
        "list",
        "tuple",
        "range",
        "dict",
        "set",
        "frozenset",
        "bool",
        "bytes",
        "bytearray",
        "memoryview",
        "print",
        "len",
        "range",
        "enumerate",
        "zip",
        "map",
        "filter",
        "open",
        "super",
        "isinstance",
        // JS / TS
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "new",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "let",
        "static",
        "enum",
        "implements",
        "interface",
        "package",
        "private",
        "protected",
        "public",
        "abstract",
        "any",
        "boolean",
        "number",
        "string",
        "symbol",
        "never",
        "unknown",
        "undefined",
        "null",
        "NaN",
        "Infinity",
        "console",
        "window",
        "document",
        "process",
        "require",
        "module",
        "exports",
        "Promise",
        "Array",
        "Object",
        // Go
        "break",
        "default",
        "func",
        "interface",
        "select",
        "case",
        "defer",
        "go",
        "map",
        "struct",
        "chan",
        "else",
        "goto",
        "package",
        "switch",
        "const",
        "fallthrough",
        "if",
        "range",
        "type",
        "continue",
        "for",
        "import",
        "return",
        "var",
        "nil",
        "iota",
        "append",
        "cap",
        "close",
        "complex",
        "copy",
        "delete",
        "imag",
        "len",
        "make",
        "new",
        "panic",
        "print",
        "println",
        "real",
        "recover",
        "error",
        "byte",
        "rune",
        // Java
        "abstract",
        "assert",
        "boolean",
        "break",
        "byte",
        "case",
        "catch",
        "char",
        "class",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extends",
        "final",
        "finally",
        "float",
        "for",
        "goto",
        "if",
        "implements",
        "import",
        "instanceof",
        "int",
        "interface",
        "long",
        "native",
        "new",
        "package",
        "private",
        "protected",
        "public",
        "return",
        "short",
        "static",
        "strictfp",
        "super",
        "switch",
        "synchronized",
        "this",
        "throw",
        "throws",
        "transient",
        "try",
        "void",
        "volatile",
        "while",
        "String",
        "System",
        "Integer",
        "Boolean",
        // Common tool call / library symbols
        "id",
        "main",
        "run",
        "test",
        "init",
        "new",
        "get",
        "set",
        "name",
        "value",
        "data",
        "arg",
        "args",
        "params",
        "path",
        "file",
        "url",
        "key",
        "result",
        "response",
        "request",
        "error",
    ];

    for kw in KEYWORDS {
        s.insert(*kw);
    }
    s
}

/// Extract symbols from code according to policy rules.
#[allow(clippy::collapsible_if)]
pub fn extract_symbols(code: &str, policy: &HomomorphPolicy) -> Vec<ExtractedSymbol> {
    let mut symbols = Vec::new();
    let mut seen = HashSet::new();
    let protected = get_protected_keywords();

    for line in code.lines() {
        let trimmed = line.trim();

        // 1. Rust / Go / JS / Python Functions
        if let Some(rest) = trimmed
            .strip_prefix("fn ")
            .or_else(|| trimmed.strip_prefix("pub fn "))
            .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
            .or_else(|| trimmed.strip_prefix("pub async fn "))
            .or_else(|| trimmed.strip_prefix("async fn "))
            .or_else(|| trimmed.strip_prefix("def "))
            .or_else(|| trimmed.strip_prefix("async def "))
            .or_else(|| trimmed.strip_prefix("function "))
            .or_else(|| trimmed.strip_prefix("func "))
        {
            if let Some(ident) = extract_identifier(rest) {
                maybe_add_symbol(
                    ident,
                    SymbolKind::Function,
                    &protected,
                    policy,
                    &mut seen,
                    &mut symbols,
                );
            }
        }

        // 2. Types: Structs, Classes, Interfaces, Enums
        if let Some(rest) = trimmed
            .strip_prefix("struct ")
            .or_else(|| trimmed.strip_prefix("pub struct "))
            .or_else(|| trimmed.strip_prefix("pub enum "))
            .or_else(|| trimmed.strip_prefix("enum "))
            .or_else(|| trimmed.strip_prefix("public class "))
            .or_else(|| trimmed.strip_prefix("private class "))
            .or_else(|| trimmed.strip_prefix("class "))
            .or_else(|| trimmed.strip_prefix("public interface "))
            .or_else(|| trimmed.strip_prefix("interface "))
            .or_else(|| trimmed.strip_prefix("type "))
        {
            if let Some(ident) = extract_identifier(rest) {
                maybe_add_symbol(
                    ident,
                    SymbolKind::Type,
                    &protected,
                    policy,
                    &mut seen,
                    &mut symbols,
                );
            }
        }

        // Java / C# methods & fields: public / private [static] <return_type> <name> ...
        if let Some(rest) = trimmed
            .strip_prefix("public ")
            .or_else(|| trimmed.strip_prefix("private "))
            .or_else(|| trimmed.strip_prefix("protected "))
        {
            if !rest.starts_with("class ") && !rest.starts_with("interface ") && !rest.starts_with("enum ") {
                let after_static = rest.strip_prefix("static ").unwrap_or(rest);
                let parts: Vec<&str> = after_static.split_whitespace().collect();
                if parts.len() >= 2 && parts[1].contains('(') {
                    let method_name = parts[1].split('(').next().unwrap_or("");
                    if let Some(ident) = extract_identifier(method_name) {
                        maybe_add_symbol(
                            ident,
                            SymbolKind::Function,
                            &protected,
                            policy,
                            &mut seen,
                            &mut symbols,
                        );
                    }
                } else if parts.len() >= 2 && after_static.contains('=') {
                    if let Some(ident) = extract_identifier(parts[1]) {
                        maybe_add_symbol(
                            ident,
                            SymbolKind::Variable,
                            &protected,
                            policy,
                            &mut seen,
                            &mut symbols,
                        );
                    }
                }
            }
        }

        // 3. Database Tables
        if let Some(rest) = trimmed
            .strip_prefix("CREATE TABLE ")
            .or_else(|| trimmed.strip_prefix("CREATE TABLE IF NOT EXISTS "))
            .or_else(|| trimmed.strip_prefix("ALTER TABLE "))
            .or_else(|| trimmed.strip_prefix("FROM "))
            .or_else(|| trimmed.strip_prefix("JOIN "))
        {
            if let Some(ident) = extract_identifier(rest) {
                maybe_add_symbol(
                    ident,
                    SymbolKind::Table,
                    &protected,
                    policy,
                    &mut seen,
                    &mut symbols,
                );
            }
        }

        // 4. Variables / Constants
        if let Some(rest) = trimmed
            .strip_prefix("let mut ")
            .or_else(|| trimmed.strip_prefix("let "))
            .or_else(|| trimmed.strip_prefix("const "))
            .or_else(|| trimmed.strip_prefix("var "))
        {
            if let Some(ident) = extract_identifier(rest) {
                maybe_add_symbol(
                    ident,
                    SymbolKind::Variable,
                    &protected,
                    policy,
                    &mut seen,
                    &mut symbols,
                );
            }
        } else if let Some((left, _)) = trimmed.split_once('=') {
            let left_trimmed = left.trim_end();
            if !left_trimmed.starts_with("if ")
                && !left_trimmed.contains("==")
                && !left_trimmed.contains("!=")
                && !left_trimmed.contains("<=")
                && !left_trimmed.contains(">=")
            {
                if let Some(ident) = extract_identifier(left_trimmed) {
                    maybe_add_symbol(
                        ident,
                        SymbolKind::Variable,
                        &protected,
                        policy,
                        &mut seen,
                        &mut symbols,
                    );
                }
            }
        }
    }

    symbols
}

fn extract_identifier(s: &str) -> Option<String> {
    let s = s.trim_start();
    let mut end = 0;
    for (i, c) in s.char_indices() {
        if i == 0 {
            if !c.is_alphabetic() && c != '_' {
                return None;
            }
        } else if !c.is_alphanumeric() && c != '_' {
            end = i;
            break;
        }
        end = i + c.len_utf8();
    }

    if end == 0 {
        return None;
    }

    let ident = s.get(..end).unwrap_or("");
    if ident.is_empty() {
        None
    } else {
        Some(ident.to_string())
    }
}

fn maybe_add_symbol(
    ident: String,
    kind: SymbolKind,
    protected: &HashSet<&'static str>,
    policy: &HomomorphPolicy,
    seen: &mut HashSet<String>,
    symbols: &mut Vec<ExtractedSymbol>,
) {
    if ident.len() < 3 {
        return;
    }
    if protected.contains(ident.as_str()) {
        return;
    }
    if policy.is_public_api(&ident) {
        return;
    }
    if seen.insert(ident.clone()) {
        symbols.push(ExtractedSymbol { name: ident, kind });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_symbols_multi_language() {
        let code = r#"
            pub fn calculate_internal_billing(rate: f64) -> f64 {
                let mut base_amount = 100.0;
                base_amount * rate
            }

            pub struct CustomerBillingRecord {
                pub account_id: u64,
            }

            def process_payment_flow(user_data):
                secret_token = "abc"
                return secret_token

            class InvoiceManager:
                pass

            CREATE TABLE billing_ledger_entries (
                id INT
            );
        "#;

        let policy = HomomorphPolicy::default();
        let symbols = extract_symbols(code, &policy);

        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"calculate_internal_billing"));
        assert!(names.contains(&"CustomerBillingRecord"));
        assert!(names.contains(&"process_payment_flow"));
        assert!(names.contains(&"InvoiceManager"));
        assert!(names.contains(&"billing_ledger_entries"));
        assert!(names.contains(&"base_amount"));

        // Protected keywords are never extracted
        assert!(!names.contains(&"main"));
        assert!(!names.contains(&"id"));
        assert!(!names.contains(&"let"));
    }
}
