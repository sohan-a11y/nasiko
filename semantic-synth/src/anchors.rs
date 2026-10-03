//! Anchor extraction from user queries, recent turns, and error messages.

use std::collections::HashSet;

/// Extract high-salience anchors (identifiers, file paths, error codes, quoted strings) from text.
pub fn extract_anchors(text: &str) -> Vec<String> {
    let mut anchors = HashSet::new();

    // 1. Quoted strings: `"..."` and `'...'`
    let mut in_quote = None;
    let mut current_quote = String::new();

    for ch in text.chars() {
        match in_quote {
            Some(quote_char) if ch == quote_char => {
                let trimmed = current_quote.trim();
                if trimmed.len() >= 2 && trimmed.len() <= 120 {
                    anchors.insert(trimmed.to_string());
                }
                current_quote.clear();
                in_quote = None;
            }
            Some(_) => {
                current_quote.push(ch);
            }
            None if ch == '"' || ch == '\'' || ch == '`' => {
                in_quote = Some(ch);
            }
            None => {}
        }
    }

    // 2. Token extraction for paths, error codes, and identifiers
    for token in text.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '_' && c != '/' && c != '\\' && c != '.' && c != '-'
        });
        if cleaned.is_empty() {
            continue;
        }

        // File paths (e.g. src/main.rs, C:\foo\bar.txt, config.json)
        if is_file_path(cleaned) {
            anchors.insert(cleaned.to_string());
            continue;
        }

        // Error codes (e.g. E0369, ERR_404, HTTP_500, Status 404)
        if is_error_code(cleaned) {
            anchors.insert(cleaned.to_string());
            continue;
        }

        // Code identifiers (e.g. ContextManager, compact_simple, get_weather)
        if is_code_identifier(cleaned) {
            anchors.insert(cleaned.to_string());
        }
    }

    let mut result: Vec<String> = anchors.into_iter().collect();
    result.sort();
    result
}

fn is_file_path(s: &str) -> bool {
    (s.contains('/') || s.contains('\\') || s.contains('.'))
        && (s.ends_with(".rs")
            || s.ends_with(".py")
            || s.ends_with(".js")
            || s.ends_with(".ts")
            || s.ends_with(".json")
            || s.ends_with(".toml")
            || s.ends_with(".md")
            || s.ends_with(".go")
            || s.ends_with(".java")
            || s.ends_with(".c")
            || s.ends_with(".cpp")
            || s.ends_with(".h")
            || s.ends_with(".yaml")
            || s.ends_with(".yml")
            || s.ends_with(".log"))
}

fn is_error_code(s: &str) -> bool {
    let s_upper = s.to_ascii_uppercase();
    if s_upper.starts_with("ERR_") || s_upper.starts_with("ERROR_") {
        return true;
    }
    // Rust compiler errors like E0369, E0502
    if s.len() == 5 && s.starts_with('E') && s.chars().skip(1).all(|c| c.is_ascii_digit()) {
        return true;
    }
    // HTTP status codes like 404, 500, 502
    if s.len() == 3
        && s.chars().all(|c| c.is_ascii_digit())
        && matches!(s.chars().next(), Some('4' | '5'))
    {
        return true;
    }
    false
}

fn is_code_identifier(s: &str) -> bool {
    if s.len() < 3 || s.len() > 60 {
        return false;
    }
    let first = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }

    // Exclude basic english stopwords
    !matches!(
        s.to_ascii_lowercase().as_str(),
        "the"
            | "and"
            | "for"
            | "with"
            | "this"
            | "that"
            | "from"
            | "have"
            | "here"
            | "what"
            | "when"
            | "where"
            | "which"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_anchors() {
        let text = "Fix error E0369 in src/compact_tools.rs when calling `apply_egress` with \"invalid parameter\"";
        let anchors = extract_anchors(text);

        assert!(anchors.contains(&"E0369".to_string()));
        assert!(anchors.contains(&"src/compact_tools.rs".to_string()));
        assert!(anchors.contains(&"apply_egress".to_string()));
        assert!(anchors.contains(&"invalid parameter".to_string()));
    }
}
