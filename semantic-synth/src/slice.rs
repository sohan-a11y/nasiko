//! UTF-8 safe slicing utilities ensuring char-boundary safety.

/// Safely slice a string from byte `start` to `end` without panicking on non-char boundaries.
pub fn safe_slice(s: &str, start: usize, end: usize) -> &str {
    let len = s.len();
    let mut actual_start = start.min(len);
    let mut actual_end = end.min(len);

    if actual_start > actual_end {
        return "";
    }

    while actual_start < len && !s.is_char_boundary(actual_start) {
        actual_start += 1;
    }
    while actual_end > 0 && !s.is_char_boundary(actual_end) {
        actual_end -= 1;
    }

    if actual_start >= actual_end {
        return "";
    }

    s.get(actual_start..actual_end).unwrap_or_default()
}

/// Safely slice a string from byte `start` to the end.
pub fn safe_slice_from(s: &str, start: usize) -> &str {
    safe_slice(s, start, s.len())
}

/// Safely slice a string from the beginning to byte `end`.
pub fn safe_slice_to(s: &str, end: usize) -> &str {
    safe_slice(s, 0, end)
}
