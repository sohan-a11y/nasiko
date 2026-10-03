use nasiko_compress::Policy;
use serde::{Deserialize, Serialize};

/// Configuration for context window management.
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Max estimated tokens before triggering compaction.
    pub max_context_tokens: usize,
    /// Number of recent entries to always preserve verbatim.
    pub keep_recent: usize,
    /// Rough chars-per-token estimate for budget tracking.
    pub chars_per_token: usize,
    /// Structural compression applied to tool results as they are stored.
    ///
    /// This is the store, not the wire: it shrinks what the loop keeps, which also defers
    /// `max_context_tokens` compaction. The llm-router seam compresses what an agent *sends*;
    /// the two compose because compression is idempotent, so a payload that passes through
    /// both is compressed once.
    ///
    /// Disabled by default — an unconfigured loop stores exactly what it stored before.
    pub compress: Policy<'static>,
    /// Compaction mode for handling turns older than keep_recent.
    pub compaction_mode: CompactionMode,
    /// Token budget for the summary before compacting the summary itself.
    pub max_summary_tokens: usize,
}

/// Strategy for compacting entries older than `keep_recent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CompactionMode {
    /// Default: 300-char truncation per entry when compact_simple is called.
    #[default]
    Simple,
    /// Continuous ledger-verified synthesis: entries leaving the window are folded
    /// immediately into the summary with zero silent invisibility window.
    Synthesized,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_context_tokens: 80_000,
            keep_recent: 12,
            chars_per_token: 4,
            compress: Policy::default(),
            compaction_mode: CompactionMode::Simple,
            max_summary_tokens: 40_000,
        }
    }
}

/// Manages conversation history for the ReAct loop.
/// Tracks entries, estimates token usage, and provides compaction.
#[derive(Clone)]
pub struct ContextManager {
    config: ContextConfig,
    entries: Vec<ContextEntry>,
    summary: Option<String>,
    estimated_tokens: usize,
    recovery_store: nasiko_semantic_synth::InMemoryRecoveryStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEntry {
    pub role: ContextRole,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContextRole {
    User,
    Assistant,
    ToolResult { tool_name: String },
    System,
}

impl ContextManager {
    pub fn new(config: ContextConfig) -> Self {
        Self {
            config,
            entries: Vec::new(),
            summary: None,
            estimated_tokens: 0,
            recovery_store: nasiko_semantic_synth::InMemoryRecoveryStore::new(),
        }
    }

    /// Access the in-memory recovery store holding elided text originals.
    pub fn recovery_store(&self) -> &nasiko_semantic_synth::InMemoryRecoveryStore {
        &self.recovery_store
    }

    pub fn push_user(&mut self, content: &str) {
        self.push(ContextEntry {
            role: ContextRole::User,
            content: content.to_string(),
        });
    }

    pub fn push_assistant(&mut self, content: &str) {
        self.push(ContextEntry {
            role: ContextRole::Assistant,
            content: content.to_string(),
        });
    }

    pub fn push_tool_result(&mut self, tool_name: &str, content: &str) {
        // Compress on the way in, so `push`'s token estimate — and therefore the compaction
        // trigger — sees the size the loop will actually carry.
        let stored = nasiko_compress::compress(content, &self.config.compress);
        self.push(ContextEntry {
            role: ContextRole::ToolResult {
                tool_name: tool_name.to_string(),
            },
            content: stored.into_text(),
        });
    }

    fn push(&mut self, entry: ContextEntry) {
        self.estimated_tokens += entry.content.len() / self.config.chars_per_token;
        self.entries.push(entry);

        if self.config.compaction_mode == CompactionMode::Synthesized
            && self.entries.len() > self.config.keep_recent
        {
            self.fold_oldest_into_synthesized_summary();
        }
    }

    fn fold_oldest_into_synthesized_summary(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let oldest = self.entries.remove(0);
        let label = match &oldest.role {
            ContextRole::User => "User".to_string(),
            ContextRole::Assistant => "Assistant".to_string(),
            ContextRole::ToolResult { tool_name } => format!("Tool({tool_name})"),
            ContextRole::System => "System".to_string(),
        };

        let mut anchors = Vec::new();
        for entry in &self.entries {
            anchors.extend(nasiko_semantic_synth::extract_anchors(&entry.content));
        }

        let synth_policy = nasiko_semantic_synth::SynthPolicy {
            compress: self.config.compress,
            enable_code_synth: true,
            recovery_prefix: Some("ctx_rec".into()),
        };

        let synthesized =
            nasiko_semantic_synth::synthesize(&oldest.content, &anchors, &synth_policy);

        for span in synthesized.elided_spans {
            self.recovery_store.store(&span.handle, span.original_text);
        }

        let summary_line = format!("[{label}]: {}", synthesized.text);
        let new_summary = match self.summary.take() {
            Some(existing) => format!("{existing}\n{summary_line}"),
            None => summary_line,
        };
        self.summary = Some(new_summary);

        let summary_tokens = self
            .summary
            .as_ref()
            .map(|s| s.len() / self.config.chars_per_token)
            .unwrap_or(0);
        if summary_tokens > self.config.max_summary_tokens {
            self.compact_summary();
        }

        self.recalculate_tokens();
    }

    /// Compact the summary itself when it exceeds the summary token budget (B5).
    fn compact_summary(&mut self) {
        let Some(summary) = self.summary.take() else {
            return;
        };
        let lines: Vec<&str> = summary.lines().collect();
        if lines.len() <= 2 {
            self.summary = Some(summary);
            return;
        }

        let cut_point = lines.len() / 2;
        let old_lines = lines[..cut_point].join("\n");
        let handle = format!("ctx_sum_{:08x}", {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in old_lines.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x1000_0000_01b3);
            }
            h as u32
        });
        self.recovery_store.store(&handle, old_lines);

        let marker = format!(
            "[⋯ {} prior summary turns elided · recover: {} ⋯]",
            cut_point, handle
        );
        let remaining = lines[cut_point..].join("\n");
        self.summary = Some(format!("{marker}\n{remaining}"));
    }

    pub fn needs_compaction(&self) -> bool {
        self.estimated_tokens > self.config.max_context_tokens
    }

    /// Returns the current context window for the LLM.
    pub fn window(&self) -> ContextWindow {
        if self.entries.len() <= self.config.keep_recent {
            return ContextWindow {
                summary: self.summary.clone(),
                recent: self.entries.clone(),
            };
        }

        let start = self.entries.len() - self.config.keep_recent;
        ContextWindow {
            summary: self.summary.clone(),
            recent: self.entries[start..].to_vec(),
        }
    }

    /// Compact older entries according to the configured compaction_mode (B5).
    pub fn compact(&mut self) {
        match self.config.compaction_mode {
            CompactionMode::Simple => self.compact_simple(),
            CompactionMode::Synthesized => {
                while self.entries.len() > self.config.keep_recent {
                    self.fold_oldest_into_synthesized_summary();
                }
                let summary_tokens = self
                    .summary
                    .as_ref()
                    .map(|s| s.len() / self.config.chars_per_token)
                    .unwrap_or(0);
                if summary_tokens > self.config.max_summary_tokens {
                    self.compact_summary();
                    self.recalculate_tokens();
                }
            }
        }
    }

    /// Compact older entries into a summary string.
    pub fn compact_simple(&mut self) {
        if self.entries.len() <= self.config.keep_recent {
            return;
        }

        let split_at = self.entries.len() - self.config.keep_recent;
        let old: Vec<_> = self.entries.drain(..split_at).collect();

        let mut parts = Vec::new();
        if let Some(ref existing) = self.summary {
            parts.push(format!("[Prior summary]: {existing}"));
        }
        for entry in &old {
            let label = match &entry.role {
                ContextRole::User => "User".to_string(),
                ContextRole::Assistant => "Assistant".to_string(),
                ContextRole::ToolResult { tool_name } => format!("Tool({tool_name})"),
                ContextRole::System => "System".to_string(),
            };
            // Truncate by character count, not byte count — `entry.content` holds
            // LLM/tool output which is attacker-influenceable and may contain
            // multi-byte UTF-8 chars. A raw `&entry.content[..300]` byte slice can
            // land mid-character and panic ("byte index N is not a char boundary").
            let truncated = if entry.content.chars().count() > 300 {
                let head: String = entry.content.chars().take(300).collect();
                format!("{head}…")
            } else {
                entry.content.clone()
            };
            parts.push(format!("[{label}]: {truncated}"));
        }

        self.summary = Some(parts.join("\n"));
        self.recalculate_tokens();
    }

    /// Apply an external summary and drop the old entries.
    pub fn apply_summary(&mut self, summary: String) {
        let split_at = self.entries.len().saturating_sub(self.config.keep_recent);
        if split_at > 0 {
            self.entries.drain(..split_at);
        }
        self.summary = Some(summary);
        self.recalculate_tokens();
    }

    fn recalculate_tokens(&mut self) {
        let entry_tokens: usize = self
            .entries
            .iter()
            .map(|e| e.content.len() / self.config.chars_per_token)
            .sum();
        let summary_tokens = self
            .summary
            .as_ref()
            .map(|s| s.len() / self.config.chars_per_token)
            .unwrap_or(0);
        self.estimated_tokens = entry_tokens + summary_tokens;
    }

    pub fn estimated_tokens(&self) -> usize {
        self.estimated_tokens
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// A snapshot of the context window to include in the LLM prompt.
#[derive(Debug, Clone)]
pub struct ContextWindow {
    pub summary: Option<String>,
    pub recent: Vec<ContextEntry>,
}

impl ContextWindow {
    /// Format as a string block for inclusion in a system prompt.
    pub fn format_for_prompt(&self) -> String {
        let mut out = String::new();

        if let Some(ref summary) = self.summary {
            out.push_str("<conversation-summary>\n");
            out.push_str(summary);
            out.push_str("\n</conversation-summary>\n\n");
        }

        if !self.recent.is_empty() {
            out.push_str("<recent-turns>\n");
            for entry in &self.recent {
                let tag = match &entry.role {
                    ContextRole::User => "user",
                    ContextRole::Assistant => "assistant",
                    ContextRole::ToolResult { tool_name } => tool_name.as_str(),
                    ContextRole::System => "system",
                };
                out.push_str(&format!("<{tag}>{}</{tag}>\n", entry.content));
            }
            out.push_str("</recent-turns>");
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_keep_recent_config() -> ContextConfig {
        ContextConfig {
            max_context_tokens: 1_000_000,
            max_summary_tokens: 40_000,
            keep_recent: 1,
            chars_per_token: 4,
            compress: Policy::default(),
            compaction_mode: CompactionMode::default(),
        }
    }

    // ── IP-3: tool-result compression ───────────────────────────────────────

    /// 300 lines of timestamped log — the shape a tool result actually takes.
    fn noisy_tool_result() -> String {
        (0..300)
            .map(|i| format!("2026-01-01T00:00:00Z INFO handled request {i}\n"))
            .collect()
    }

    fn compressing_config() -> ContextConfig {
        ContextConfig {
            compress: Policy {
                enabled: true,
                min_bytes: 0,
                ..Policy::default()
            },
            ..ContextConfig::default()
        }
    }

    #[test]
    fn tool_results_are_stored_verbatim_by_default() {
        // The zero-behaviour-change guard: an unconfigured loop must store what it always did.
        let payload = noisy_tool_result();
        let mut ctx = ContextManager::new(ContextConfig::default());

        ctx.push_tool_result("fetch_logs", &payload);

        assert_eq!(ctx.entries.last().unwrap().content, payload);
    }

    #[test]
    fn enabling_compression_shrinks_what_is_stored() {
        let payload = noisy_tool_result();
        let mut ctx = ContextManager::new(compressing_config());

        ctx.push_tool_result("fetch_logs", &payload);

        let stored = &ctx.entries.last().unwrap().content;
        assert!(
            stored.len() < payload.len(),
            "stored {} bytes, original {}",
            stored.len(),
            payload.len()
        );
    }

    #[test]
    fn compression_defers_the_compaction_cliff() {
        // The quality claim in PRD §9 IP-3: a smaller store reaches `max_context_tokens` later.
        let payload = noisy_tool_result();

        let mut plain = ContextManager::new(ContextConfig::default());
        let mut compressed = ContextManager::new(compressing_config());
        for _ in 0..20 {
            plain.push_tool_result("fetch_logs", &payload);
            compressed.push_tool_result("fetch_logs", &payload);
        }

        assert!(
            compressed.estimated_tokens < plain.estimated_tokens,
            "compressed {} vs plain {} estimated tokens",
            compressed.estimated_tokens,
            plain.estimated_tokens
        );
    }

    #[test]
    fn a_second_pass_at_the_router_seam_would_be_a_no_op() {
        // IP-3 and IP-1 both run on the same bytes when an agent forwards a stored result.
        // Idempotence (invariant I3) is what keeps that from compounding into a second elision.
        let payload = noisy_tool_result();
        let mut ctx = ContextManager::new(compressing_config());
        ctx.push_tool_result("fetch_logs", &payload);
        let stored = ctx.entries.last().unwrap().content.clone();

        let policy = Policy {
            enabled: true,
            min_bytes: 0,
            ..Policy::default()
        };
        let again = nasiko_compress::compress(&stored, &policy);

        assert_eq!(again.into_text(), stored);
    }

    #[test]
    fn dry_run_measures_without_changing_the_store() {
        let payload = noisy_tool_result();
        let mut ctx = ContextManager::new(ContextConfig {
            compress: Policy {
                enabled: true,
                min_bytes: 0,
                dry_run: true,
                ..Policy::default()
            },
            ..ContextConfig::default()
        });

        ctx.push_tool_result("fetch_logs", &payload);

        assert_eq!(ctx.entries.last().unwrap().content, payload);
    }

    #[test]
    fn compact_simple_truncates_multibyte_content_without_panicking() {
        let mut ctx = ContextManager::new(small_keep_recent_config());

        // 299 ASCII chars followed by a 3-byte '€' character then more ASCII.
        // Byte index 300 lands mid-way through the '€' character's UTF-8
        // encoding — a naive `&content[..300]` byte slice panics here with
        // "byte index 300 is not a char boundary". Truncating by character
        // count instead must not panic.
        let content = format!("{}{}", "a".repeat(299), "€bbbb");
        assert!(content.chars().count() > 300);

        ctx.push_tool_result("tool", &content);
        // A second, recent entry so compact_simple() has something to fold
        // into the summary (the tool result) and something to keep verbatim.
        ctx.push_user("recent turn");

        ctx.compact_simple(); // must not panic

        let summary = ctx.window().summary.expect("summary should be set");
        assert!(
            summary.contains('…'),
            "expected truncation marker in summary: {summary}"
        );
        assert!(
            !summary.contains("bbbb"),
            "content past the 300-char cutoff should have been dropped: {summary}"
        );
    }

    #[test]
    fn compact_simple_leaves_short_content_untruncated() {
        let mut ctx = ContextManager::new(small_keep_recent_config());
        ctx.push_tool_result("tool", "short result");
        ctx.push_user("recent turn");

        ctx.compact_simple();

        let summary = ctx.window().summary.expect("summary should be set");
        assert!(summary.contains("short result"));
        assert!(!summary.contains('…'));
    }

    #[test]
    fn test_flag_off_simple_byte_identical() {
        let mut ctx = ContextManager::new(ContextConfig {
            keep_recent: 2,
            compaction_mode: CompactionMode::Simple,
            ..Default::default()
        });
        ctx.push_user("turn 0");
        ctx.push_user("turn 1");
        ctx.push_user("turn 2");
        // In simple mode, turn 0 is not in recent and not in summary until compacted
        let w = ctx.window();
        assert_eq!(w.recent.len(), 2);
        assert_eq!(w.summary, None);
    }

    #[test]
    fn test_synthesized_mode_no_silent_invisibility() {
        let mut ctx = ContextManager::new(ContextConfig {
            keep_recent: 2,
            compaction_mode: CompactionMode::Synthesized,
            ..Default::default()
        });
        ctx.push_user("CRITICAL_ANCHOR: turn 0 task specification");
        ctx.push_user("turn 1");
        ctx.push_user("turn 2");

        // In synthesized mode, turn 0 was immediately folded into summary
        let w = ctx.window();
        assert_eq!(w.recent.len(), 2);
        let summary = w.summary.expect("Summary must exist in synthesized mode");
        assert!(summary.contains("CRITICAL_ANCHOR: turn 0"));
    }

    #[test]
    fn test_synthesized_mode_summary_budget_compaction() {
        let mut ctx = ContextManager::new(ContextConfig {
            keep_recent: 1,
            compaction_mode: CompactionMode::Synthesized,
            max_summary_tokens: 30,
            chars_per_token: 4,
            ..Default::default()
        });

        for i in 0..10 {
            ctx.push_user(&format!(
                "Turn {i}: Detailed user message with sufficient text to exceed the summary token budget limit"
            ));
        }

        let summary = ctx.window().summary.expect("Summary must exist in synthesized mode");
        assert!(
            summary.contains("prior summary turns elided"),
            "summary must compact itself when exceeding budget: {summary}"
        );
        assert!(
            !ctx.recovery_store().is_empty(),
            "recovery store must hold elided summary text"
        );
    }
}
