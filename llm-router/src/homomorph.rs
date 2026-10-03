//! Homomorph integration at the router egress and ingress seams.
//!
//! Reversibly transforms code identifiers in requests before forwarding to providers,
//! and restores original identifiers in provider responses and streaming chunks.

use crate::ir::chat::{ChatRequest, ChatResponse};
use nasiko_homomorph::{
    ForwardResult, HomomorphPolicy, ReverseError, SessionSymbolTable, StreamingHoldbackBuffer,
    forward_transform, reverse_transform,
};
use serde_json::Value;

/// Context holding the session symbol table and policy for a request.
#[derive(Debug, Clone)]
pub struct HomomorphContext {
    pub enabled: bool,
    pub policy: HomomorphPolicy,
    pub table: SessionSymbolTable,
    pub salt: Vec<u8>,
}

impl Default for HomomorphContext {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: HomomorphPolicy::default(),
            table: SessionSymbolTable::new(),
            salt: b"nasiko-router-homomorph-salt".to_vec(),
        }
    }
}

impl HomomorphContext {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }
}

/// Transform request in-place before dispatching to provider.
///
/// Returns whether the request was blocked due to hardcoded secrets.
pub fn apply_forward(
    req: &mut ChatRequest,
    ctx: &mut HomomorphContext,
) -> Result<(), &'static str> {
    if !ctx.enabled {
        return Ok(());
    }

    for msg in &mut req.messages {
        if let Some(Value::String(s)) = msg.content.as_mut() {
            let res: ForwardResult = forward_transform(s, &mut ctx.table, &ctx.policy, &ctx.salt);
            if res.blocked {
                return Err(
                    "request blocked: hardcoded credentials detected under Homomorph policy",
                );
            }
            *s = res.text;
        }
    }

    Ok(())
}

/// Reverse transform an incoming non-streaming response.
pub fn apply_reverse_response(
    resp: &mut ChatResponse,
    ctx: &HomomorphContext,
) -> Result<(), ReverseError> {
    if !ctx.enabled || ctx.table.is_empty() {
        return Ok(());
    }

    for choice in &mut resp.choices {
        if let Some(Value::String(s)) = choice.message.content.as_mut() {
            *s = reverse_transform(s, &ctx.table)?;
        }
        if let Some(ref mut tool_calls) = choice.message.tool_calls {
            for call in tool_calls.iter_mut() {
                call.function.arguments = reverse_transform(&call.function.arguments, &ctx.table)?;
            }
        }
    }

    Ok(())
}

/// Reverse transform streaming text chunk with holdback buffering.
pub struct HomomorphStreamDecoder {
    holdback: StreamingHoldbackBuffer,
    table: SessionSymbolTable,
    enabled: bool,
}

impl HomomorphStreamDecoder {
    pub fn new(ctx: &HomomorphContext) -> Self {
        Self {
            holdback: StreamingHoldbackBuffer::default(),
            table: ctx.table.clone(),
            enabled: ctx.enabled,
        }
    }

    pub fn push(&mut self, chunk: &str) -> Result<String, ReverseError> {
        if !self.enabled || self.table.is_empty() {
            return Ok(chunk.to_string());
        }
        self.holdback.push(chunk, &self.table)
    }

    pub fn finish(self) -> Result<String, ReverseError> {
        if !self.enabled || self.table.is_empty() {
            return Ok(String::new());
        }
        self.holdback.finish(&self.table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::chat::{Choice, Message};

    #[test]
    fn test_byte_identical_when_off() {
        let original_text = "pub fn secret_calc() { let val = 42; }";
        let mut req = ChatRequest {
            model: Some("gpt-4o".into()),
            messages: vec![Message {
                role: "user".into(),
                content: Some(Value::String(original_text.into())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: Default::default(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: Default::default(),
        };

        let mut ctx = HomomorphContext::new(false); // flag OFF
        apply_forward(&mut req, &mut ctx).expect("apply forward ok");

        // Bytes must be byte-identical when off
        assert_eq!(
            req.messages[0].content.as_ref().unwrap().as_str().unwrap(),
            original_text
        );
    }

    #[test]
    fn test_router_forward_and_reverse_roundtrip() {
        let original_text = "pub fn internal_process_order() { let total = 100; }";
        let mut req = ChatRequest {
            model: Some("gpt-4o".into()),
            messages: vec![Message {
                role: "user".into(),
                content: Some(Value::String(original_text.into())),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: Default::default(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: Default::default(),
        };

        let mut ctx = HomomorphContext::new(true); // flag ON
        apply_forward(&mut req, &mut ctx).expect("apply forward ok");

        let egress_text = req.messages[0].content.as_ref().unwrap().as_str().unwrap();
        assert!(!egress_text.contains("internal_process_order"));
        assert!(egress_text.contains("fn_"));

        // Simulate provider replying with the surrogate
        let mut resp = ChatResponse {
            id: "resp_1".into(),
            object: "chat.completion".into(),
            created: Some(12345),
            model: "gpt-4o".into(),
            choices: vec![Choice {
                index: 0,
                message: Message {
                    role: "assistant".into(),
                    content: Some(Value::String(egress_text.to_string())),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                    extra: Default::default(),
                },
                finish_reason: Some("stop".into()),
            }],
            usage: None,
            extra: Default::default(),
        };

        apply_reverse_response(&mut resp, &ctx).expect("apply reverse ok");
        assert_eq!(
            resp.choices[0]
                .message
                .content
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap(),
            original_text
        );
    }
}
