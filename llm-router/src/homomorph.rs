//! Homomorph integration at the router egress and ingress seams.
//!
//! Reversibly transforms code identifiers in requests before forwarding to providers,
//! and restores original identifiers in provider responses and streaming chunks.

use crate::ir::chat::{ChatRequest, ChatResponse};
use nasiko_homomorph::{
    ForwardResult, HomomorphPolicy, ReverseError, SessionSymbolTable, StreamingHoldbackBuffer,
    forward_transform, reverse_transform,
    vault::{decrypt_session_table, encrypt_session_table, VaultRecord},
};
use nasiko_secrets::SecretsCrypto;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

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
            salt: SecretsCrypto::homomorph_salt(),
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

    /// Construct a context with explicit salt and enablement.
    pub fn with_salt(enabled: bool, salt: Vec<u8>) -> Self {
        Self {
            enabled,
            salt,
            ..Default::default()
        }
    }

    /// Derive a tenant/owner-isolated salt from the platform secret store and owner UUID.
    pub fn for_owner(enabled: bool, owner_id: &str) -> Self {
        let base_salt = SecretsCrypto::homomorph_salt();
        let mut combined = base_salt;
        combined.extend_from_slice(owner_id.as_bytes());
        Self::with_salt(enabled, combined)
    }
}

fn transform_string(
    s: &mut String,
    table: &mut SessionSymbolTable,
    policy: &HomomorphPolicy,
    salt: &[u8],
) -> Result<(), &'static str> {
    let res: ForwardResult = forward_transform(s, table, policy, salt);
    if res.blocked {
        return Err("request blocked: hardcoded credentials detected under Homomorph policy");
    }
    *s = res.text;
    Ok(())
}

fn transform_json_values(
    val: &mut Value,
    table: &mut SessionSymbolTable,
    policy: &HomomorphPolicy,
    salt: &[u8],
) -> Result<(), &'static str> {
    match val {
        Value::String(s) => transform_string(s, table, policy, salt),
        Value::Array(arr) => {
            for item in arr {
                transform_json_values(item, table, policy, salt)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                transform_json_values(item, table, policy, salt)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reverse_json_values(
    val: &mut Value,
    table: &SessionSymbolTable,
) -> Result<(), ReverseError> {
    match val {
        Value::String(s) => {
            *s = reverse_transform(s, table)?;
            Ok(())
        }
        Value::Array(arr) => {
            for item in arr {
                reverse_json_values(item, table)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                reverse_json_values(item, table)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn transform_content_block(
    block: &mut Value,
    table: &mut SessionSymbolTable,
    policy: &HomomorphPolicy,
    salt: &[u8],
) -> Result<(), &'static str> {
    match block {
        Value::String(s) => transform_string(s, table, policy, salt),
        Value::Object(map) => {
            let block_type = map
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            match block_type.as_str() {
                "text" => {
                    if let Some(Value::String(text)) = map.get_mut("text") {
                        transform_string(text, table, policy, salt)?;
                    }
                }
                "tool_result" => {
                    if let Some(content) = map.get_mut("content") {
                        match content {
                            Value::String(s) => transform_string(s, table, policy, salt)?,
                            Value::Array(arr) => {
                                for item in arr {
                                    transform_content_block(item, table, policy, salt)?;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "tool_use" => {
                    if let Some(input) = map.get_mut("input") {
                        transform_json_values(input, table, policy, salt)?;
                    }
                }
                _ => {
                    if let Some(Value::String(text)) = map.get_mut("text") {
                        transform_string(text, table, policy, salt)?;
                    }
                    if let Some(Value::String(content)) = map.get_mut("content") {
                        transform_string(content, table, policy, salt)?;
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reverse_content_block(
    block: &mut Value,
    table: &SessionSymbolTable,
) -> Result<(), ReverseError> {
    match block {
        Value::String(s) => {
            *s = reverse_transform(s, table)?;
            Ok(())
        }
        Value::Object(map) => {
            let block_type = map
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            match block_type.as_str() {
                "text" => {
                    if let Some(Value::String(text)) = map.get_mut("text") {
                        *text = reverse_transform(text, table)?;
                    }
                }
                "tool_result" => {
                    if let Some(content) = map.get_mut("content") {
                        match content {
                            Value::String(s) => {
                                *s = reverse_transform(s, table)?;
                            }
                            Value::Array(arr) => {
                                for item in arr {
                                    reverse_content_block(item, table)?;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "tool_use" => {
                    if let Some(input) = map.get_mut("input") {
                        reverse_json_values(input, table)?;
                    }
                }
                _ => {
                    if let Some(Value::String(text)) = map.get_mut("text") {
                        *text = reverse_transform(text, table)?;
                    }
                    if let Some(Value::String(content)) = map.get_mut("content") {
                        *content = reverse_transform(content, table)?;
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn transform_function_arguments(
    args: &mut String,
    table: &mut SessionSymbolTable,
    policy: &HomomorphPolicy,
    salt: &[u8],
) -> Result<(), &'static str> {
    if let Ok(mut val) = serde_json::from_str::<Value>(args) {
        transform_json_values(&mut val, table, policy, salt)?;
        if let Ok(serialized) = serde_json::to_string(&val) {
            *args = serialized;
            return Ok(());
        }
    }
    transform_string(args, table, policy, salt)
}

fn reverse_function_arguments(
    args: &mut String,
    table: &SessionSymbolTable,
) -> Result<(), ReverseError> {
    if let Ok(mut val) = serde_json::from_str::<Value>(args)
        && reverse_json_values(&mut val, table).is_ok()
        && let Ok(serialized) = serde_json::to_string(&val)
    {
        *args = serialized;
        return Ok(());
    }
    *args = reverse_transform(args, table)?;
    Ok(())
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
        if let Some(content) = msg.content.as_mut() {
            match content {
                Value::String(s) => {
                    transform_string(s, &mut ctx.table, &ctx.policy, &ctx.salt)?;
                }
                Value::Array(blocks) => {
                    for b in blocks {
                        transform_content_block(b, &mut ctx.table, &ctx.policy, &ctx.salt)?;
                    }
                }
                _ => {}
            }
        }

        if let Some(ref mut tool_calls) = msg.tool_calls {
            for call in tool_calls.iter_mut() {
                transform_function_arguments(
                    &mut call.function.arguments,
                    &mut ctx.table,
                    &ctx.policy,
                    &ctx.salt,
                )?;
            }
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
        if let Some(content) = choice.message.content.as_mut() {
            match content {
                Value::String(s) => {
                    *s = reverse_transform(s, &ctx.table)?;
                }
                Value::Array(blocks) => {
                    for b in blocks {
                        reverse_content_block(b, &ctx.table)?;
                    }
                }
                _ => {}
            }
        }

        if let Some(ref mut tool_calls) = choice.message.tool_calls {
            for call in tool_calls.iter_mut() {
                reverse_function_arguments(&mut call.function.arguments, &ctx.table)?;
            }
        }
    }

    Ok(())
}

/// Persist an active session symbol table into `homomorph_vault`.
pub async fn persist_vault(
    db: &PgPool,
    flow_id: &str,
    owner_id: Uuid,
    agent_id: Option<Uuid>,
    table: &SessionSymbolTable,
) {
    if table.is_empty() {
        return;
    }

    let crypto = match SecretsCrypto::try_for_user(owner_id)
        .or_else(|_| SecretsCrypto::try_for_system())
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "nasiko::llm_router::homomorph",
                error = %e,
                "homomorph: could not get encryption key for vault persistence"
            );
            return;
        }
    };

    let session_id = Uuid::new_v4();
    let record = match encrypt_session_table(
        session_id,
        flow_id,
        owner_id,
        agent_id,
        table,
        &crypto,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "nasiko::llm_router::homomorph",
                error = %e,
                "homomorph: failed to encrypt session table"
            );
            return;
        }
    };

    if let Err(e) = sqlx::query(
        "INSERT INTO homomorph_vault \
             (session_id, flow_id, owner_id, agent_id, encrypted_mapping, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, now(), now())",
    )
    .bind(record.session_id)
    .bind(&record.flow_id)
    .bind(record.owner_id)
    .bind(record.agent_id)
    .bind(&record.encrypted_mapping)
    .execute(db)
    .await
    {
        tracing::warn!(
            target: "nasiko::llm_router::homomorph",
            error = %e,
            "homomorph: failed to persist session table to homomorph_vault"
        );
    }
}

/// Retrieve and decrypt an existing session symbol table from `homomorph_vault`.
pub async fn retrieve_vault(
    db: &PgPool,
    flow_id: &str,
    owner_id: Uuid,
) -> Option<SessionSymbolTable> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT encrypted_mapping FROM homomorph_vault \
         WHERE flow_id = $1 AND owner_id = $2 \
         ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(flow_id)
    .bind(owner_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    let encrypted_mapping = row?.0;
    let crypto = SecretsCrypto::try_for_user(owner_id)
        .or_else(|_| SecretsCrypto::try_for_system())
        .ok()?;

    let record = VaultRecord {
        session_id: Uuid::nil(),
        flow_id: flow_id.to_string(),
        owner_id,
        agent_id: None,
        encrypted_mapping,
    };
    decrypt_session_table(&record, &crypto).ok()
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
    use crate::ir::chat::{Choice, FunctionCall, Message, ToolCall};
    use serde_json::json;

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

    #[test]
    fn test_anthropic_content_blocks_transformed_and_reversed() {
        // C2: Anthropic content-block arrays (text, tool_result, tool_use.input)
        let mut req = ChatRequest {
            model: Some("claude-3-5-sonnet".into()),
            messages: vec![
                Message {
                    role: "user".into(),
                    content: Some(json!([
                        {
                            "type": "text",
                            "text": "fn run_audit_report() {}\nPlease inspect run_audit_report() in audit.rs"
                        },
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": "fn run_audit_report() failed with code 500"
                        }
                    ])),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                    extra: Default::default(),
                },
                Message {
                    role: "assistant".into(),
                    content: Some(json!([
                        {
                            "type": "tool_use",
                            "id": "toolu_02",
                            "name": "str_replace_editor",
                            "input": {
                                "command": "str_replace",
                                "path": "audit.rs",
                                "new_str": "fn run_audit_report() { println!(\"fixed\"); }"
                            }
                        }
                    ])),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                    extra: Default::default(),
                },
            ],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: Default::default(),
        };

        let mut ctx = HomomorphContext::new(true);
        apply_forward(&mut req, &mut ctx).expect("forward transform ok");

        // Symbols in all blocks must be pseudonymized
        let user_blocks = req.messages[0].content.as_ref().unwrap().as_array().unwrap();
        let user_text = user_blocks[0]["text"].as_str().unwrap();
        assert!(!user_text.contains("run_audit_report"));
        assert!(user_text.contains("fn_"));

        let tool_res = user_blocks[1]["content"].as_str().unwrap();
        assert!(!tool_res.contains("run_audit_report"));
        assert!(tool_res.contains("fn_"));

        let assistant_blocks = req.messages[1].content.as_ref().unwrap().as_array().unwrap();
        let new_str = assistant_blocks[0]["input"]["new_str"].as_str().unwrap();
        assert!(!new_str.contains("run_audit_report"));
        assert!(new_str.contains("fn_"));

        // Now reverse transform a response containing these blocks
        let mut resp = ChatResponse {
            id: "resp_anthropic".into(),
            object: "chat.completion".into(),
            created: Some(12345),
            model: "claude-3-5-sonnet".into(),
            choices: vec![Choice {
                index: 0,
                message: Message {
                    role: "assistant".into(),
                    content: Some(req.messages[1].content.clone().unwrap()),
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

        apply_reverse_response(&mut resp, &ctx).expect("reverse response ok");
        let reversed_blocks = resp.choices[0].message.content.as_ref().unwrap().as_array().unwrap();
        let reversed_str = reversed_blocks[0]["input"]["new_str"].as_str().unwrap();
        assert!(reversed_str.contains("fn run_audit_report()"));
    }

    #[test]
    fn test_openai_tool_calls_transformed_and_reversed() {
        let mut req = ChatRequest {
            model: Some("gpt-4o".into()),
            messages: vec![Message {
                role: "assistant".into(),
                content: None,
                name: None,
                tool_calls: Some(vec![ToolCall {
                    id: "call_01".into(),
                    kind: "function".into(),
                    function: FunctionCall {
                        name: "execute_code".into(),
                        arguments: json!({
                            "code": "fn calculate_net_income() -> f64 { 1000.0 }"
                        }).to_string(),
                    },
                    extra: Default::default(),
                }]),
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

        let mut ctx = HomomorphContext::new(true);
        apply_forward(&mut req, &mut ctx).expect("forward transform ok");

        let args = &req.messages[0].tool_calls.as_ref().unwrap()[0].function.arguments;
        assert!(!args.contains("calculate_net_income"));
        assert!(args.contains("fn_"));

        let mut resp = ChatResponse {
            id: "resp_openai".into(),
            object: "chat.completion".into(),
            created: Some(12345),
            model: "gpt-4o".into(),
            choices: vec![Choice {
                index: 0,
                message: req.messages[0].clone(),
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
            extra: Default::default(),
        };

        apply_reverse_response(&mut resp, &ctx).expect("reverse response ok");
        let rev_args = &resp.choices[0].message.tool_calls.as_ref().unwrap()[0].function.arguments;
        assert!(rev_args.contains("calculate_net_income"));
    }
}
