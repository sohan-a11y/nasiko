-- Homomorph Vault storage for pseudonymized session symbol mappings.
--
-- Persists encrypted symbol mappings per flow/session so that downstream tool calls
-- and multi-turn conversations can reversibly restore identifiers without leaking plaintext.
-- Mappings are encrypted at rest using AES-256-GCM via `nasiko-secrets`.

CREATE TABLE homomorph_vault (
    session_id        UUID PRIMARY KEY,
    -- Scope for retrieval. `flow_id` is the W3C traceparent trace-id,
    -- ensuring agents can only decrypt mappings within their own authorized flow.
    flow_id           TEXT NOT NULL,
    owner_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id          UUID REFERENCES agents(id) ON DELETE SET NULL,
    -- Base64 AES-256-GCM ciphertext containing the serialized SessionSymbolTable.
    encrypted_mapping TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scope lookup index for fast retrieval by flow and owner.
CREATE INDEX idx_homomorph_vault_scope
    ON homomorph_vault (flow_id, owner_id);

-- TTL sweep index to clean up completed sessions.
CREATE INDEX idx_homomorph_vault_created
    ON homomorph_vault (created_at);
