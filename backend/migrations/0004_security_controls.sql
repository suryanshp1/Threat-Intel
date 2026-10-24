-- Durable logout tombstones. Only session fingerprints are stored.
CREATE TABLE IF NOT EXISTS session_revocations (
 session_hash text PRIMARY KEY,
 expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS session_revocation_expiry ON session_revocations(expires_at);
-- Preserve VEX write history and the credential identity; existing documents are untouched.
CREATE TABLE IF NOT EXISTS vex_revisions (
 revision bigserial PRIMARY KEY,
 document_id text NOT NULL,
 subject text NOT NULL,
 before_document jsonb,
 after_document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vex_revision_document ON vex_revisions(document_id,revision DESC);
CREATE INDEX IF NOT EXISTS entities_cve_ref ON intelligence_entities(kind,(data->>'cve_id'));
CREATE INDEX IF NOT EXISTS entities_source_ref ON intelligence_entities(kind,(data->>'source_ref'));
CREATE INDEX IF NOT EXISTS entities_target_ref ON intelligence_entities(kind,(data->>'target_ref'));
CREATE INDEX IF NOT EXISTS entities_entity_id ON intelligence_entities(kind,(data->>'id'));
CREATE INDEX IF NOT EXISTS vex_data ON vex_documents USING gin(data jsonb_path_ops);
