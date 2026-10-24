-- Local authorization is independent of identity-provider group claims.
CREATE TABLE IF NOT EXISTS identity_users (
 id text PRIMARY KEY,
 issuer text NOT NULL,
 provider_subject text NOT NULL,
 label text NOT NULL,
 role text NOT NULL DEFAULT 'pending' CHECK (role IN ('pending','reader','analyst','auditor','admin')),
 disabled boolean NOT NULL DEFAULT false,
 version bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 last_login_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS identity_sessions (
 session_hash text PRIMARY KEY,
 user_id text NOT NULL REFERENCES identity_users(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_session_user ON identity_sessions(user_id,expires_at);
CREATE INDEX IF NOT EXISTS audit_action_id ON audit_events(action,id DESC);
CREATE INDEX IF NOT EXISTS audit_subject_id ON audit_events(subject,id DESC);

ALTER TABLE identity_users ADD COLUMN IF NOT EXISTS provider_subject text NOT NULL DEFAULT '';
