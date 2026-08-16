-- Core tables. Everything that outlives a process restart.
--
-- Design rules from docs/data-layer.md, visible in the DDL rather than left
-- to application discipline:
--   * every subject-scoped row carries tenant_id, and every unique index
--     includes it, so a lookup cannot cross tenants even by mistake
--   * personal data is stored as ciphertext plus a wrapped DEK; the plaintext
--     column simply does not exist
--   * search happens through blind indexes, never through plaintext
--   * audit rows are append-only, enforced by the grants in 0001

BEGIN;

-- Tenants -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS control.tenants (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  profile     text NOT NULL DEFAULT 'strict'
              CHECK (profile IN ('strict','balanced','legacy','regulated')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Clients -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS control.clients (
  tenant_id   text NOT NULL REFERENCES control.tenants(id) ON DELETE CASCADE,
  id          text NOT NULL,
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

-- Redirect URIs are their own rows so exactness is a database property:
-- a value either is registered or is not, with no pattern to interpret.
CREATE TABLE IF NOT EXISTS control.client_redirect_uris (
  tenant_id   text NOT NULL,
  client_id   text NOT NULL,
  uri         text NOT NULL,
  PRIMARY KEY (tenant_id, client_id, uri),
  FOREIGN KEY (tenant_id, client_id)
    REFERENCES control.clients(tenant_id, id) ON DELETE CASCADE
);

-- Subjects ------------------------------------------------------------
-- No email column. The address lives encrypted in email_ciphertext, and
-- lookup happens through email_index — a tenant-scoped HMAC produced by the
-- crypto service. Adding a plaintext column here would silently break the
-- cryptographic shredding guarantee.
CREATE TABLE IF NOT EXISTS gateway.subjects (
  tenant_id         text NOT NULL,
  id                text NOT NULL,
  email_index       bytea,
  email_ciphertext  bytea,
  email_wrapped_dek bytea,
  status            text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','suspended','deleted')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

-- The blind index is unique per tenant, never globally: the same address in
-- two tenants produces different indexes and must not collide (T10).
CREATE UNIQUE INDEX IF NOT EXISTS subjects_email_index_uq
  ON gateway.subjects (tenant_id, email_index)
  WHERE email_index IS NOT NULL;

-- Credentials ---------------------------------------------------------
-- Public keys are stored in the clear because they are public. sign_count is
-- updated on every login; without that, clone detection compares against a
-- stale value forever.
CREATE TABLE IF NOT EXISTS gateway.credentials (
  tenant_id     text NOT NULL,
  id            text NOT NULL,
  subject_id    text NOT NULL,
  public_key    bytea NOT NULL,
  sign_count    bigint NOT NULL DEFAULT 0,
  aaguid        bytea,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, subject_id)
    REFERENCES gateway.subjects(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS credentials_by_subject
  ON gateway.credentials (tenant_id, subject_id);

-- Authorization codes -------------------------------------------------
-- Single use is enforced by DELETE ... RETURNING, which is atomic: two
-- concurrent redemptions cannot both win.
CREATE TABLE IF NOT EXISTS gateway.auth_codes (
  code            text PRIMARY KEY,
  tenant_id       text NOT NULL,
  subject_id      text NOT NULL,
  client_id       text NOT NULL,
  redirect_uri    text NOT NULL,
  scope           text NOT NULL,
  nonce           text,
  code_challenge  text NOT NULL,
  auth_time       timestamptz NOT NULL,
  expires_at      timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_codes_expiry ON gateway.auth_codes (expires_at);

-- Revocation ----------------------------------------------------------
-- Two shapes, matching the in-memory design: one row kills one token, one
-- row kills every token a subject held before an instant.
CREATE TABLE IF NOT EXISTS gateway.revoked_tokens (
  jti          text PRIMARY KEY,
  forget_after timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS revoked_tokens_expiry
  ON gateway.revoked_tokens (forget_after);

CREATE TABLE IF NOT EXISTS gateway.revocation_cutoffs (
  tenant_id   text NOT NULL,
  subject_id  text NOT NULL DEFAULT '',
  cutoff      timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, subject_id)
);

-- Audit ---------------------------------------------------------------
-- prev_hash chains each row to the one before it, so a deletion or an edit
-- breaks the chain visibly. The grants in 0001 already forbid UPDATE and
-- DELETE to every service role; this makes tampering detectable even if a
-- grant is ever loosened by mistake.
CREATE TABLE IF NOT EXISTS audit.events (
  seq        bigserial PRIMARY KEY,
  tenant_id  text NOT NULL,
  subject_id text,
  action     text NOT NULL,
  outcome    text NOT NULL,
  request_id text,
  detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash  bytea,
  hash       bytea NOT NULL,
  at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_events_by_tenant ON audit.events (tenant_id, at DESC);

COMMIT;
