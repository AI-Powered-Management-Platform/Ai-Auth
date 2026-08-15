-- Schema-per-service with least-privilege roles: the data-layer twin of the
-- three-network rule (docs/data-layer.md). Isolation here is grants, not
-- separate database engines.
--
-- The absence that matters: there is NO crypto role in this file. The vault
-- is stateless and holds no database credentials at all.

BEGIN;

CREATE SCHEMA IF NOT EXISTS gateway;   -- sessions, tokens, credentials
CREATE SCHEMA IF NOT EXISTS control;   -- tenants, policy (api writes)
CREATE SCHEMA IF NOT EXISTS risk;      -- behavioural baselines (ai only)
CREATE SCHEMA IF NOT EXISTS audit;     -- append-only, nobody may edit

-- Roles are NOLOGIN group roles; deployment attaches passwords/IAM to login
-- users that inherit them, so credentials never live in a migration.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway_svc') THEN
    CREATE ROLE gateway_svc NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_svc') THEN
    CREATE ROLE api_svc NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'worker_svc') THEN
    CREATE ROLE worker_svc NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ai_svc') THEN
    CREATE ROLE ai_svc NOLOGIN;
  END IF;
END$$;

-- Nobody gets anything by default, including on the public schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE aiauth FROM PUBLIC;
GRANT CONNECT ON DATABASE aiauth TO gateway_svc, api_svc, worker_svc, ai_svc;

-- gateway: owns session state; reads tenant policy but may never write it.
GRANT USAGE ON SCHEMA gateway TO gateway_svc;
GRANT USAGE ON SCHEMA control TO gateway_svc;
ALTER DEFAULT PRIVILEGES IN SCHEMA gateway
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO gateway_svc;
ALTER DEFAULT PRIVILEGES IN SCHEMA control
  GRANT SELECT ON TABLES TO gateway_svc;

-- api: the only writer of tenant policy.
GRANT USAGE ON SCHEMA control TO api_svc;
ALTER DEFAULT PRIVILEGES IN SCHEMA control
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO api_svc;

-- worker: reads control for its jobs, exports audit. No session access.
GRANT USAGE ON SCHEMA control, audit TO worker_svc;
ALTER DEFAULT PRIVILEGES IN SCHEMA control GRANT SELECT ON TABLES TO worker_svc;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit  GRANT SELECT ON TABLES TO worker_svc;

-- ai: its own schema and nothing else. It cannot name a session row.
GRANT USAGE ON SCHEMA risk TO ai_svc;
ALTER DEFAULT PRIVILEGES IN SCHEMA risk
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ai_svc;

-- audit is append-only at the database level: INSERT to the writers, SELECT
-- to the exporter, UPDATE/DELETE to nobody — not even the owner's services.
GRANT USAGE ON SCHEMA audit TO gateway_svc, api_svc;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
  GRANT INSERT ON TABLES TO gateway_svc, api_svc;

COMMIT;
