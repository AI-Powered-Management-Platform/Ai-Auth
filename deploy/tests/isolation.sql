-- Create a table as owner in each schema, then attempt cross-schema access
-- as each service role. Every DENIED line below is a control working.
CREATE TABLE IF NOT EXISTS gateway.sessions (id text primary key);
CREATE TABLE IF NOT EXISTS risk.baselines (id text primary key);
CREATE TABLE IF NOT EXISTS audit.events (id text primary key);
GRANT SELECT, INSERT ON gateway.sessions TO gateway_svc;
GRANT SELECT, INSERT ON risk.baselines TO ai_svc;
GRANT INSERT ON audit.events TO gateway_svc;
GRANT SELECT ON audit.events TO worker_svc;

\echo '--- ai_svc reading gateway.sessions (MUST FAIL) ---'
SET ROLE ai_svc;
\set ON_ERROR_STOP off
SELECT * FROM gateway.sessions;
\echo '--- ai_svc reading its own risk.baselines (must work) ---'
SELECT count(*) FROM risk.baselines;
RESET ROLE;

\echo '--- gateway_svc UPDATE on audit.events (MUST FAIL: append-only) ---'
SET ROLE gateway_svc;
UPDATE audit.events SET id = 'tampered';
\echo '--- gateway_svc DELETE on audit.events (MUST FAIL) ---'
DELETE FROM audit.events;
\echo '--- gateway_svc INSERT into audit.events (must work) ---'
INSERT INTO audit.events VALUES ('ev-1');
RESET ROLE;

\echo '--- worker_svc reading audit.events (must work) ---'
SET ROLE worker_svc;
SELECT count(*) FROM audit.events;
\echo '--- worker_svc reading gateway.sessions (MUST FAIL) ---'
SELECT * FROM gateway.sessions;
RESET ROLE;
