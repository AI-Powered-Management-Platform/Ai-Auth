#!/usr/bin/env bash
# Proves the data-layer isolation claims against a real Postgres: every
# cross-schema read and every audit mutation must be DENIED. Run by CI.
set -euo pipefail
export MSYS_NO_PATHCONV=1

C=aiauth-isolation-test
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker run -d --name "$C" -e POSTGRES_USER=aiauth -e POSTGRES_PASSWORD=t \
  -e POSTGRES_DB=aiauth postgres:17 >/dev/null
for _ in $(seq 30); do
  docker exec "$C" pg_isready -U aiauth -d aiauth >/dev/null 2>&1 && break
  sleep 1
done

docker exec -i "$C" psql -U aiauth -d aiauth -v ON_ERROR_STOP=1 \
  < deploy/migrations/0001_schemas_and_roles.sql >/dev/null
OUT=$(docker exec -i "$C" psql -U aiauth -d aiauth < deploy/tests/isolation.sql 2>&1)

fail=0
must_deny() {
  if ! printf '%s' "$OUT" | grep -A6 -- "$1" | grep -q "ERROR:  permission denied"; then
    echo "FAIL: expected denial after: $1"; fail=1
  else
    echo "ok (denied): $1"
  fi
}
must_deny "ai_svc reading gateway.sessions"
must_deny "gateway_svc UPDATE on audit.events"
must_deny "gateway_svc DELETE on audit.events"
must_deny "worker_svc reading gateway.sessions"

printf '%s' "$OUT" | grep -q "INSERT 0 1" || { echo "FAIL: append-only INSERT should succeed"; fail=1; }
[ "$fail" -eq 0 ] && echo "db isolation: all controls held"
exit "$fail"
