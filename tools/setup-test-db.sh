#!/usr/bin/env bash
# setup-test-db.sh — base PostgreSQL locale pour les tests de bout en bout de la console (Linux, droits sudo).
# Rôle « ddi » / base « ddibuntu_test » : valeurs attendues par webui/tests/e2e*.test.ts. Ne jamais utiliser en production.
set -euo pipefail
sudo systemctl start postgresql 2>/dev/null || sudo pg_ctlcluster 16 main start 2>/dev/null || true
sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ddi') THEN CREATE ROLE ddi LOGIN PASSWORD 'ddi-test-pw' CREATEDB; END IF; END $$;
SELECT 'CREATE DATABASE ddibuntu_test OWNER ddi' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ddibuntu_test')\gexec
SQL
echo "OK : base ddibuntu_test prête"
