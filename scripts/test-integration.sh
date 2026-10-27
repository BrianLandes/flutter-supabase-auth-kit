#!/usr/bin/env bash
# Run the server integration tests against THIS repo's local stack.
#
#   npx -y supabase@2.117.0 start -x realtime,storage-api,imgproxy,mailpit,postgres-meta,studio,edge-runtime,logflare,vector,supavisor
#   scripts/test-integration.sh
#
# Reads the stack's URL and keys from `supabase status -o env` (run from the
# repo root, so it targets project_id flutter-supabase-auth-kit, ports 547xx).
# Set SUPABASE_CLI to override the CLI command (CI uses the installed `supabase`).
set -euo pipefail
cd "$(dirname "$0")/.."

SUPABASE_CLI="${SUPABASE_CLI:-npx -y supabase@2.117.0}"
eval "$($SUPABASE_CLI status -o env 2>/dev/null | grep -E '^(API_URL|ANON_KEY|SERVICE_ROLE_KEY)=')"

export SUPABASE_URL="$API_URL"
export SUPABASE_ANON_KEY="$ANON_KEY"
export SUPABASE_SERVICE_ROLE_KEY="$SERVICE_ROLE_KEY"
export RUN_INTEGRATION=true

cd supabase/functions
exec deno test --allow-env --allow-net _tests/
