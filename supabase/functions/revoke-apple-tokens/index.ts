// revoke-apple-tokens
//
// Cron sweep: revokes, through Apple's /auth/revoke, the stored Sign in with
// Apple refresh token of every account that `apple_token_revocation_due` says is
// gone, then deletes the row (App Store guideline 5.1.1(v)). A failed revoke
// keeps its row for the next run. At most MAX_REVOKES_PER_RUN per run. The
// logic and the reasons are in ../_shared/apple_tokens.ts; handler.ts wires the
// dependencies.
//
// Auth: a dedicated secret, REVOKE_APPLE_TOKENS_SECRET, with verify_jwt = false
// in config.toml. Why not the service-role key with verify_jwt on? Two reasons
// found in production:
//   - The SUPABASE_SERVICE_ROLE_KEY value the platform injects into the
//     function is not necessarily the key the dashboard hands you, so a cron
//     job cannot reliably reproduce it for a bearer comparison.
//   - Projects on the newer opaque API keys (`sb_secret_...`) have them
//     rejected at the gateway ("Invalid API key") whenever verify_jwt is on,
//     before the function ever runs.
// So the gateway check is off and the function compares the bearer against a
// secret you set yourself. Unset, it refuses every call. The admin client still
// uses SUPABASE_SERVICE_ROLE_KEY: that works for API calls, it just isn't a
// value you can put in a cron job.
//
// Body: `{}` from cron, or `{"dryRun": true}` to report without revoking.
//
// Required Supabase secrets:
//   REVOKE_APPLE_TOKENS_SECRET, APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY
// Auto-provided: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
// Setup and the cron SQL: ../README.md

import 'jsr:@supabase/functions-js@2.112.4/edge-runtime.d.ts';
import { createRevokeHandler } from './handler.ts';

Deno.serve(
  createRevokeHandler({
    supabaseUrl: Deno.env.get('SUPABASE_URL') ?? '',
    serviceRoleKey: Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    secret: Deno.env.get('REVOKE_APPLE_TOKENS_SECRET') ?? '',
    appleTeamId: Deno.env.get('APPLE_TEAM_ID') ?? '',
    appleKeyId: Deno.env.get('APPLE_KEY_ID') ?? '',
    applePrivateKey: Deno.env.get('APPLE_PRIVATE_KEY') ?? '',
  }),
);
