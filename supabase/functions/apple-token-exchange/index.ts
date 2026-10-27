// apple-token-exchange
//
// Called by the app right after a native Sign in with Apple, with the
// single-use authorization code Apple returned. Swaps it for a refresh token and
// stores that in `apple_refresh_tokens`, so revoke-apple-tokens can revoke it
// when the account is deleted (App Store guideline 5.1.1(v)). The logic and the
// reasons are in ../_shared/apple_tokens.ts; handler.ts wires the dependencies.
//
// Auth: signed-in users only. verify_jwt stays on, and the handler resolves the
// JWT to a user itself and refuses any account without an Apple identity. It
// also checks that the code Apple exchanged belongs to THAT Apple identity, so
// a caller cannot park someone else's token under their own account.
//
// Body: `{"authorization_code": "<code from Sign in with Apple>"}`
//
// Required Supabase secrets:
//   APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY (the .p8 key, PEM text),
//   APPLE_CLIENT_ID (the bundle id native sign-in uses)
// Auto-provided: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

import 'jsr:@supabase/functions-js@2.112.4/edge-runtime.d.ts';
import { createExchangeHandler } from './handler.ts';

Deno.serve(
  createExchangeHandler({
    supabaseUrl: Deno.env.get('SUPABASE_URL') ?? '',
    serviceRoleKey: Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    appleTeamId: Deno.env.get('APPLE_TEAM_ID') ?? '',
    appleKeyId: Deno.env.get('APPLE_KEY_ID') ?? '',
    applePrivateKey: Deno.env.get('APPLE_PRIVATE_KEY') ?? '',
    appleClientId: Deno.env.get('APPLE_CLIENT_ID') ?? '',
  }),
);
