// Request handler for revoke-apple-tokens, built from explicit config so the
// integration tests can run the real sweep in-process against a real database
// with Apple's HTTP faked. index.ts reads the environment and serves it.

import { createClient } from 'npm:@supabase/supabase-js@2.118.0';
import {
  APPLE_REVOKE_URL,
  appleClientSecret,
  type StoredToken,
  sweepRevocations,
} from '../_shared/apple_tokens.ts';

export interface RevokeHandlerConfig {
  supabaseUrl: string;
  serviceRoleKey: string;
  /// The bearer secret the caller (pg_cron) must present.
  secret: string;
  appleTeamId: string;
  appleKeyId: string;
  /// The Sign in with Apple private key (.p8), PEM text.
  applePrivateKey: string;
  /// Used for Apple's endpoints only. Defaults to the global fetch.
  appleFetch?: typeof fetch;
  /// Seconds since the epoch. Defaults to the wall clock.
  nowSeconds?: () => number;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/// Constant-time string comparison, so the secret check leaks no timing.
function safeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < Math.max(ea.length, eb.length); i++) {
    diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
  }
  return diff === 0;
}

export function createRevokeHandler(
  config: RevokeHandlerConfig,
): (req: Request) => Promise<Response> {
  const appleFetch = config.appleFetch ?? fetch;
  const nowSeconds = config.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
  const configured = Boolean(
    config.secret && config.appleTeamId && config.appleKeyId && config.applePrivateKey,
  );
  const keyConfig = {
    teamId: config.appleTeamId,
    keyId: config.appleKeyId,
    privateKeyPem: config.applePrivateKey,
  };

  return async (req: Request) => {
    // Fail closed, and distinctly, when misconfigured: an unset secret must
    // refuse every call rather than fall back to something guessable.
    if (!configured) {
      console.error('revoke-apple-tokens secrets are not set; refusing every request');
      return json(500, { error: 'not_configured' });
    }
    if (!safeEqual(req.headers.get('Authorization') ?? '', `Bearer ${config.secret}`)) {
      return json(401, { error: 'unauthorized' });
    }

    let dryRun = false;
    try {
      dryRun = (await req.json())?.dryRun === true;
    } catch {
      // Cron posts '{}'; an empty or malformed body is a normal run.
    }

    const admin = createClient(config.supabaseUrl, config.serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    try {
      const result = await sweepRevocations(
        {
          listTokens: async () => {
            const { data, error } = await admin
              .from('apple_refresh_tokens')
              .select('user_id, refresh_token, client_id');
            if (error) throw error;
            return (data ?? []) as StoredToken[];
          },
          dueUserIds: async (userIds) => {
            // One RPC; the id list travels in the POST body, so no chunking.
            const { data, error } = await admin.rpc('apple_token_revocation_due', {
              p_user_ids: userIds,
            });
            if (error) throw error;
            return new Set((data ?? []) as string[]);
          },
          revoke: async (token: StoredToken) => {
            const secret = await appleClientSecret(keyConfig, token.client_id, nowSeconds());
            const res = await appleFetch(APPLE_REVOKE_URL, {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({
                client_id: token.client_id,
                client_secret: secret,
                token: token.refresh_token,
                token_type_hint: 'refresh_token',
              }),
            });
            if (!res.ok) {
              console.warn(`revoke failed for ${token.user_id}: ${res.status} ${await res.text()}`);
            } else {
              await res.body?.cancel();
            }
            return res.ok;
          },
          deleteToken: async (userId) => {
            const { error } = await admin
              .from('apple_refresh_tokens')
              .delete()
              .eq('user_id', userId);
            if (error) throw error;
          },
        },
        { dryRun },
      );

      console.log('revoke-apple-tokens', { dryRun, ...result });
      return json(200, { dryRun, ...result });
    } catch (e) {
      // A database error aborts the run; rows not yet revoked stay for the next.
      console.error('revoke-apple-tokens failed', e);
      return json(500, { error: 'sweep_failed' });
    }
  };
}
