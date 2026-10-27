// Request handler for apple-token-exchange, built from explicit config so the
// integration tests can run it in-process against a real database with Apple's
// HTTP faked. index.ts reads the environment and serves it.

import { createClient } from 'npm:@supabase/supabase-js@2.118.0';
import {
  APPLE_TOKEN_URL,
  appleClientSecret,
  handleExchangeRequest,
} from '../_shared/apple_tokens.ts';

export interface ExchangeHandlerConfig {
  supabaseUrl: string;
  serviceRoleKey: string;
  appleTeamId: string;
  appleKeyId: string;
  /// The Sign in with Apple private key (.p8), PEM text.
  applePrivateKey: string;
  /// The client the app signs in with: the iOS bundle id for native sign-in.
  appleClientId: string;
  /// Used for Apple's endpoints only. Defaults to the global fetch.
  appleFetch?: typeof fetch;
  /// Seconds since the epoch. Defaults to the wall clock.
  nowSeconds?: () => number;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

export function createExchangeHandler(
  config: ExchangeHandlerConfig,
): (req: Request) => Promise<Response> {
  const appleFetch = config.appleFetch ?? fetch;
  const nowSeconds = config.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
  const configured = Boolean(
    config.appleTeamId && config.appleKeyId && config.applePrivateKey && config.appleClientId,
  );

  return async (req: Request) => {
    if (req.method === 'OPTIONS') {
      return new Response('ok', { headers: corsHeaders });
    }
    // Fail closed, and distinctly, when misconfigured.
    if (!configured) {
      console.error('Apple key secrets are not set; refusing every request');
      return json(500, { error: 'not_configured' });
    }

    const body = await req.json().catch(() => ({}));
    const sb = createClient(config.supabaseUrl, config.serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const result = await handleExchangeRequest(
      { authorization: req.headers.get('Authorization'), body },
      {
        callerForToken: async (token) => {
          const { data, error } = await sb.auth.getUser(token);
          const user = error ? null : data.user;
          // Anonymous users cannot have an Apple identity worth storing.
          if (!user || user.is_anonymous) return null;
          const apple = (user.identities ?? []).find((i) => i.provider === 'apple');
          const sub = (apple?.identity_data?.sub as string | undefined) ?? apple?.id ?? null;
          return { id: user.id, appleSubject: sub };
        },
        exchangeCode: async (code) => {
          const secret = await appleClientSecret(
            {
              teamId: config.appleTeamId,
              keyId: config.appleKeyId,
              privateKeyPem: config.applePrivateKey,
            },
            config.appleClientId,
            nowSeconds(),
          );
          const res = await appleFetch(APPLE_TOKEN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              client_id: config.appleClientId,
              client_secret: secret,
              code,
              grant_type: 'authorization_code',
            }),
          });
          const parsed = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(`apple ${res.status}: ${parsed?.error ?? 'unknown'}`);
          return parsed;
        },
        storeToken: async (userId, refreshToken) => {
          const { error } = await sb.from('apple_refresh_tokens').upsert({
            user_id: userId,
            refresh_token: refreshToken,
            client_id: config.appleClientId,
            updated_at: new Date().toISOString(),
          });
          if (error) throw error;
        },
      },
    );

    if (result.status >= 500) console.error('apple-token-exchange', result.body);
    return json(result.status, result.body);
  };
}
