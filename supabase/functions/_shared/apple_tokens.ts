// Sign in with Apple token storage and revocation.
//
// App Store guideline 5.1.1(v): an app that offers Sign in with Apple must
// revoke the user's Apple tokens when they delete their account, through
// `POST https://appleid.apple.com/auth/revoke`. Revoking needs a refresh token,
// and the only way to get one is to exchange the single-use authorization code
// Apple hands the app at sign-in (it expires after five minutes). So:
//
//   EXCHANGE  apple-token-exchange, called by the app right after a native Apple
//             sign-in. Swaps the code for a refresh token and stores it in
//             `apple_refresh_tokens` (service-role only).
//   REVOKE    revoke-apple-tokens, on a cron. Asks the database which stored
//             tokens are due (`apple_token_revocation_due`, an SQL function you
//             can replace), revokes each with Apple and deletes its row.
//
// A sweep rather than a call at deletion time: it covers every way an account
// can go away (a delete-account RPC, a purge job, a dashboard delete, a future
// admin tool), and it retries a failed revoke on the next run. The table has no
// foreign key to auth.users on purpose, so a token outlives the account until
// it has been revoked.
//
// Kept pure: HTTP, the database and the clock are injected, so every branch is
// covered by apple_tokens_test.ts without Apple or a database.

export const APPLE_TOKEN_URL = 'https://appleid.apple.com/auth/token';
export const APPLE_REVOKE_URL = 'https://appleid.apple.com/auth/revoke';

/// Most tokens one sweep revokes. Bounded so a bad `apple_token_revocation_due`
/// rule (or a bad read) can never revoke everyone in one go; the next run picks
/// up the rest.
export const MAX_REVOKES_PER_RUN = 200;

export interface AppleKeyConfig {
  teamId: string;
  keyId: string;
  /// The Sign in with Apple private key (.p8), PEM text.
  privateKeyPem: string;
}

// ── Client secret ───────────────────────────────────────────────────────────

function base64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlJson(value: unknown): string {
  return base64url(new TextEncoder().encode(JSON.stringify(value)));
}

function pemToPkcs8(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

/// The ES256 JWT Apple accepts as `client_secret` for [clientId]. Valid for
/// five minutes: it is minted per request, never stored.
export async function appleClientSecret(
  config: AppleKeyConfig,
  clientId: string,
  nowSeconds: number,
): Promise<string> {
  const header = { alg: 'ES256', kid: config.keyId, typ: 'JWT' };
  const claims = {
    iss: config.teamId,
    iat: nowSeconds,
    exp: nowSeconds + 300,
    aud: 'https://appleid.apple.com',
    sub: clientId,
  };
  const signingInput = `${base64urlJson(header)}.${base64urlJson(claims)}`;
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToPkcs8(config.privateKeyPem),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  // WebCrypto returns the raw r||s signature JWS expects, not DER.
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      new TextEncoder().encode(signingInput),
    ),
  );
  return `${signingInput}.${base64url(signature)}`;
}

/// The `sub` claim of an id_token, without verifying it. Only used on the
/// id_token Apple returns from /auth/token over TLS, never on client input.
export function idTokenSubject(idToken: string): string | null {
  const parts = idToken.split('.');
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '=')));
    return typeof claims?.sub === 'string' ? claims.sub : null;
  } catch {
    return null;
  }
}

// ── Exchange ────────────────────────────────────────────────────────────────

export interface ExchangeCaller {
  id: string;
  /// The caller's Apple identity (`auth.identities.provider_id` for provider
  /// 'apple'), or null if the account has none.
  appleSubject: string | null;
}

export interface ExchangeDeps {
  /// Resolves the bearer token to the signed-in caller, or null.
  callerForToken: (token: string) => Promise<ExchangeCaller | null>;
  /// POSTs the code to Apple's token endpoint. Returns the parsed body, or
  /// throws with Apple's error.
  exchangeCode: (
    code: string,
  ) => Promise<{ refresh_token?: string; id_token?: string }>;
  storeToken: (userId: string, refreshToken: string) => Promise<void>;
}

export interface HandlerResult {
  status: number;
  body: Record<string, unknown>;
}

export async function handleExchangeRequest(
  input: { authorization: string | null; body: unknown },
  deps: ExchangeDeps,
): Promise<HandlerResult> {
  const token = (input.authorization ?? '').replace(/^Bearer\s+/i, '').trim();
  const caller = token ? await deps.callerForToken(token) : null;
  if (!caller) return { status: 401, body: { error: 'unauthorized' } };

  const code = (input.body as { authorization_code?: unknown } | null)
    ?.authorization_code;
  if (typeof code !== 'string' || code.length === 0 || code.length > 2048) {
    return { status: 400, body: { error: 'missing_authorization_code' } };
  }
  if (!caller.appleSubject) {
    return { status: 403, body: { error: 'no_apple_identity' } };
  }

  let response: { refresh_token?: string; id_token?: string };
  try {
    response = await deps.exchangeCode(code);
  } catch (e) {
    return {
      status: 502,
      body: { error: 'apple_exchange_failed', detail: String(e) },
    };
  }

  // The code is the caller's own only if Apple says it belongs to their Apple
  // identity. Without this, a caller could park someone else's token under
  // their own account.
  const subject = response.id_token ? idTokenSubject(response.id_token) : null;
  if (!subject || subject !== caller.appleSubject) {
    return { status: 403, body: { error: 'identity_mismatch' } };
  }
  if (!response.refresh_token) {
    return { status: 502, body: { error: 'no_refresh_token' } };
  }

  await deps.storeToken(caller.id, response.refresh_token);
  return { status: 200, body: { stored: true } };
}

// ── Revocation sweep ────────────────────────────────────────────────────────

export interface StoredToken {
  user_id: string;
  refresh_token: string;
  client_id: string;
}

export interface SweepDeps {
  listTokens: () => Promise<StoredToken[]>;
  /// The subset of [userIds] whose token must be revoked now. Backed by the
  /// `apple_token_revocation_due` SQL function, which decides what "deleted"
  /// means for your app (by default: no live row in auth.users).
  dueUserIds: (userIds: string[]) => Promise<Set<string>>;
  /// Calls Apple's revoke endpoint. Returns true on HTTP 200.
  revoke: (token: StoredToken) => Promise<boolean>;
  deleteToken: (userId: string) => Promise<void>;
}

export interface SweepResult {
  checked: number;
  due: number;
  revoked: number;
  failed: number;
}

export async function sweepRevocations(
  deps: SweepDeps,
  options: { dryRun?: boolean } = {},
): Promise<SweepResult> {
  const tokens = await deps.listTokens();
  const dueIds = tokens.length === 0
    ? new Set<string>()
    : await deps.dueUserIds(tokens.map((t) => t.user_id));
  const due = tokens
    .filter((t) => dueIds.has(t.user_id))
    .slice(0, MAX_REVOKES_PER_RUN);

  const result: SweepResult = {
    checked: tokens.length,
    due: due.length,
    revoked: 0,
    failed: 0,
  };
  if (options.dryRun) return result;

  for (const token of due) {
    // A failed revoke keeps the row, so the next run tries again.
    if (await deps.revoke(token)) {
      await deps.deleteToken(token.user_id);
      result.revoked++;
    } else {
      result.failed++;
    }
  }
  return result;
}
