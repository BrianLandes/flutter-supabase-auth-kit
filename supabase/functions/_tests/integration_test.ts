// Integration tests against a running local stack (this repo's `supabase start`).
//
// Skipped unless RUN_INTEGRATION=true. Connection details come from the
// environment; `scripts/test-integration.sh` (repo root) exports them from
// `supabase status -o env`:
//
//   SUPABASE_URL               (default http://127.0.0.1:54721, this repo's port)
//   SUPABASE_ANON_KEY          (or ANON_KEY)
//   SUPABASE_SERVICE_ROLE_KEY  (or SERVICE_ROLE_KEY)
//
// What is covered:
//   (a) the lockdown: no client role can touch apple_refresh_tokens or call
//       apple_token_revocation_due;
//   (b) account_signin_methods, every branch a local stack can produce;
//   (c) the default apple_token_revocation_due rule;
//   (d) both edge-function handlers end to end against the real table, with
//       Apple's HTTP faked through an injected fetch.
//
// NOT covered: the OAuth-only branch of account_signin_methods
// (account_exists = true, has_password = false). GoTrue always creates an
// 'email' identity for users made through the admin API and refuses to unlink
// the last identity, so a password-less email account cannot be produced
// locally. Reaching it needs a real Apple or Google sign-in. Likewise the
// exchange's success path needs a real Apple identity; its logic is covered by
// the unit tests in _shared/apple_tokens_test.ts.
//
// The tests share this stack's database and clear apple_refresh_tokens, so
// never point them at a database you care about.

import { assert, assertEquals, assertExists } from 'jsr:@std/assert@1';
import { createClient, type SupabaseClient } from 'npm:@supabase/supabase-js@2.118.0';

import { APPLE_REVOKE_URL, APPLE_TOKEN_URL } from '../_shared/apple_tokens.ts';
import { createExchangeHandler } from '../apple-token-exchange/handler.ts';
import { createRevokeHandler } from '../revoke-apple-tokens/handler.ts';

const RUN = Deno.env.get('RUN_INTEGRATION') === 'true';
const URL_ = Deno.env.get('SUPABASE_URL') ?? Deno.env.get('API_URL') ?? 'http://127.0.0.1:54721';
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY') ?? Deno.env.get('ANON_KEY') ?? '';
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ??
  Deno.env.get('SERVICE_ROLE_KEY') ?? '';

const PASSWORD = 'AuthKitTest1!';
const CLIENT_ID = 'com.example.app';
const SECRET = 'test-revoke-secret';

function client(key: string): SupabaseClient {
  return createClient(URL_, key, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

function itest(name: string, fn: () => Promise<void>) {
  Deno.test({ name, ignore: !RUN, fn });
}

const admin = () => client(SERVICE_KEY);
const anon = () => client(ANON_KEY);

function uniqueEmail(tag: string): string {
  return `authkit_${tag}_${Date.now()}_${crypto.randomUUID().slice(0, 8)}@example.test`;
}

async function createUser(tag: string): Promise<{ id: string; email: string }> {
  const email = uniqueEmail(tag);
  const { data, error } = await admin().auth.admin.createUser({
    email,
    password: PASSWORD,
    email_confirm: true,
  });
  if (error) throw error;
  return { id: data.user.id, email };
}

async function deleteUser(id: string, soft = false): Promise<void> {
  const { error } = await admin().auth.admin.deleteUser(id, soft);
  if (error && !soft) throw error;
}

async function signedInClient(email: string): Promise<{ sb: SupabaseClient; jwt: string }> {
  const sb = anon();
  const { data, error } = await sb.auth.signInWithPassword({ email, password: PASSWORD });
  if (error) throw error;
  return { sb, jwt: data.session!.access_token };
}

async function testPem(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  let bin = '';
  for (const b of pkcs8) bin += String.fromCharCode(b);
  return `-----BEGIN PRIVATE KEY-----\n${btoa(bin)}\n-----END PRIVATE KEY-----`;
}

/// A fetch that records every call and answers from [respond].
function fakeApple(respond: (url: string, form: URLSearchParams) => Response) {
  const calls: Array<{ url: string; form: URLSearchParams }> = [];
  const fetchFn = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input instanceof Request ? input.url : String(input);
    const form = new URLSearchParams(String(init?.body ?? ''));
    calls.push({ url, form });
    return Promise.resolve(respond(url, form));
  };
  return { calls, fetch: fetchFn as typeof fetch };
}

async function storeToken(userId: string): Promise<void> {
  const { error } = await admin().from('apple_refresh_tokens').upsert({
    user_id: userId,
    refresh_token: `r-${userId}`,
    client_id: CLIENT_ID,
  });
  if (error) throw error;
}

async function storedIds(): Promise<string[]> {
  const { data, error } = await admin().from('apple_refresh_tokens').select('user_id');
  if (error) throw error;
  return (data ?? []).map((r) => r.user_id as string).sort();
}

async function clearTokens(): Promise<void> {
  const { error } = await admin().from('apple_refresh_tokens').delete().not('user_id', 'is', null);
  if (error) throw error;
}

function expectDenied(error: { code?: string; message?: string } | null, what: string) {
  assertExists(error, `${what} must be refused`);
  assertEquals(error.code, '42501', `${what}: expected permission denied, got ${error.message}`);
}

if (RUN && (!ANON_KEY || !SERVICE_KEY)) {
  throw new Error(
    'RUN_INTEGRATION=true but SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY are unset. ' +
      'Run scripts/test-integration.sh, which exports them from `supabase status`.',
  );
}

// ── (a) lockdown ──────────────────────────────────────────────────────────

itest('anon cannot read or write apple_refresh_tokens', async () => {
  const sb = anon();
  expectDenied((await sb.from('apple_refresh_tokens').select('user_id')).error, 'anon select');
  expectDenied(
    (await sb.from('apple_refresh_tokens').insert({
      user_id: crypto.randomUUID(),
      refresh_token: 'x',
      client_id: 'x',
    })).error,
    'anon insert',
  );
  expectDenied(
    (await sb.from('apple_refresh_tokens').delete().neq('client_id', '')).error,
    'anon delete',
  );
});

itest('a signed-in user cannot read or write apple_refresh_tokens, even their own row', async () => {
  const user = await createUser('tbl');
  try {
    await storeToken(user.id);
    const { sb } = await signedInClient(user.email);
    expectDenied((await sb.from('apple_refresh_tokens').select('user_id')).error, 'user select');
    expectDenied(
      (await sb.from('apple_refresh_tokens').upsert({
        user_id: user.id,
        refresh_token: 'attacker',
        client_id: 'x',
      })).error,
      'user upsert',
    );
    expectDenied(
      (await sb.from('apple_refresh_tokens').delete().eq('user_id', user.id)).error,
      'user delete',
    );
  } finally {
    await admin().from('apple_refresh_tokens').delete().eq('user_id', user.id);
    await deleteUser(user.id);
  }
});

itest('no client role can call apple_token_revocation_due', async () => {
  const params = { p_user_ids: [crypto.randomUUID()] };
  expectDenied((await anon().rpc('apple_token_revocation_due', params)).error, 'anon rpc');

  const user = await createUser('rpc');
  try {
    const { sb } = await signedInClient(user.email);
    expectDenied(
      (await sb.rpc('apple_token_revocation_due', params)).error,
      'authenticated rpc',
    );
  } finally {
    await deleteUser(user.id);
  }
});

// ── (b) account_signin_methods ────────────────────────────────────────────

type Methods = { account_exists: boolean; has_password: boolean; providers: string[] };

async function methods(sb: SupabaseClient, email: string): Promise<Methods> {
  const { data, error } = await sb.rpc('account_signin_methods', { p_email: email });
  if (error) throw error;
  // RETURNS TABLE, so PostgREST hands back a list of one row.
  const row = Array.isArray(data) ? data[0] : data;
  assertExists(row, 'account_signin_methods returned no row');
  return row as Methods;
}

itest('account_signin_methods: shape, password account, case and whitespace', async () => {
  const user = await createUser('pw');
  try {
    // anon can call it: the forgot-password screen runs before sign-in.
    const row = await methods(anon(), user.email);
    assertEquals(
      new Set(Object.keys(row)),
      new Set(['account_exists', 'has_password', 'providers']),
      'exactly the three fields, nothing that identifies the user',
    );
    assertEquals(row.account_exists, true);
    assertEquals(row.has_password, true, 'an email/password account has a resettable password');
    assert(row.providers.includes('email'));

    // The login field is free text; the function does lower(trim(p_email)).
    const sloppy = await methods(anon(), `  ${user.email.toUpperCase()}  `);
    assertEquals(sloppy.account_exists, true);
    assertEquals(sloppy.has_password, true);

    // A signed-in caller gets the same answer.
    const { sb } = await signedInClient(user.email);
    assertEquals((await methods(sb, user.email)).account_exists, true);
  } finally {
    await deleteUser(user.id);
  }
});

itest('account_signin_methods: unknown email reports no account', async () => {
  const row = await methods(anon(), uniqueEmail('nobody'));
  assertEquals(row, { account_exists: false, has_password: false, providers: [] });
});

itest('account_signin_methods: soft- and hard-deleted accounts report no account', async () => {
  const soft = await createUser('softdel');
  const hard = await createUser('harddel');
  try {
    assertEquals((await methods(anon(), soft.email)).account_exists, true);
    await deleteUser(soft.id, true);
    assertEquals(await methods(anon(), soft.email), {
      account_exists: false,
      has_password: false,
      providers: [],
    });

    await deleteUser(hard.id);
    assertEquals((await methods(anon(), hard.email)).account_exists, false);
  } finally {
    await deleteUser(soft.id).catch(() => {});
  }
});

// ── (c) the default apple_token_revocation_due rule ───────────────────────

itest('apple_token_revocation_due: deleted, soft-deleted and unknown ids are due; live ones are not', async () => {
  const live = await createUser('live');
  const gone = await createUser('gone');
  const soft = await createUser('soft');
  const never = crypto.randomUUID();
  try {
    await deleteUser(gone.id);
    await deleteUser(soft.id, true);

    const { data, error } = await admin().rpc('apple_token_revocation_due', {
      p_user_ids: [live.id, gone.id, soft.id, never, gone.id],
    });
    if (error) throw error;
    assertEquals(
      ((data ?? []) as string[]).slice().sort(),
      [gone.id, soft.id, never].sort(),
      'duplicates collapse; the live user is never due',
    );

    const empty = await admin().rpc('apple_token_revocation_due', { p_user_ids: [] });
    assertEquals(empty.error, null);
    assertEquals(empty.data, []);
  } finally {
    await deleteUser(live.id);
    await deleteUser(soft.id).catch(() => {});
  }
});

// ── (d) the edge-function handlers, end to end ────────────────────────────

itest('revoke-apple-tokens: auth, dry run, revoke, and a failed revoke keeps its row', async () => {
  await clearTokens();
  const live = await createUser('sweep_live');
  const gone = await createUser('sweep_gone');
  const flaky = await createUser('sweep_flaky');
  const pem = await testPem();
  try {
    await storeToken(live.id);
    await storeToken(gone.id);
    await storeToken(flaky.id);
    await deleteUser(gone.id);
    await deleteUser(flaky.id);

    const apple = fakeApple((_url, form) =>
      form.get('token') === `r-${flaky.id}`
        ? new Response('{"error":"invalid_client"}', { status: 400 })
        : new Response('', { status: 200 })
    );
    const config = {
      supabaseUrl: URL_,
      serviceRoleKey: SERVICE_KEY,
      secret: SECRET,
      appleTeamId: 'TEAM123',
      appleKeyId: 'KEY456',
      applePrivateKey: pem,
      appleFetch: apple.fetch,
    };
    const handler = createRevokeHandler(config);
    const post = (auth: string | null, body: unknown) =>
      handler(
        new Request('http://localhost/revoke-apple-tokens', {
          method: 'POST',
          headers: auth ? { Authorization: auth } : {},
          body: JSON.stringify(body),
        }),
      );

    // Misconfigured: refuses everything, even the right secret.
    const unconfigured = await createRevokeHandler({ ...config, secret: '' })(
      new Request('http://localhost/', { method: 'POST', headers: { Authorization: 'Bearer ' } }),
    );
    assertEquals(unconfigured.status, 500);
    await unconfigured.body?.cancel();

    for (const auth of [null, 'Bearer wrong', `Bearer ${SECRET}x`, `Bearer ${SERVICE_KEY}`]) {
      const res = await post(auth, {});
      assertEquals(res.status, 401, `auth ${auth?.slice(0, 12)} must be refused`);
      await res.body?.cancel();
    }

    const dry = await post(`Bearer ${SECRET}`, { dryRun: true });
    assertEquals(dry.status, 200);
    assertEquals(await dry.json(), { dryRun: true, checked: 3, due: 2, revoked: 0, failed: 0 });
    assertEquals(apple.calls.length, 0, 'a dry run never calls Apple');
    assertEquals(await storedIds(), [live.id, gone.id, flaky.id].sort());

    const run = await post(`Bearer ${SECRET}`, {});
    assertEquals(run.status, 200);
    assertEquals(await run.json(), { dryRun: false, checked: 3, due: 2, revoked: 1, failed: 1 });

    assertEquals(apple.calls.length, 2);
    for (const call of apple.calls) {
      assertEquals(call.url, APPLE_REVOKE_URL);
      assertEquals(call.form.get('client_id'), CLIENT_ID);
      assertEquals(call.form.get('token_type_hint'), 'refresh_token');
      assertEquals(call.form.get('client_secret')?.split('.').length, 3, 'an ES256 JWT');
    }
    assertEquals(
      apple.calls.map((c) => c.form.get('token')).sort(),
      [`r-${gone.id}`, `r-${flaky.id}`].sort(),
      'the live user is never revoked',
    );
    assertEquals(
      await storedIds(),
      [live.id, flaky.id].sort(),
      'revoked row deleted; failed row kept for the next run',
    );
  } finally {
    await clearTokens();
    await deleteUser(live.id);
  }
});

itest('apple-token-exchange: refuses bad sessions and accounts without an Apple identity', async () => {
  await clearTokens();
  const user = await createUser('exchange');
  const pem = await testPem();
  try {
    const apple = fakeApple(() => new Response('{}', { status: 200 }));
    const config = {
      supabaseUrl: URL_,
      serviceRoleKey: SERVICE_KEY,
      appleTeamId: 'TEAM123',
      appleKeyId: 'KEY456',
      applePrivateKey: pem,
      appleClientId: CLIENT_ID,
      appleFetch: apple.fetch,
    };
    const handler = createExchangeHandler(config);
    const post = (auth: string | null, body: unknown) =>
      handler(
        new Request('http://localhost/apple-token-exchange', {
          method: 'POST',
          headers: auth ? { Authorization: auth } : {},
          body: JSON.stringify(body),
        }),
      );

    const unconfigured = await createExchangeHandler({ ...config, appleClientId: '' })(
      new Request('http://localhost/', { method: 'POST' }),
    );
    assertEquals(unconfigured.status, 500);
    await unconfigured.body?.cancel();

    for (const auth of [null, `Bearer ${ANON_KEY}`, 'Bearer not-a-jwt']) {
      const res = await post(auth, { authorization_code: 'c' });
      assertEquals(res.status, 401);
      await res.body?.cancel();
    }

    const { jwt } = await signedInClient(user.email);
    const noCode = await post(`Bearer ${jwt}`, {});
    assertEquals(noCode.status, 400);
    await noCode.body?.cancel();

    // A real session, but an email/password account: no Apple identity.
    const res = await post(`Bearer ${jwt}`, { authorization_code: 'c' });
    assertEquals(res.status, 403);
    assertEquals((await res.json()).error, 'no_apple_identity');

    assertEquals(
      apple.calls.filter((c) => c.url === APPLE_TOKEN_URL).length,
      0,
      'Apple is never called for a caller who cannot own the code',
    );
    assertEquals(await storedIds(), []);
  } finally {
    await deleteUser(user.id);
  }
});
