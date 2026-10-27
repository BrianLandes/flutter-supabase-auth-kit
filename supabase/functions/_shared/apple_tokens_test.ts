// Unit tests for Sign in with Apple token exchange and revocation.
//
// Run from supabase/functions with: deno test --allow-env --allow-net
// No Apple, network or database: every dependency is a stub.

import { assert, assertEquals } from 'jsr:@std/assert@1';

import {
  appleClientSecret,
  type ExchangeDeps,
  handleExchangeRequest,
  idTokenSubject,
  MAX_REVOKES_PER_RUN,
  type StoredToken,
  sweepRevocations,
} from './apple_tokens.ts';

const USER_ID = '00000000-0000-0000-0000-000000000001';
const APPLE_SUB = '001234.abcdef.0123';

function fakeIdToken(sub: string): string {
  const enc = (v: unknown) =>
    btoa(JSON.stringify(v)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${enc({ alg: 'RS256' })}.${enc({ sub, aud: 'com.example.app' })}.sig`;
}

function exchangeDeps(overrides: Partial<ExchangeDeps> = {}) {
  const stored: Array<{ userId: string; refreshToken: string }> = [];
  const deps: ExchangeDeps = {
    callerForToken: (t) =>
      Promise.resolve(t === 'user-jwt' ? { id: USER_ID, appleSubject: APPLE_SUB } : null),
    exchangeCode: () =>
      Promise.resolve({ refresh_token: 'r-token', id_token: fakeIdToken(APPLE_SUB) }),
    storeToken: (userId, refreshToken) => {
      stored.push({ userId, refreshToken });
      return Promise.resolve();
    },
    ...overrides,
  };
  return { deps, stored };
}

Deno.test('exchange: stores the refresh token for the caller', async () => {
  const { deps, stored } = exchangeDeps();
  const res = await handleExchangeRequest(
    { authorization: 'Bearer user-jwt', body: { authorization_code: 'c' } },
    deps,
  );
  assertEquals(res.status, 200);
  assertEquals(stored, [{ userId: USER_ID, refreshToken: 'r-token' }]);
});

Deno.test('exchange: rejects a caller without a valid session', async () => {
  const { deps, stored } = exchangeDeps();
  for (const authorization of [null, 'Bearer', 'Bearer anon-key']) {
    const res = await handleExchangeRequest(
      { authorization, body: { authorization_code: 'c' } },
      deps,
    );
    assertEquals(res.status, 401);
  }
  assertEquals(stored.length, 0);
});

Deno.test('exchange: needs a code', async () => {
  const { deps, stored } = exchangeDeps();
  for (const body of [{}, null, { authorization_code: '' }, { authorization_code: 7 }]) {
    const res = await handleExchangeRequest({ authorization: 'Bearer user-jwt', body }, deps);
    assertEquals(res.status, 400);
  }
  assertEquals(stored.length, 0);
});

Deno.test('exchange: refuses an account with no Apple identity, before calling Apple', async () => {
  let called = false;
  const { deps, stored } = exchangeDeps({
    callerForToken: () => Promise.resolve({ id: USER_ID, appleSubject: null }),
    exchangeCode: () => {
      called = true;
      return Promise.resolve({});
    },
  });
  const res = await handleExchangeRequest(
    { authorization: 'Bearer user-jwt', body: { authorization_code: 'c' } },
    deps,
  );
  assertEquals(res.status, 403);
  assert(!called, 'Apple must not be called');
  assertEquals(stored.length, 0);
});

Deno.test("exchange: refuses a code that belongs to someone else's Apple ID", async () => {
  const { deps, stored } = exchangeDeps({
    exchangeCode: () =>
      Promise.resolve({ refresh_token: 'r', id_token: fakeIdToken('another.apple.id') }),
  });
  const res = await handleExchangeRequest(
    { authorization: 'Bearer user-jwt', body: { authorization_code: 'c' } },
    deps,
  );
  assertEquals(res.status, 403);
  assertEquals(res.body.error, 'identity_mismatch');
  assertEquals(stored.length, 0);
});

Deno.test('exchange: an Apple error is a 502 and stores nothing', async () => {
  const { deps, stored } = exchangeDeps({
    exchangeCode: () => Promise.reject(new Error('invalid_grant')),
  });
  const res = await handleExchangeRequest(
    { authorization: 'Bearer user-jwt', body: { authorization_code: 'c' } },
    deps,
  );
  assertEquals(res.status, 502);
  assertEquals(stored.length, 0);
});

Deno.test('idTokenSubject reads sub and tolerates garbage', () => {
  assertEquals(idTokenSubject(fakeIdToken('abc')), 'abc');
  assertEquals(idTokenSubject('not-a-jwt'), null);
  assertEquals(idTokenSubject('a.%%%.c'), null);
});

Deno.test('client secret is an ES256 JWT that verifies with the key', async () => {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  let bin = '';
  for (const b of pkcs8) bin += String.fromCharCode(b);
  const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(bin)}\n-----END PRIVATE KEY-----`;

  const jwt = await appleClientSecret(
    { teamId: 'TEAM123', keyId: 'KEY456', privateKeyPem: pem },
    'com.example.app',
    1_700_000_000,
  );
  const [h, c, s] = jwt.split('.');
  const decode = (p: string) =>
    JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(p.length / 4) * 4, '=')));
  assertEquals(decode(h), { alg: 'ES256', kid: 'KEY456', typ: 'JWT' });
  assertEquals(decode(c), {
    iss: 'TEAM123',
    iat: 1_700_000_000,
    exp: 1_700_000_300,
    aud: 'https://appleid.apple.com',
    sub: 'com.example.app',
  });
  const sig = Uint8Array.from(
    atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')),
    (ch) => ch.charCodeAt(0),
  );
  assert(
    await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.publicKey,
      sig,
      new TextEncoder().encode(`${h}.${c}`),
    ),
  );
});

// ── Sweep ──────────────────────────────────────────────────────────────────

function token(userId: string): StoredToken {
  return { user_id: userId, refresh_token: `r-${userId}`, client_id: 'com.example.app' };
}

function dueFrom(ids: string[]) {
  return () => Promise.resolve(new Set(ids));
}

Deno.test('sweep revokes due tokens, deletes them, and keeps the rest', async () => {
  const deleted: string[] = [];
  const revoked: string[] = [];
  let asked: string[] = [];
  const result = await sweepRevocations({
    listTokens: () => Promise.resolve([token('live'), token('leaving'), token('gone')]),
    dueUserIds: (ids) => {
      asked = ids;
      return Promise.resolve(new Set(['leaving', 'gone']));
    },
    revoke: (t) => {
      revoked.push(t.user_id);
      return Promise.resolve(true);
    },
    deleteToken: (id) => {
      deleted.push(id);
      return Promise.resolve();
    },
  });
  assertEquals(asked.sort(), ['gone', 'leaving', 'live'], 'every stored id is asked about');
  assertEquals(revoked.sort(), ['gone', 'leaving']);
  assertEquals(deleted.sort(), ['gone', 'leaving']);
  assertEquals(result, { checked: 3, due: 2, revoked: 2, failed: 0 });
});

Deno.test('sweep ignores ids the due hook returns that have no stored token', async () => {
  const revoked: string[] = [];
  const result = await sweepRevocations({
    listTokens: () => Promise.resolve([token('live')]),
    dueUserIds: dueFrom(['stranger']),
    revoke: (t) => {
      revoked.push(t.user_id);
      return Promise.resolve(true);
    },
    deleteToken: () => Promise.resolve(),
  });
  assertEquals(revoked, []);
  assertEquals(result, { checked: 1, due: 0, revoked: 0, failed: 0 });
});

Deno.test('sweep with no stored tokens does not query the due hook', async () => {
  let called = false;
  const result = await sweepRevocations({
    listTokens: () => Promise.resolve([]),
    dueUserIds: () => {
      called = true;
      return Promise.resolve(new Set());
    },
    revoke: () => Promise.resolve(true),
    deleteToken: () => Promise.resolve(),
  });
  assert(!called);
  assertEquals(result, { checked: 0, due: 0, revoked: 0, failed: 0 });
});

Deno.test('sweep keeps a token whose revoke failed, for the next run', async () => {
  const deleted: string[] = [];
  const result = await sweepRevocations({
    listTokens: () => Promise.resolve([token('gone')]),
    dueUserIds: dueFrom(['gone']),
    revoke: () => Promise.resolve(false),
    deleteToken: (id) => {
      deleted.push(id);
      return Promise.resolve();
    },
  });
  assertEquals(deleted, []);
  assertEquals(result.failed, 1);
});

Deno.test('a failing due hook aborts the sweep before any revoke', async () => {
  let touched = false;
  let threw = false;
  try {
    await sweepRevocations({
      listTokens: () => Promise.resolve([token('gone')]),
      dueUserIds: () => Promise.reject(new Error('db down')),
      revoke: () => {
        touched = true;
        return Promise.resolve(true);
      },
      deleteToken: () => {
        touched = true;
        return Promise.resolve();
      },
    });
  } catch {
    threw = true;
  }
  assert(threw);
  assert(!touched);
});

Deno.test('dry run reports and touches nothing', async () => {
  let touched = false;
  const result = await sweepRevocations(
    {
      listTokens: () => Promise.resolve([token('gone')]),
      dueUserIds: dueFrom(['gone']),
      revoke: () => {
        touched = true;
        return Promise.resolve(true);
      },
      deleteToken: () => {
        touched = true;
        return Promise.resolve();
      },
    },
    { dryRun: true },
  );
  assertEquals(result.due, 1);
  assert(!touched);
});

Deno.test('sweep is capped per run', async () => {
  const many = Array.from({ length: MAX_REVOKES_PER_RUN + 5 }, (_, i) => token(`u${i}`));
  let revokes = 0;
  const result = await sweepRevocations({
    listTokens: () => Promise.resolve(many),
    dueUserIds: (ids) => Promise.resolve(new Set(ids)),
    revoke: () => {
      revokes++;
      return Promise.resolve(true);
    },
    deleteToken: () => Promise.resolve(),
  });
  assertEquals(revokes, MAX_REVOKES_PER_RUN);
  assertEquals(result.due, MAX_REVOKES_PER_RUN);
});
