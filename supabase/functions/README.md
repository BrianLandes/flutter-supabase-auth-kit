# Server side: Supabase migrations and edge functions

Two pieces of server code that the Flutter package relies on:

1. **Sign in with Apple token revocation** (App Store guideline 5.1.1(v)): a
   table, two edge functions, an SQL hook that decides when a token is due,
   and a cron job.
2. **`account_signin_methods(p_email)`**: a pre-login lookup that lets the
   forgot-password screen say something true instead of "check your inbox"
   forever.

```
supabase/
├── config.toml                                    local stack, ports 547xx
├── security-posture.yaml                          classifications for supabase-security-posture
├── migrations/
│   ├── 20261027120000_account_signin_methods.sql
│   └── 20261027120100_apple_refresh_tokens.sql    table + apple_token_revocation_due()
└── functions/
    ├── _shared/apple_tokens.ts                    pure logic (exchange, client secret, sweep)
    ├── _shared/apple_tokens_test.ts               unit tests, no network
    ├── _tests/integration_test.ts                 against a local stack (RUN_INTEGRATION=true)
    ├── apple-token-exchange/                      index.ts (env) + handler.ts (testable)
    └── revoke-apple-tokens/                       index.ts (env) + handler.ts (testable)
```

To use them in your project, copy the two migrations into your own
`supabase/migrations/` (give them timestamps later than your newest migration,
or `supabase db push` refuses them as out of order) and copy the
`functions/_shared/apple_tokens.ts`, `apple-token-exchange/` and
`revoke-apple-tokens/` folders into your `supabase/functions/`.

---

## Sign in with Apple token revocation

### Why

Apple requires an app that offers Sign in with Apple to revoke the user's Apple
tokens when they delete their account, through
`POST https://appleid.apple.com/auth/revoke`. Revoking needs a refresh token,
and the only way to get one is to exchange the single-use authorization code
Apple gives the app at sign-in. That code expires after five minutes, so it has
to be exchanged right away, not at deletion time.

### How it works

```
sign-in    app ──authorization_code──▶ apple-token-exchange ──▶ Apple /auth/token
                                              │
                                              ▼
                                   public.apple_refresh_tokens   (service_role only)
                                              ▲
cron       pg_cron ──bearer secret──▶ revoke-apple-tokens
                                         │  1. list stored tokens
                                         │  2. rpc apple_token_revocation_due(ids)
                                         │  3. Apple /auth/revoke for each due one
                                         └  4. delete the row (only if Apple said 200)
```

- **apple-token-exchange** is called by the app with the user's session right
  after a native Apple sign-in. It refuses anonymous users and accounts with no
  Apple identity, and it checks that the `sub` of the `id_token` Apple returns
  matches the caller's Apple identity, so nobody can store someone else's token
  under their own account.
- **revoke-apple-tokens** is a sweep on a cron, not a call at deletion time. It
  covers every way an account can disappear (your delete RPC, a purge job, a
  dashboard delete, a tool you write next year), and a failed revoke keeps its
  row and is retried on the next run.
- **The table has no foreign key to `auth.users`, on purpose.** Deleting the
  user must not delete the token: it has to outlive the account until it has
  been revoked. A row whose user is gone is exactly what the sweep looks for.
- **At most 200 revokes per run** (`MAX_REVOKES_PER_RUN`), so a broken
  "is it due?" rule can never sign everyone out of Apple in one go.
- **`{"dryRun": true}`** reports what would be revoked and touches nothing.

### 1. Create the Sign in with Apple key

In the [Apple Developer portal](https://developer.apple.com/account/resources/authkeys/list):

1. **Certificates, Identifiers & Profiles → Identifiers**: open your app's App ID
   and make sure **Sign in with Apple** is enabled.
2. **Keys → +**: name the key, tick **Sign in with Apple**, click **Configure**
   and pick the same App ID as the primary App ID. Continue, register, and
   **download the `.p8` file**. Apple lets you download it once.
3. Note the **Key ID** (shown on the key page) and your **Team ID** (top right
   of the portal, or Membership details).

The client id is the identifier the authorization code was issued to: your
iOS **bundle id** for native sign-in (for example `com.example.app`). Codes from
web sign-in are issued to a Services ID instead; this kit handles native
sign-in.

### 2. Set the secrets

```bash
supabase secrets set \
  APPLE_TEAM_ID='<team id>' \
  APPLE_KEY_ID='<key id>' \
  APPLE_CLIENT_ID='<your bundle id>' \
  APPLE_PRIVATE_KEY="$(cat AuthKey_<key id>.p8)" \
  REVOKE_APPLE_TOKENS_SECRET="$(openssl rand -hex 32)"
```

| Secret | Used by | What |
|---|---|---|
| `APPLE_TEAM_ID` | both | Your Apple Developer Team ID |
| `APPLE_KEY_ID` | both | The Sign in with Apple key's ID |
| `APPLE_PRIVATE_KEY` | both | The `.p8` file's contents (PEM text) |
| `APPLE_CLIENT_ID` | exchange | Your bundle id. Stored with each token; revocation reuses the stored value |
| `REVOKE_APPLE_TOKENS_SECRET` | revoke | The bearer the cron job sends. Keep a copy for step 4 |

`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are provided to every function
automatically. Each function refuses every request with `500 not_configured`
until its secrets are set, rather than running half-configured.

### 3. Apply the migration and deploy

```bash
supabase db push
supabase functions deploy apple-token-exchange
supabase functions deploy revoke-apple-tokens --no-verify-jwt
```

`revoke-apple-tokens` runs with `verify_jwt = false` (also set in
`config.toml`, which `supabase functions deploy` reads). It is called by
pg_cron with a secret you set, not a user JWT, and it checks that secret
itself. A service-role key is the wrong bearer here: the value the platform
injects into functions isn't necessarily the one the dashboard shows, and
projects on the newer `sb_secret_…` keys have them rejected at the gateway
whenever `verify_jwt` is on. `apple-token-exchange` keeps `verify_jwt` on.

The Flutter package calls `apple-token-exchange` after a native Apple sign-in.
Without the package, the call is:

```dart
await supabase.functions.invoke(
  'apple-token-exchange',
  body: {'authorization_code': credential.authorizationCode},
);
```

### 4. Register the cron job

Cron jobs aren't in a migration because they contain per-project values. Run
this once in the SQL editor of each project. The URL and the secret live in
Vault, so neither is stored in plain text in `cron.job`.

```sql
create extension if not exists pg_cron;
create extension if not exists pg_net;

select vault.create_secret('https://<project-ref>.supabase.co', 'project_url');
select vault.create_secret('<REVOKE_APPLE_TOKENS_SECRET>', 'revoke_apple_tokens_secret');

select cron.schedule(
  'revoke-apple-tokens',
  '17 * * * *',  -- hourly at :17, so a deletion is revoked within the hour
  $$
    select net.http_post(
      url     := (select decrypted_secret from vault.decrypted_secrets
                  where name = 'project_url') || '/functions/v1/revoke-apple-tokens',
      headers := jsonb_build_object(
        'Content-Type',  'application/json',
        'Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets
                                       where name = 'revoke_apple_tokens_secret')
      ),
      body    := '{}'::jsonb,
      timeout_milliseconds := 30000
    );
  $$
);
```

If you already have a `project_url` secret in Vault, skip creating it. To
rotate the secret, `supabase secrets set REVOKE_APPLE_TOKENS_SECRET=…` and
`select vault.update_secret('<id>', '<new value>');` (the id is in
`vault.secrets`). To remove the job: `select cron.unschedule('revoke-apple-tokens');`.

Check that it runs:

```sql
select status, return_message, start_time
from cron.job_run_details
where jobid = (select jobid from cron.job where jobname = 'revoke-apple-tokens')
order by start_time desc limit 5;

-- pg_net keeps the HTTP responses for a few hours:
select status_code, content from net._http_response order by created desc limit 5;
```

### 5. Dry run first

Before the first real run, ask what it would do. Nothing is revoked or deleted:

```bash
curl -s -X POST 'https://<project-ref>.supabase.co/functions/v1/revoke-apple-tokens' \
  -H "Authorization: Bearer $REVOKE_APPLE_TOKENS_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"dryRun": true}'
# {"dryRun":true,"checked":12,"due":1,"revoked":0,"failed":0}
```

`checked` is the number of stored tokens, `due` how many the rule selects (after
the per-run cap). If `due` is larger than the number of accounts you expect to
be deleted, fix `apple_token_revocation_due` before the cron runs. A real run
returns the same shape with `revoked` and `failed` filled in. Failed revokes are
logged with Apple's response and retried next run.

### 6. Decide when a token is due: `apple_token_revocation_due`

The sweep asks the database which tokens to revoke, in one call:

```sql
public.apple_token_revocation_due(p_user_ids uuid[]) returns setof uuid
```

It receives every user id with a stored token and returns the ones that are
due. **The default says an account is gone when it has no row in `auth.users`,
or its row is soft-deleted (`deleted_at` set).** That is right if deleting an
account deletes the auth user.

If your app has a **grace period** (the user asks to delete, the account is
purged N days later), you probably want to revoke at the request, since the
user has already said they're leaving. Replace the function in a migration of
your own. For example, with a `profiles.account_status` column where
`'pending_deletion'` marks a deletion request and a purged account has no
profile:

```sql
create or replace function public.apple_token_revocation_due(p_user_ids uuid[])
returns setof uuid
language sql stable security definer set search_path = ''
as $$
  select distinct t.id
  from unnest(p_user_ids) as t(id)
  where not exists (
    select 1 from public.profiles p
    where p.id = t.id
      and coalesce(p.account_status, 'active') <> 'pending_deletion'
  );
$$;
```

Rules for a replacement:

- Keep the name and the signature: the sweep calls it by name with `p_user_ids`.
- Keep `security definer` and `set search_path = ''`, and qualify every name
  (`public.profiles`, `auth.users`).
- Return only ids from `p_user_ids`, and lean towards **not due** when unsure.
  A wrong "due" signs a live user out of Apple for your app.
- `create or replace` keeps the existing grants (service_role only). If you
  `drop` it instead, re-run the `revoke … from public, anon, authenticated` and
  `grant execute … to service_role` lines from the kit's migration. No client
  role should ever be able to call it: it would tell anyone which user ids are
  live accounts.

A user who signs back in with Apple during a grace period gets fresh tokens
from the exchange, so revoking early costs them nothing.

---

## `account_signin_methods(p_email)`

> **Warning: this is an account-existence oracle callable by anon.** Anyone with
> your anon key (anyone with a copy of your app) can ask whether an email has
> an account and which providers it uses. That is deliberate, because the
> forgot-password screen runs signed out, but **put rate limiting and/or a
> captcha in front of it before a public launch**, or leave this migration out
> and accept the blind reset flow.

Supabase's `/recover` returns 200 whether or not the email has an account, and
it also "succeeds" for accounts that only sign in with Apple or Google and have
no password. Either way the user waits for an email that never arrives. This
function returns:

| Field | Type | Meaning |
|---|---|---|
| `account_exists` | boolean | A live, non-anonymous user has this email |
| `has_password` | boolean | That user has an `email` (password) identity |
| `providers` | text[] | Their identity providers, e.g. `{apple,email}` |

So the screen can route: no account → "we couldn't find an account"; account
without a password → "you signed up with Apple/Google"; password account →
send the reset. The lookup ignores case and surrounding whitespace, and
soft-deleted and anonymous users count as no account. It returns nothing that
identifies the user (no id, no timestamps).

```dart
final rows = await supabase.rpc(
  'account_signin_methods',
  params: {'p_email': email},
) as List;
final row = rows.first as Map<String, dynamic>;
```

It is `security definer` because it reads `auth.users` and `auth.identities`,
which client roles can't select. It is granted to `anon` and `authenticated`.

---

## Security posture

Every object follows the same rules:

- `apple_refresh_tokens`: RLS on with **no policies**, and every privilege
  revoked from `anon` and `authenticated`, so a client read is a hard
  `permission denied`. Only the two functions touch it, as `service_role`.
- Each `security definer` function revokes `EXECUTE` from
  `public, anon, authenticated` **by name**, then grants exactly the intended
  roles. On Supabase, `revoke … from public` alone does not lock a function
  down: new functions in `public` are granted to `anon` and `authenticated`
  directly.
- `set search_path = ''` with fully-qualified names, and `p_`-prefixed
  parameters (an unprefixed parameter that matches a column name silently binds
  to the column).

`security-posture.yaml` records the intent, and CI checks the live database
against it with
[`supabase-security-posture`](https://www.npmjs.com/package/supabase-security-posture).
The integration tests also assert the lockdown directly, as anon and as a
signed-in stranger.

## Running the tests

```bash
cd supabase/functions
deno test --allow-env --allow-net   # unit tests; integration tests are skipped
deno lint && deno task check
```

Integration tests run against this repo's own local stack, which uses ports
547xx so it doesn't collide with another Supabase project on the same machine:

```bash
# from the repo root
npx -y supabase@2.117.0 start -x realtime,storage-api,imgproxy,mailpit,postgres-meta,studio,edge-runtime,logflare,vector,supavisor
scripts/test-integration.sh
npx -y supabase-security-posture@0.1.0 check --config supabase/security-posture.yaml \
  --db-url postgresql://postgres:postgres@127.0.0.1:54722/postgres
npx -y supabase@2.117.0 stop --no-backup
```

Always pass `--db-url` to the posture check: without it, the tool defaults to
port 54322, which is some *other* project's local database.

The integration suite exercises both edge-function handlers in-process against
the real table, with Apple's endpoints replaced by an injected `fetch`.
Two paths need a real Apple sign-in and are covered by unit tests only: a
successful exchange, and `account_signin_methods` for an account with no
password.
