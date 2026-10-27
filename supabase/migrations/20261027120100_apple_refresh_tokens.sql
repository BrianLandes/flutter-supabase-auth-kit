-- Sign in with Apple token revocation: storage + the "is it due?" hook.
--
-- App Store guideline 5.1.1(v) requires an app that offers Sign in with Apple
-- to revoke the user's Apple tokens when they delete their account. Revoking
-- needs a refresh token, and the only way to get one is to exchange the
-- single-use authorization code Apple hands the app at sign-in. So:
--
--   apple-token-exchange   (edge function, called by the app right after a
--                          native Apple sign-in) stores the refresh token here.
--   revoke-apple-tokens    (edge function, on a cron) asks
--                          apple_token_revocation_due() which stored tokens
--                          belong to deleted accounts, revokes them with Apple,
--                          and deletes the rows.
--
-- See supabase/functions/_shared/apple_tokens.ts for the logic and
-- supabase/functions/README.md for setup.

-- ── Table ──────────────────────────────────────────────────────────────────
--
-- No foreign key to auth.users, ON PURPOSE. Deleting the user must not delete
-- the token: it has to outlive the account until the sweep has revoked it with
-- Apple. A row whose user is gone is exactly what the sweep looks for. (With
-- ON DELETE CASCADE the token would vanish unrevoked, which is the violation
-- this table exists to prevent.)

CREATE TABLE IF NOT EXISTS public.apple_refresh_tokens (
  user_id        uuid PRIMARY KEY,
  refresh_token  text NOT NULL,
  -- The client the code was issued to (the bundle id for native sign-in, the
  -- Services ID for web). Revoking must use the same one.
  client_id      text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Internal: a refresh token is a credential. Only the two edge functions,
-- running as service_role, read or write it. RLS on with no policies, and every
-- client role's privileges revoked, so a client read is a hard
-- `permission denied` rather than a quietly empty result.
ALTER TABLE public.apple_refresh_tokens ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.apple_refresh_tokens FROM public, anon, authenticated;

-- ── apple_token_revocation_due(p_user_ids) ─────────────────────────────────
--
-- THE EXTENSION POINT. Given the user ids that have a stored token, return the
-- ones whose token must now be revoked. The sweep calls this once per run with
-- every stored id (POSTed as an RPC body, so the list length is not limited by
-- a URL), so keep it a single set-based query.
--
-- Default rule: due when the account is gone, i.e. there is no row in
-- auth.users, or the row is soft-deleted (deleted_at set).
--
-- If your app has a soft-delete GRACE PERIOD (the user asks to delete, the
-- account is purged N days later), you probably want revocation to happen at
-- the request, not at the purge. Replace this function in a later migration of
-- your own with CREATE OR REPLACE. Example, from the production app this kit
-- came from, where `public.profiles.account_status = 'pending_deletion'` marks
-- a deletion request and a missing profile means the account was purged:
--
--   CREATE OR REPLACE FUNCTION public.apple_token_revocation_due(p_user_ids uuid[])
--   RETURNS SETOF uuid
--   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
--   AS $$
--     SELECT DISTINCT t.id
--     FROM unnest(p_user_ids) AS t(id)
--     WHERE NOT EXISTS (
--       SELECT 1 FROM public.profiles p
--       WHERE p.id = t.id
--         AND coalesce(p.account_status, 'active') <> 'pending_deletion'
--     );
--   $$;
--
-- Keep the signature identical (the sweep calls it by name with p_user_ids),
-- keep SECURITY DEFINER + SET search_path = '' with fully-qualified names, and
-- err towards "not due" on anything ambiguous: a false "due" signs a live user
-- out of Apple for this app. (The sweep caps how many it revokes per run, so a
-- bad rule cannot revoke everyone at once, but it can still revoke some.)
-- CREATE OR REPLACE keeps the grants below; re-run them anyway if you DROP.

CREATE OR REPLACE FUNCTION public.apple_token_revocation_due(p_user_ids uuid[])
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT DISTINCT t.id
  FROM unnest(p_user_ids) AS t(id)
  WHERE t.id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM auth.users u
      WHERE u.id = t.id
        AND u.deleted_at IS NULL
    );
$$;

-- Backend only: the sweep runs as service_role. A client must never be able to
-- call this. It would tell anyone which user ids are live accounts.
-- Name the roles explicitly: on Supabase, `REVOKE ... FROM PUBLIC` leaves the
-- default by-name grants to anon and authenticated in place.
REVOKE ALL ON FUNCTION public.apple_token_revocation_due(uuid[]) FROM public, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.apple_token_revocation_due(uuid[]) TO service_role;
