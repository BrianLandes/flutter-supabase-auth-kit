-- account_signin_methods(p_email): which ways can this email sign in?
--
-- ┌──────────────────────────────────────────────────────────────────────────┐
-- │ WARNING: THIS IS AN ACCOUNT-EXISTENCE ORACLE, CALLABLE BY ANON.          │
-- │                                                                          │
-- │ Anyone holding your anon key (i.e. anyone with a copy of your app) can   │
-- │ ask whether an email address has an account here, and which providers   │
-- │ it uses. That is deliberate: the forgot-password screen runs before      │
-- │ sign-in, so anon must be able to call it. Before a public launch, put    │
-- │ rate limiting and/or a captcha in front of it, or drop this migration    │
-- │ and accept the blind reset flow. Do not grant it more than it has.       │
-- └──────────────────────────────────────────────────────────────────────────┘
--
-- Why it exists: Supabase's /recover returns 200 whether or not the email
-- matches a user (anti-enumeration), sends nothing for an unknown address, and
-- also "succeeds" for OAuth-only accounts that have no password to reset. Both
-- cases fail silently: the user waits for an email that never comes. This lets
-- the login screen tell three cases apart BEFORE sending a reset:
--
--   no account for that email               -> "we couldn't find an account"
--   account exists, OAuth-only (Apple/Google,
--     no 'email' identity)                  -> steer to the social button
--   account exists WITH a password          -> actually send the reset
--
-- SECURITY DEFINER because it reads the `auth` schema (auth.users,
-- auth.identities), which client roles cannot select. It returns three fields
-- and nothing else: no user id, no timestamps, no metadata.
--
-- Soft-deleted (deleted_at set) and anonymous users are reported as no
-- account: there is nothing to reset for either.

CREATE OR REPLACE FUNCTION public.account_signin_methods(p_email text)
RETURNS TABLE (
  account_exists boolean,
  has_password   boolean,
  providers      text[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user_id   uuid;
  v_providers text[];
BEGIN
  SELECT u.id
    INTO v_user_id
  FROM auth.users u
  WHERE u.email = lower(trim(p_email))
    AND u.deleted_at IS NULL
    AND coalesce(u.is_anonymous, false) = false
  ORDER BY u.created_at
  LIMIT 1;

  IF v_user_id IS NULL THEN
    RETURN QUERY SELECT false, false, ARRAY[]::text[];
    RETURN;
  END IF;

  SELECT coalesce(array_agg(i.provider ORDER BY i.provider), ARRAY[]::text[])
    INTO v_providers
  FROM auth.identities i
  WHERE i.user_id = v_user_id;

  -- GoTrue represents an email/password credential as an 'email' identity.
  RETURN QUERY SELECT true, ('email' = ANY (v_providers)), v_providers;
END;
$$;

-- `REVOKE ... FROM PUBLIC` alone does NOT lock a function down on Supabase:
-- the platform's default privileges grant EXECUTE on every new function in
-- `public` to anon and authenticated BY NAME. Revoke all three explicitly,
-- then grant exactly the roles intended.
REVOKE ALL ON FUNCTION public.account_signin_methods(text) FROM public, anon, authenticated;

-- Pre-login on purpose (see the warning above): the reset flow runs signed out.
GRANT EXECUTE ON FUNCTION public.account_signin_methods(text) TO anon, authenticated;
