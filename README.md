# flutter-supabase-auth-kit

**The parts of Supabase auth in a Flutter app that a production app had to learn the hard way: native Google and Apple sign-in that works on every iPhone, Apple token revocation for App Review, and linking phones and emails without creating duplicate accounts.**

It comes in two halves, and you can use either one alone:

| Part | What it gives you |
|---|---|
| [`flutter_supabase_auth_kit`](packages/flutter_supabase_auth_kit) (pub.dev) | Native Google and Apple sign-in and identity linking, the Apple nonce retry, phone and email linking with honest outcomes, auth error classification, and a sign-in-method lookup. No UI, and no logging of its own. |
| [`supabase/`](supabase) | Two edge functions and two migrations: **Sign in with Apple token revocation** (exchange the authorization code at sign-in, revoke on a cron once the account is gone) and the `account_signin_methods` lookup. |

## Why it exists

It was built for [GobbleGo](https://gobblego.com), a Flutter + Supabase app. Each part comes from a production failure:

- **Sign in with Apple failed on some real iPhones.** Apple leaves the `nonce` claim out of keychain credentials, and Supabase rejects a sign-in unless the nonce sent and the token's nonce are both present or both absent. A build that checked the claim *still* failed on devices, because what the server verified disagreed with what the app read. Exactly one of the two request shapes can match, so the kit sends one and retries the other.
- **App Review requires revoking Apple tokens when an account is deleted** (guideline 5.1.1(v)), and Supabase doesn't do it. Revoking needs a refresh token, which you can only get by exchanging the single-use authorization code within five minutes of sign-in. The edge functions do the exchange, then a cron sweep revokes tokens for accounts that are gone. A failed revoke is retried on the next run, and no single run can revoke everyone.
- **Returning users got a second account, twice.** A phone number, and later an email, was saved to `profiles` instead of the auth identity. Supabase signs users in against `auth.users`, so each returning user minted a new account and the real one was stranded. The kit writes credentials to the auth identity and reports "confirmation sent" separately from "linked."
- **"Forgot password" said "sent" for accounts that had no password.** `account_signin_methods` tells the app the account uses Google, before the user waits for an email that will never come.

## Quick start

**App:**
```yaml
dependencies:
  flutter_supabase_auth_kit: ^0.1.0
```
```dart
final social = NativeSocialAuth(Supabase.instance.client, googleTokens: googleTokensV7);
final response = await social.signInWithApple(); // null = the user closed the sheet
```
See [the package README](packages/flutter_supabase_auth_kit) for Google setup (6.x and 7.x), linking and errors.

**Server:** copy `supabase/migrations/*` and `supabase/functions/*` into your project, then follow [the functions README](supabase/functions/README.md): create the Apple key, set five secrets, deploy, and schedule the sweep.

By default, revocation runs once the auth user is deleted. If your app holds deleted accounts for a grace period, redefine `apple_token_revocation_due()` to also revoke during it. The migration shows how.

## Security

Every table and function follows the rules in [supabase-security-posture](https://github.com/BrianLandes/supabase-security-posture), and CI runs that check against a live stack:

- `apple_refresh_tokens` has RLS on and is revoked from `anon` and `authenticated`. Only edge functions can touch it.
- `apple_token_revocation_due()` is callable by `service_role` only.
- `account_signin_methods()` is callable by anyone, on purpose: it runs before sign-in. **That makes it an account-existence oracle**, so rate-limit it or put a captcha in front before a public launch.

## Coming next

v0.2 will add the guest layer: a default-deny `guest` role set by a custom access-token hook, one-time tickets that let a guest claim an existing account, and the account lifecycle (deactivate, deletion with a grace period, scheduled purges), with hooks for your own data.

## Development

```bash
cd packages/flutter_supabase_auth_kit && flutter test        # 49 tests, auth server mocked at the HTTP layer
cd supabase/functions && deno task test                        # unit tests
supabase start && scripts/test-integration.sh                  # against a real local stack (ports 547xx)
```

## License

MIT
