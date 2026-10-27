# flutter_supabase_auth_kit

Native Google and Apple sign-in, credential linking and auth error handling for Flutter apps on Supabase, with the fixes a production app found the hard way.

- **Sign in with Apple that doesn't fail on some iPhones.** Apple omits the `nonce` claim from keychain credentials, and Supabase rejects the sign-in when the nonce sent and the token's nonce don't match in presence. Checking the claim isn't enough: on some devices the server still disagrees. The kit sends the right shape and retries the other one once, so sign-in works whichever way the check went wrong.
- **Apple token revocation**, which App Review requires when an account is deleted (guideline 5.1.1(v)) and Supabase doesn't do for you. The kit hands Apple's single-use authorization code to an edge function that stores a revocable refresh token. The functions are [in the repo](https://github.com/BrianLandes/flutter-supabase-auth-kit/tree/main/supabase).
- **Phone and email linking without duplicate accounts.** A credential saved only to your `profiles` table is invisible at sign-in, so the returning user gets a second account. The kit writes it to the auth identity and tells you honestly whether it's linked or only pending a confirmation link.
- **Errors you can act on.** Cancelled, expected (wrong password, taken email) or unexpected, including Apple's "error 1000" dismissal that never says "cancelled".

No UI and no logging of its own. It returns results and reports events, and your app decides what to show and where to log.

Built for [GobbleGo](https://gobblego.com).

## Sign in

```dart
import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';

final social = NativeSocialAuth(
  Supabase.instance.client,
  googleTokens: googleTokensV7, // see "Google" below
  onAppleName: (name) => saveName(name), // Apple sends it once, ever
  log: (event) => errorReporter.log(event),
);

final response = await social.signInWithApple(); // or signInWithGoogle()
if (response == null) return; // the user closed the sheet: say nothing
```

Every method returns `null` when the user dismissed the sheet. Anything else throws; use `classifyAuthError` to decide what to show:

```dart
} on AuthException catch (e) {
  switch (classifyAuthError(e)) {
    case AuthErrorKind.cancelled: return;
    case AuthErrorKind.expected: showMessage(isUserBanned(e) ? 'Account suspended.' : e.message);
    case AuthErrorKind.unexpected: showMessage('Something went wrong.'); report(e);
  }
}
```

### Linking a provider to the signed-in user

`linkGoogle()` and `linkApple()` add an identity while keeping the user id. That's how an anonymous user saves their account. They refresh the session afterwards, so the token stops describing the old identity. If the Google or Apple account already belongs to someone else, they throw an error for which `isCredentialInUse(e)` is true. Enable **manual linking** in your project's auth settings first.

### Apple

- Native Sign in with Apple uses `sign_in_with_apple` (6.1 through 8.x).
- After every Apple sign-in or link, the kit posts the authorization code to the `apple-token-exchange` edge function, without awaiting it and without ever failing sign-in. Deploy the functions from [the repo's `supabase/`](https://github.com/BrianLandes/flutter-supabase-auth-kit/tree/main/supabase), or pass `appleTokenExchangeFunction: null` if you revoke Apple tokens some other way.
- `onAppleName` receives the user's name. **Apple sends it only on the very first authorization**, so if you drop it, it's gone. App Review also rejects apps that ask for a name Sign in with Apple already provided.

### Google

The kit doesn't depend on `google_sign_in`, because its 6.x and 7.x APIs are incompatible and depending on either would lock out apps on the other. Copy the provider for your version.

**google_sign_in 7.x**

```dart
// Once, at startup. serverClientId is your WEB client ID (the one in
// Supabase's Google provider settings); Android needs it for an ID token.
await GoogleSignIn.instance.initialize(serverClientId: webClientId, clientId: iosClientId);

Future<GoogleTokens?> googleTokensV7() async {
  final account = await GoogleSignIn.instance.authenticate();
  return (idToken: account.authentication.idToken, accessToken: null);
}
```

**google_sign_in 6.x**

```dart
GoogleTokenProvider googleTokensV6({required String webClientId, String? iosClientId}) {
  return () async {
    final google = GoogleSignIn(clientId: iosClientId, serverClientId: webClientId);
    // A stale cached credential can return a null idToken on Android even
    // when the OAuth setup is right. Signing out first forces a fresh token.
    try { await google.signOut(); } catch (_) {}
    final user = await google.signIn();
    if (user == null) return null;
    final auth = await user.authentication;
    return (idToken: auth.idToken, accessToken: auth.accessToken);
  };
}
```

A `null` ID token is reported as a `google.null_id_token` event and thrown with a hint. It almost always means `serverClientId` isn't your web client ID.

## Linking a phone or email

**Write credentials to the auth identity, never only to `profiles`.** Supabase Auth matches sign-ins against `auth.users`, so a phone or email that only reached `profiles` gets the returning user a brand-new account.

```dart
switch (await requestPhoneLink(supabase.auth, '+15551234567')) {
  case PhoneLinkStatus.linked: // the project doesn't confirm phone changes
  case PhoneLinkStatus.codeSent: // collect the code, then:
    await confirmPhoneLink(supabase.auth, '+15551234567', code);
  case PhoneLinkStatus.inUse: // offer to sign in to that account instead
}

switch (await requestEmailLink(supabase.auth, email, redirectTo: 'io.supabase.myapp://login-callback/')) {
  case EmailLinkStatus.linked:
  case EmailLinkStatus.confirmationSent: // NOT linked yet: tell them to tap the link
  case EmailLinkStatus.inUse:
}
```

`confirmationSent` means the address is waiting in `auth.users.new_email` until the user taps the link. That might happen on another device, days later, with the app closed. Don't report it as saved. The `redirectTo` URL must be on your project's redirect allow-list (Dashboard → Authentication → URL Configuration), or the link dead-ends in a browser.

## Before "forgot password"

```dart
final methods = await lookUpSignInMethods(supabase, email);
if (methods != null && !methods.hasPassword) {
  // "This account uses Google to sign in" (methods.socialProvider), or "no account"
}
```

Supabase's reset answers "sent" for unknown addresses and for social-only accounts, so the user waits for an email that never comes. This reads the `account_signin_methods` function from [the repo's migrations](https://github.com/BrianLandes/flutter-supabase-auth-kit/tree/main/supabase/migrations). It returns `null` on any failure, so you can fail open and send the reset anyway. **It tells anyone whether an email has an account**, so rate-limit it or add a captcha before a public launch.

## License

MIT
