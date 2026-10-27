import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import 'package:supabase/supabase.dart';

import 'apple_id_token.dart';
import 'errors.dart';
import 'events.dart';

/// Tokens from a native Google sign-in.
typedef GoogleTokens = ({String? idToken, String? accessToken});

/// Runs the native Google account picker. Returns null when the user dismissed
/// it.
///
/// The kit doesn't depend on `google_sign_in`, whose 6.x and 7.x APIs are
/// incompatible, so an app on either can use the kit. Copy the provider for
/// your version from the README.
typedef GoogleTokenProvider = Future<GoogleTokens?> Function();

/// A native Apple credential.
class AppleCredential {
  const AppleCredential({
    required this.idToken,
    required this.authorizationCode,
    this.givenName,
    this.familyName,
  });

  final String idToken;

  /// Single-use, valid for five minutes. Exchanged server-side for the refresh
  /// token Apple requires you to revoke when the account is deleted.
  final String authorizationCode;
  final String? givenName;
  final String? familyName;
}

/// Runs the native Apple sheet with [hashedNonce]. Throws on failure;
/// a cancellation is recognized by [isAuthFlowCancellation].
typedef AppleCredentialProvider = Future<AppleCredential> Function(
    String hashedNonce);

/// The default [AppleCredentialProvider], via `sign_in_with_apple`.
Future<AppleCredential> nativeAppleCredential(String hashedNonce) async {
  final credential = await SignInWithApple.getAppleIDCredential(
    scopes: [
      AppleIDAuthorizationScopes.email,
      AppleIDAuthorizationScopes.fullName
    ],
    nonce: hashedNonce,
  );
  final idToken = credential.identityToken;
  if (idToken == null) {
    throw const AuthException('Apple returned no identity token.');
  }
  return AppleCredential(
    idToken: idToken,
    authorizationCode: credential.authorizationCode,
    givenName: credential.givenName,
    familyName: credential.familyName,
  );
}

/// Native Google and Apple sign-in and identity linking for Supabase.
///
/// Every method returns null when the user dismissed the sheet, which is not an
/// error and needs no message. Anything else throws, and
/// [classifyAuthError] says how to treat it.
///
/// ```dart
/// final social = NativeSocialAuth(
///   Supabase.instance.client,
///   googleTokens: googleTokensV7(serverClientId: webClientId),
///   onAppleName: (name) => profile.saveName(name),
///   log: (event) => errorReporter.log(event),
/// );
/// final response = await social.signInWithApple();
/// ```
class NativeSocialAuth {
  NativeSocialAuth(
    this.client, {
    this.googleTokens,
    AppleCredentialProvider? appleCredential,
    this.appleTokenExchangeFunction = 'apple-token-exchange',
    this.onAppleName,
    this.log,
  }) : appleCredential = appleCredential ?? nativeAppleCredential;

  final SupabaseClient client;

  /// Required for the Google methods.
  final GoogleTokenProvider? googleTokens;
  final AppleCredentialProvider appleCredential;

  /// The edge function that exchanges Apple's authorization code for a
  /// revocable refresh token (in this kit's `supabase/functions`). Null skips
  /// the exchange, if you handle Apple token revocation another way.
  final String? appleTokenExchangeFunction;

  /// Receives the user's name from Apple, which Apple sends only on the very
  /// first authorization and never again. Save it, or it's gone. App Review
  /// also rejects apps that ask for a name Sign in with Apple already gave.
  final void Function(String fullName)? onAppleName;

  final AuthKitLogger? log;

  /// Signs in (or up) with Google.
  Future<AuthResponse?> signInWithGoogle() async {
    final tokens = await _google();
    if (tokens == null) return null;
    return client.auth.signInWithIdToken(
      provider: OAuthProvider.google,
      idToken: tokens.idToken!,
      accessToken: tokens.accessToken,
    );
  }

  /// Signs in (or up) with Apple.
  Future<AuthResponse?> signInWithApple() async {
    final apple = await _apple();
    if (apple == null) return null;
    final response = await _sendApple(
      apple,
      (nonce) => client.auth.signInWithIdToken(
        provider: OAuthProvider.apple,
        idToken: apple.credential.idToken,
        nonce: nonce,
      ),
    );
    _registerAuthorizationCode(apple.credential.authorizationCode);
    return response;
  }

  /// Adds Google to the signed-in user, keeping their user id. This is how an
  /// anonymous user saves their account.
  ///
  /// Throws an [AuthException] for which [isCredentialInUse] is true when that
  /// Google account already belongs to someone else. Requires manual linking
  /// to be enabled in your project's auth settings.
  Future<AuthResponse?> linkGoogle() async {
    final tokens = await _google();
    if (tokens == null) return null;
    final response = await client.auth.linkIdentityWithIdToken(
      provider: OAuthProvider.google,
      idToken: tokens.idToken!,
      accessToken: tokens.accessToken,
    );
    await _refresh();
    return response;
  }

  /// Adds an Apple ID to the signed-in user. See [linkGoogle].
  Future<AuthResponse?> linkApple() async {
    final apple = await _apple();
    if (apple == null) return null;
    final response = await _sendApple(
      apple,
      (nonce) => client.auth.linkIdentityWithIdToken(
        provider: OAuthProvider.apple,
        idToken: apple.credential.idToken,
        nonce: nonce,
      ),
    );
    await _refresh();
    // After the refresh, so the exchange carries a token for the linked
    // account rather than the one it replaced.
    _registerAuthorizationCode(apple.credential.authorizationCode);
    return response;
  }

  Future<GoogleTokens?> _google() async {
    final provider = googleTokens;
    if (provider == null) {
      throw StateError(
          'NativeSocialAuth needs a googleTokens provider for Google sign-in.');
    }
    final GoogleTokens? tokens;
    try {
      tokens = await provider();
    } catch (e) {
      if (isAuthFlowCancellation(e)) return null;
      rethrow;
    }
    if (tokens == null) return null;
    if (tokens.idToken == null) {
      // A null idToken with an access token almost always means the web
      // (server) client id and the Android OAuth client are mislinked, or a
      // stale cached credential predates the SHA-1 being registered.
      log?.call(AuthKitEvent('google.null_id_token', details: {
        'has_access_token': tokens.accessToken != null,
      }));
      throw const AuthException(
        'Google returned no ID token. Check that serverClientId is your web client ID.',
      );
    }
    return tokens;
  }

  Future<({AppleCredential credential, String rawNonce})?> _apple() async {
    final rawNonce = generateRawNonce();
    final hashedNonce = sha256.convert(utf8.encode(rawNonce)).toString();
    final AppleCredential credential;
    try {
      credential = await appleCredential(hashedNonce);
    } catch (e) {
      if (isAuthFlowCancellation(e)) return null;
      rethrow;
    }
    final name = appleFullName(credential.givenName, credential.familyName);
    if (name.isNotEmpty) onAppleName?.call(name);
    return (credential: credential, rawNonce: rawNonce);
  }

  Future<AuthResponse> _sendApple(
    ({AppleCredential credential, String rawNonce}) apple,
    Future<AuthResponse> Function(String? nonce) send,
  ) =>
      withAppleNonceRetry(
        idToken: apple.credential.idToken,
        rawNonce: apple.rawNonce,
        send: send,
        onMismatch: (error, sentNonce) => log?.call(AuthKitEvent(
          'apple.nonce_mismatch',
          error: error,
          details: {
            'sent_nonce': sentNonce,
            ...appleIdTokenDiagnostics(apple.credential.idToken)
          },
        )),
      );

  Future<void> _refresh() async {
    // A token minted before the link still describes the old identity (for an
    // anonymous user, `is_anonymous: true` and whatever role a hook gave it).
    try {
      await client.auth.refreshSession();
    } catch (e, st) {
      log?.call(AuthKitEvent('link.refresh_failed', error: e, stackTrace: st));
    }
  }

  /// Hands Apple's authorization code to [appleTokenExchangeFunction]. Never
  /// throws and never delays sign-in: a failure is logged, and the next Apple
  /// sign-in tries again with a fresh code.
  void _registerAuthorizationCode(String code) {
    final function = appleTokenExchangeFunction;
    if (function == null) return;
    unawaited(() async {
      try {
        await client.functions
            .invoke(function, body: {'authorization_code': code});
      } catch (e, st) {
        log?.call(AuthKitEvent('apple.token_exchange_failed',
            error: e, stackTrace: st));
      }
    }());
  }
}

/// A random nonce for an Apple request. Apple receives its SHA-256; the auth
/// server receives the raw value and checks the two match.
String generateRawNonce() {
  final random = Random.secure();
  return base64UrlEncode(List<int>.generate(32, (_) => random.nextInt(256)));
}
