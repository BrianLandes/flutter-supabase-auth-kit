import 'dart:convert';

import 'package:supabase/supabase.dart';

/// The payload of a JWT, or null when it isn't a readable three-part token.
///
/// Reads the claims without verifying the signature: that's the auth server's
/// job. Everything here only decides which of two request shapes to send.
Map<String, dynamic>? _payload(String idToken) {
  try {
    final parts = idToken.split('.');
    if (parts.length != 3) return null;
    final decoded = json.decode(
      utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))),
    );
    return decoded is Map<String, dynamic> ? decoded : null;
  } catch (_) {
    return null;
  }
}

/// Whether [idToken] carries a `nonce` claim.
///
/// Apple omits the claim when a credential comes from the keychain rather than
/// a fresh Apple ID assertion, even though the app asked for one. Supabase's
/// auth server rejects any request where the nonce sent and the token's nonce
/// aren't both present or both absent.
bool appleIdTokenHasNonce(String idToken) {
  final nonce = _payload(idToken)?['nonce'];
  return nonce is String && nonce.isNotEmpty;
}

/// What the token looked like, for your log when the auth server disagrees
/// with [appleIdTokenHasNonce].
///
/// Claim **names** only, plus Apple's boolean `nonce_supported`. Never the
/// token, and never claim values: `email` and `sub` identify the person.
Map<String, Object?> appleIdTokenDiagnostics(String idToken) {
  final payload = _payload(idToken);
  return {
    'token_parts': idToken.split('.').length,
    'payload_decoded': payload != null,
    'claim_names': payload == null ? null : (payload.keys.toList()..sort()),
    'nonce_claim_type': payload?['nonce']?.runtimeType.toString(),
    'nonce_supported': payload?['nonce_supported'],
  };
}

/// The auth server's "the nonces don't match in presence" rejection (HTTP 400).
bool isNoncePresenceMismatch(Object error) =>
    error is AuthException &&
    error.message.contains('nonce in id_token should either both exist or not');

/// Sends an Apple identity token with [rawNonce] only when the token carries
/// a nonce claim, and retries once with the opposite choice if the auth
/// server still reports a presence mismatch.
///
/// The claim check alone isn't enough. In production it shipped and still
/// failed on real iPhones: on some devices the token the server verifies
/// disagrees with what the app read. Exactly one of the two request shapes
/// can match the token, so the retry makes sign-in work whichever way the
/// check went wrong. [onMismatch] is where to log what the check saw. Any
/// other error, or a second mismatch, propagates unchanged.
///
/// [send] is `signInWithIdToken` or `linkIdentityWithIdToken`, called with the
/// nonce to send (or null).
Future<AuthResponse> withAppleNonceRetry({
  required String idToken,
  required String rawNonce,
  required Future<AuthResponse> Function(String? nonce) send,
  void Function(Object error, bool sentNonce)? onMismatch,
}) async {
  final sendNonce = appleIdTokenHasNonce(idToken);
  try {
    return await send(sendNonce ? rawNonce : null);
  } catch (e) {
    if (!isNoncePresenceMismatch(e)) rethrow;
    onMismatch?.call(e, sendNonce);
    return send(sendNonce ? null : rawNonce);
  }
}

/// Joins the name parts of an Apple credential. Apple sends them only on the
/// very first authorization, so both are usually null and the result empty.
String appleFullName(String? givenName, String? familyName) =>
    [givenName, familyName]
        .map((part) => part?.trim() ?? '')
        .where((part) => part.isNotEmpty)
        .join(' ');

/// Whether [user] signed in with, or has linked, an Apple ID.
bool hasAppleIdentity(User user) {
  final providers = user.appMetadata['providers'];
  if (providers is List && providers.contains('apple')) return true;
  return user.appMetadata['provider'] == 'apple' ||
      (user.identities?.any((identity) => identity.provider == 'apple') ??
          false);
}
