// The Apple sign-in nonce handling.
//
// The auth server rejects an id_token sign-in when the passed nonce and the token's
// nonce aren't both present or both absent. A production build sent the nonce only when
// the token carried one, and still hit that rejection on real iPhones.
// So it retries once with the opposite choice, and logs what it saw.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';
import 'package:supabase/supabase.dart';

/// An unsigned three-part token with [claims] as its payload, base64url
/// without padding, as Apple sends it.
String _token(Map<String, Object?> claims) {
  String part(Object o) =>
      base64Url.encode(utf8.encode(json.encode(o))).replaceAll('=', '');
  return '${part({'alg': 'RS256', 'kid': 'k'})}.${part(claims)}.sig';
}

final _withNonce = _token({
  'iss': 'https://appleid.apple.com',
  'sub': '001234.abc',
  'email': 'someone@privaterelay.appleid.com',
  'nonce': 'a1b2c3',
  'nonce_supported': true,
});
final _withoutNonce = _token({
  'iss': 'https://appleid.apple.com',
  'sub': '001234.abc',
  'nonce_supported': true,
});

final _mismatch = AuthApiException(
  'Passed nonce and nonce in id_token should either both exist or not.',
  statusCode: '400',
);

final _session = AuthResponse();

void main() {
  group('appleIdTokenHasNonce', () {
    test('true when the claim is present', () {
      expect(appleIdTokenHasNonce(_withNonce), isTrue);
    });

    test('false when the claim is absent, empty or not a string', () {
      expect(appleIdTokenHasNonce(_withoutNonce), isFalse);
      expect(appleIdTokenHasNonce(_token({'nonce': ''})), isFalse);
      expect(appleIdTokenHasNonce(_token({'nonce': 42})), isFalse);
    });

    test('false for anything that is not a readable JWT', () {
      expect(appleIdTokenHasNonce('not-a-jwt'), isFalse);
      expect(appleIdTokenHasNonce('a.%%%.c'), isFalse);
    });
  });

  test('diagnostics carry claim names, never claim values', () {
    final d = appleIdTokenDiagnostics(_withNonce);

    expect(d['payload_decoded'], isTrue);
    expect(d['token_parts'], 3);
    expect(
        d['claim_names'], ['email', 'iss', 'nonce', 'nonce_supported', 'sub']);
    expect(d['nonce_supported'], isTrue);
    final text = d.toString();
    expect(text, isNot(contains('someone@')));
    expect(text, isNot(contains('001234')));
    expect(text, isNot(contains('a1b2c3')));
  });

  group('withAppleNonceRetry', () {
    test('sends the nonce when the token has one', () async {
      final sent = <String?>[];
      await withAppleNonceRetry(
        idToken: _withNonce,
        rawNonce: 'raw',
        send: (n) async {
          sent.add(n);
          return _session;
        },
      );
      expect(sent, ['raw']);
    });

    test('omits the nonce when the token has none', () async {
      final sent = <String?>[];
      await withAppleNonceRetry(
        idToken: _withoutNonce,
        rawNonce: 'raw',
        send: (n) async {
          sent.add(n);
          return _session;
        },
      );
      expect(sent, [null]);
    });

    test('on a presence mismatch, retries once with the opposite choice',
        () async {
      for (final (token, first, second) in [
        (_withNonce, 'raw', null),
        (_withoutNonce, null, 'raw'),
      ]) {
        final sent = <String?>[];
        final reported = <bool>[];
        final result = await withAppleNonceRetry(
          idToken: token,
          rawNonce: 'raw',
          send: (n) async {
            sent.add(n);
            if (sent.length == 1) throw _mismatch;
            return _session;
          },
          onMismatch: (_, sentNonce) => reported.add(sentNonce),
        );
        expect(result, same(_session));
        expect(sent, [first, second]);
        expect(reported, [first != null]);
      }
    });

    test('a second mismatch propagates rather than looping', () async {
      var calls = 0;
      await expectLater(
        withAppleNonceRetry(
          idToken: _withNonce,
          rawNonce: 'raw',
          send: (_) async {
            calls++;
            throw _mismatch;
          },
        ),
        throwsA(isA<AuthApiException>()),
      );
      expect(calls, 2);
    });

    test('any other error propagates without a retry', () async {
      var calls = 0;
      await expectLater(
        withAppleNonceRetry(
          idToken: _withNonce,
          rawNonce: 'raw',
          send: (_) async {
            calls++;
            throw AuthApiException('Nonces mismatch', statusCode: '400');
          },
        ),
        throwsA(isA<AuthApiException>()),
      );
      expect(calls, 1);
    });
  });
}
