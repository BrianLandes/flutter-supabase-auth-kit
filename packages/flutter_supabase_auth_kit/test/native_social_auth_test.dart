import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:supabase/supabase.dart';

import 'fake_supabase.dart';

final _appleTokenWithNonce = fakeJwt(
    {'iss': 'https://appleid.apple.com', 'sub': 'apple-sub', 'nonce': 'x'});
final _appleTokenWithoutNonce =
    fakeJwt({'iss': 'https://appleid.apple.com', 'sub': 'apple-sub'});

/// An Apple provider that records the hashed nonce it was asked for.
({List<String> hashedNonces, AppleCredentialProvider provider}) _apple({
  String? idToken,
  String? given,
  String? family,
  Object? throws,
}) {
  final hashedNonces = <String>[];
  Future<AppleCredential> provider(String hashedNonce) async {
    hashedNonces.add(hashedNonce);
    if (throws != null) throw throws;
    return AppleCredential(
      idToken: idToken ?? _appleTokenWithNonce,
      authorizationCode: 'auth-code',
      givenName: given,
      familyName: family,
    );
  }

  return (hashedNonces: hashedNonces, provider: provider);
}

Future<http.Response> _happyServer(http.Request r) async {
  if (r.url.path.endsWith('/token')) return sessionResponse();
  if (r.url.path.endsWith('/user/identities/link_token') ||
      r.url.path.contains('/token')) {
    return sessionResponse();
  }
  if (r.url.path.contains('/functions/v1/')) return http.Response('{}', 200);
  return http.Response('{}', 200);
}

Future<void> _settle() =>
    Future<void>.delayed(const Duration(milliseconds: 20));

void main() {
  group('signInWithApple', () {
    test('sends the raw nonce whose SHA-256 Apple was given', () async {
      final fake = FakeSupabase(_happyServer);
      final apple = _apple();
      await NativeSocialAuth(fake.client, appleCredential: apple.provider)
          .signInWithApple();

      final tokenCall = fake.to('grant_type=id_token').single;
      final body = fake.bodyOf(tokenCall);
      expect(body['provider'], 'apple');
      expect(body['id_token'], _appleTokenWithNonce);
      final rawNonce = body['nonce'] as String;
      expect(sha256.convert(utf8.encode(rawNonce)).toString(),
          apple.hashedNonces.single);
    });

    test('omits the nonce when the token carries none (keychain credentials)',
        () async {
      final fake = FakeSupabase(_happyServer);
      await NativeSocialAuth(fake.client,
              appleCredential:
                  _apple(idToken: _appleTokenWithoutNonce).provider)
          .signInWithApple();
      expect(
          fake.bodyOf(fake.to('grant_type=id_token').single)['nonce'], isNull);
    });

    test('retries the other way on a nonce presence mismatch, and logs it',
        () async {
      var calls = 0;
      final fake = FakeSupabase((r) async {
        if (r.url.query.contains('grant_type=id_token') && ++calls == 1) {
          return authError(400,
              'Passed nonce and nonce in id_token should either both exist or not.');
        }
        return _happyServer(r);
      });
      final events = <AuthKitEvent>[];
      final response = await NativeSocialAuth(fake.client,
              appleCredential: _apple().provider, log: events.add)
          .signInWithApple();

      expect(response?.session, isNotNull);
      final sent = fake
          .to('grant_type=id_token')
          .map((r) => fake.bodyOf(r)['nonce'])
          .toList();
      expect(sent.first, isNotNull);
      expect(sent.last, isNull);
      expect(events.single.name, 'apple.nonce_mismatch');
      expect(events.single.details['sent_nonce'], isTrue);
      expect(events.single.details.toString(), isNot(contains('apple-sub')),
          reason: 'diagnostics carry claim names, never values');
    });

    test('hands the authorization code to the exchange function, after sign-in',
        () async {
      final fake = FakeSupabase(_happyServer);
      await NativeSocialAuth(fake.client, appleCredential: _apple().provider)
          .signInWithApple();
      await _settle();

      final exchange = fake.to('/functions/v1/apple-token-exchange').single;
      expect(fake.bodyOf(exchange), {'authorization_code': 'auth-code'});
      expect(
          exchange.headers['authorization'] ??
              exchange.headers['Authorization'],
          contains(fakeJwt({}).split('.').first),
          reason: 'carries the signed-in user, not just the anon key');
      expect(fake.requests.indexOf(exchange),
          greaterThan(fake.requests.indexOf(fake.to('grant_type').single)));
    });

    test('a failed exchange never fails sign-in; it is logged', () async {
      final fake = FakeSupabase((r) async => r.url.path.contains('/functions/')
          ? http.Response('{"error":"boom"}', 500)
          : _happyServer(r));
      final events = <AuthKitEvent>[];
      final response = await NativeSocialAuth(fake.client,
              appleCredential: _apple().provider, log: events.add)
          .signInWithApple();
      await _settle();

      expect(response?.session, isNotNull);
      expect(events.map((e) => e.name), ['apple.token_exchange_failed']);
    });

    test('a null exchange function skips it', () async {
      final fake = FakeSupabase(_happyServer);
      await NativeSocialAuth(fake.client,
              appleCredential: _apple().provider,
              appleTokenExchangeFunction: null)
          .signInWithApple();
      await _settle();
      expect(fake.to('/functions/'), isEmpty);
    });

    test("passes on Apple's one-time name", () async {
      final names = <String>[];
      final fake = FakeSupabase(_happyServer);
      await NativeSocialAuth(fake.client,
              appleCredential:
                  _apple(given: 'Ada', family: 'Lovelace').provider,
              onAppleName: names.add)
          .signInWithApple();
      await NativeSocialAuth(fake.client,
              appleCredential: _apple().provider, onAppleName: names.add)
          .signInWithApple();
      expect(names, ['Ada Lovelace'],
          reason: 'nothing on the repeat authorization');
    });

    test('a dismissed sheet returns null and calls nothing', () async {
      final fake = FakeSupabase(_happyServer);
      final result = await NativeSocialAuth(fake.client,
              appleCredential:
                  _apple(throws: Exception('AuthorizationError error 1000'))
                      .provider)
          .signInWithApple();
      expect(result, isNull);
      expect(fake.requests, isEmpty);
    });
  });

  group('Google', () {
    test('signs in with the id and access tokens', () async {
      final fake = FakeSupabase(_happyServer);
      await NativeSocialAuth(fake.client,
              googleTokens: () async => (idToken: 'g-id', accessToken: 'g-at'))
          .signInWithGoogle();
      final body = fake.bodyOf(fake.to('grant_type=id_token').single);
      expect(body['provider'], 'google');
      expect(body['id_token'], 'g-id');
      expect(body['access_token'], 'g-at');
    });

    test('a dismissed picker returns null', () async {
      final fake = FakeSupabase(_happyServer);
      expect(
          await NativeSocialAuth(fake.client, googleTokens: () async => null)
              .signInWithGoogle(),
          isNull);
      expect(fake.requests, isEmpty);
    });

    test('a missing id token is reported with a hint, not sent', () async {
      final fake = FakeSupabase(_happyServer);
      final events = <AuthKitEvent>[];
      await expectLater(
        NativeSocialAuth(fake.client,
                googleTokens: () async => (idToken: null, accessToken: 'g-at'),
                log: events.add)
            .signInWithGoogle(),
        throwsA(isA<AuthException>()
            .having((e) => e.message, 'message', contains('serverClientId'))),
      );
      expect(events.single.name, 'google.null_id_token');
      expect(fake.requests, isEmpty);
    });

    test('no provider configured is a programming error', () async {
      expect(
          NativeSocialAuth(FakeSupabase(_happyServer).client)
              .signInWithGoogle(),
          throwsStateError);
    });
  });

  group('linking', () {
    test('linkApple links, refreshes the token, then registers the code',
        () async {
      final fake = FakeSupabase(_happyServer);
      final social =
          NativeSocialAuth(fake.client, appleCredential: _apple().provider);
      await social.signInWithApple(); // a signed-in user to link to
      await _settle();
      fake.requests.clear();

      await social.linkApple();
      await _settle();

      final paths =
          fake.requests.map((r) => '${r.url.path}?${r.url.query}').toList();
      final link = paths.indexWhere(
          (p) => p.contains('grant_type=id_token') || p.contains('link'));
      final refresh =
          paths.indexWhere((p) => p.contains('grant_type=refresh_token'));
      final exchange =
          paths.indexWhere((p) => p.contains('apple-token-exchange'));
      expect(link, isNonNegative, reason: paths.join('\n'));
      expect(refresh, greaterThan(link), reason: paths.join('\n'));
      expect(exchange, greaterThan(refresh),
          reason: 'the exchange must carry the refreshed token');
    });

    test('an identity owned by someone else surfaces as credential-in-use',
        () async {
      final fake = FakeSupabase((r) async {
        // Linking is an id_token grant with link_identity in the body.
        if (r.body.contains('"link_identity":true')) {
          return authError(422, 'Identity is already linked to another user',
              code: 'identity_already_exists');
        }
        return _happyServer(r);
      });
      final social = NativeSocialAuth(fake.client,
          googleTokens: () async => (idToken: 'g-id', accessToken: null));
      await social.signInWithGoogle();

      await expectLater(
        social.linkGoogle(),
        throwsA(isA<AuthException>()
            .having(isCredentialInUse, 'isCredentialInUse', isTrue)),
      );
      expect(fake.to('grant_type=refresh_token'), isEmpty,
          reason: 'no refresh after a refused link');
    });
  });
}
