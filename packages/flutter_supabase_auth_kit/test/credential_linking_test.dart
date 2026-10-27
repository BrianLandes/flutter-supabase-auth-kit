import 'dart:convert';

import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:supabase/supabase.dart';

import 'fake_supabase.dart';

/// A signed-in client whose `PUT /user` answers with [onUpdate].
Future<FakeSupabase> _signedIn(
    Future<http.Response> Function(http.Request r) onUpdate) async {
  final fake = FakeSupabase((r) async {
    if (r.method == 'PUT' && r.url.path.endsWith('/user')) return onUpdate(r);
    if (r.url.path.endsWith('/verify')) return sessionResponse();
    if (r.url.path.endsWith('/resend')) return http.Response('{}', 200);
    return sessionResponse();
  });
  await fake.client.auth
      .signInWithIdToken(provider: OAuthProvider.google, idToken: 'x');
  fake.requests.clear();
  return fake;
}

http.Response _user({String? phone, String? email, String? newEmail}) =>
    http.Response(
        jsonEncode(userJson(phone: phone, email: email, newEmail: newEmail)),
        200);

void main() {
  group('phone', () {
    test('writes the number to the auth identity, not a profile', () async {
      final fake = await _signedIn((_) async => _user());
      await requestPhoneLink(fake.client.auth, '+15551234567');
      final put = fake.requests.single;
      expect(put.url.path, '/auth/v1/user');
      expect(fake.bodyOf(put)['phone'], '+15551234567');
    });

    test('a code was sent when the number is not on the user yet', () async {
      final fake = await _signedIn((_) async => _user());
      expect(await requestPhoneLink(fake.client.auth, '+15551234567'),
          PhoneLinkStatus.codeSent);
    });

    test(
        'linked at once when the project skips confirmation (stored without +)',
        () async {
      final fake = await _signedIn((_) async => _user(phone: '15551234567'));
      expect(await requestPhoneLink(fake.client.auth, '+15551234567'),
          PhoneLinkStatus.linked);
    });

    test('a number on another account is inUse, not an exception', () async {
      final fake = await _signedIn((_) async => authError(
          422, 'Phone number already registered by another user',
          code: 'phone_exists'));
      expect(await requestPhoneLink(fake.client.auth, '+15551234567'),
          PhoneLinkStatus.inUse);
    });

    test('other failures throw', () async {
      final fake = await _signedIn((_) async => authError(
          429, 'Too many requests',
          code: 'over_sms_send_rate_limit'));
      expect(requestPhoneLink(fake.client.auth, '+15551234567'),
          throwsA(isA<AuthException>()));
    });

    test('confirm verifies a phone_change code', () async {
      final fake = await _signedIn((_) async => _user());
      await confirmPhoneLink(fake.client.auth, '+15551234567', ' 123456 ');
      final body = fake.bodyOf(fake.to('/verify').single);
      expect(body['type'], 'phone_change');
      expect(body['token'], '123456');
      expect(body['phone'], '+15551234567');
    });

    test('resend asks for another phone_change code', () async {
      final fake = await _signedIn((_) async => _user());
      await resendPhoneLinkCode(fake.client.auth, '+15551234567');
      expect(fake.bodyOf(fake.to('/resend').single)['type'], 'phone_change');
    });
  });

  group('email', () {
    test('confirmationSent while the address is only pending', () async {
      final fake =
          await _signedIn((_) async => _user(newEmail: 'ada@example.com'));
      expect(
        await requestEmailLink(fake.client.auth, ' Ada@Example.com ',
            redirectTo: 'io.supabase.app://login-callback/'),
        EmailLinkStatus.confirmationSent,
      );
      final put = fake.requests.single;
      expect(fake.bodyOf(put)['email'], 'ada@example.com',
          reason: 'normalized');
      expect(put.url.queryParameters['redirect_to'],
          'io.supabase.app://login-callback/');
    });

    test('linked only when the address is really on the user', () async {
      final fake =
          await _signedIn((_) async => _user(email: 'ada@example.com'));
      expect(await requestEmailLink(fake.client.auth, 'ada@example.com'),
          EmailLinkStatus.linked);
    });

    test('an address on another account is inUse', () async {
      final fake = await _signedIn((_) async => authError(
          422, 'A user with this email address has already been registered',
          code: 'email_exists'));
      expect(await requestEmailLink(fake.client.auth, 'ada@example.com'),
          EmailLinkStatus.inUse);
    });
  });

  group('lookUpSignInMethods', () {
    test('reads the row', () async {
      final fake = FakeSupabase((r) async => http.Response(
          jsonEncode([
            {
              'account_exists': true,
              'has_password': false,
              'providers': ['google', 'apple'],
            }
          ]),
          200));
      final methods =
          await lookUpSignInMethods(fake.client, ' ada@example.com ');
      expect(methods?.accountExists, isTrue);
      expect(methods?.hasPassword, isFalse);
      expect(methods?.socialProvider, 'apple',
          reason: 'Apple and Google are preferred, Apple first');
      expect(methods?.canResetPassword, isFalse);
      final call = fake.requests.single;
      expect(call.url.path, '/rest/v1/rpc/account_signin_methods');
      expect(fake.bodyOf(call), {'p_email': 'ada@example.com'});
    });

    test('fails open: null on any error, so the reset still goes out',
        () async {
      final fake = FakeSupabase((r) async =>
          http.Response('{"message":"permission denied","code":"42501"}', 401));
      final errors = <Object>[];
      expect(
          await lookUpSignInMethods(fake.client, 'ada@example.com',
              onError: (e, _) => errors.add(e)),
          isNull);
      expect(errors, hasLength(1), reason: 'the failure still reaches logs');
    });

    test('steers to any social provider when there is no Apple or Google', () {
      final m = SignInMethods.fromRow({
        'account_exists': true,
        'has_password': true,
        'providers': ['email', 'phone', 'github'],
      });
      expect(m.socialProvider, 'github');
      expect(m.canResetPassword, isTrue);
    });

    test('an unknown address', () {
      final m = SignInMethods.fromRow(
          {'account_exists': false, 'has_password': false, 'providers': null});
      expect(m.accountExists, isFalse);
      expect(m.providers, isEmpty);
      expect(m.socialProvider, isNull);
    });
  });
}
