import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:supabase/supabase.dart';

AuthApiException _api(String message, {String? code}) =>
    AuthApiException(message, statusCode: '400', code: code);

void main() {
  group('classifyAuthError', () {
    test('ordinary user mistakes are expected', () {
      for (final code in expectedAuthErrorCodes) {
        expect(classifyAuthError(_api('x', code: code)), AuthErrorKind.expected,
            reason: code);
      }
    });

    test('unknown codes, and no code, are unexpected', () {
      expect(classifyAuthError(_api('x', code: 'unexpected_failure')),
          AuthErrorKind.unexpected);
      expect(classifyAuthError(_api('x')), AuthErrorKind.unexpected);
      expect(classifyAuthError(Exception('socket closed')),
          AuthErrorKind.unexpected);
    });

    test('provider cancellations are cancelled, however they are spelled', () {
      expect(
          classifyAuthError(
              const AuthException('Google sign in was cancelled.')),
          AuthErrorKind.cancelled);
      expect(
          classifyAuthError(Exception('PlatformException(sign_in_canceled)')),
          AuthErrorKind.cancelled);
    });

    test(
        "Apple's dismissal is a cancellation though it says nothing of the sort",
        () {
      // What sign_in_with_apple throws when the user closes the sheet.
      final error = Exception(
          'SignInWithAppleAuthorizationError(AuthorizationErrorCode.unknown, '
          'The operation couldn’t be completed. (com.apple.AuthenticationServices.AuthorizationError error 1000.))');
      expect(isAuthFlowCancellation(error), isTrue);
    });
  });

  group('isCredentialInUse', () {
    test('matches by code', () {
      for (final code in [
        'email_exists',
        'phone_exists',
        'user_already_exists',
        'identity_already_exists'
      ]) {
        expect(isCredentialInUse(_api('whatever', code: code)), isTrue,
            reason: code);
      }
    });

    test('matches the wordings the auth server has used over time', () {
      for (final message in [
        'User already registered',
        'A user with this email address has already been registered',
        'Email address is already in use',
        'Identity is already linked to another user',
        'email_exists',
      ]) {
        expect(isCredentialInUse(_api(message)), isTrue, reason: message);
      }
    });

    test('does not match unrelated errors', () {
      expect(isCredentialInUse(_api('Invalid login credentials')), isFalse);
      expect(isCredentialInUse(Exception('already exists')), isFalse,
          reason: 'only auth errors count');
    });
  });

  test('isUserBanned', () {
    expect(isUserBanned(_api('User is banned', code: 'user_banned')), isTrue);
    expect(isUserBanned(_api('User is banned')), isFalse);
  });
}
