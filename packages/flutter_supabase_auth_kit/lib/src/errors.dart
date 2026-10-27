import 'package:supabase/supabase.dart';

/// What kind of failure a sign-in error is, so a logger can keep user
/// mistakes out of the real-bug view and the UI can stay quiet when the user
/// simply backed out.
enum AuthErrorKind {
  /// The user dismissed the Google or Apple sheet. Say nothing.
  cancelled,

  /// A normal user mistake: wrong password, an address that's taken, a weak
  /// password, a suspended account. Show the message; log it as info.
  expected,

  /// Anything else. A real failure worth seeing in your error reports.
  unexpected,
}

/// Auth error codes that mean the user did something ordinary, not that the
/// app is broken.
const expectedAuthErrorCodes = <String>{
  'invalid_credentials',
  'user_already_exists',
  'email_exists',
  'phone_exists',
  'identity_already_exists',
  'same_password',
  'weak_password',
  'validation_failed',
  'otp_expired',
  'user_banned',
};

AuthErrorKind classifyAuthError(Object error) {
  if (isAuthFlowCancellation(error)) return AuthErrorKind.cancelled;
  if (error is AuthException &&
      error.code != null &&
      expectedAuthErrorCodes.contains(error.code)) {
    return AuthErrorKind.expected;
  }
  return AuthErrorKind.unexpected;
}

/// Whether [error] is the user dismissing a Google or Apple sign-in sheet.
///
/// End those silently. A "sign-in failed" message for a sheet the user closed
/// on purpose reads as a bug.
bool isAuthFlowCancellation(Object error) {
  final text = error.toString();
  if (text.toLowerCase().contains('cancel')) return true;
  // Apple reports a dismissed authorization sheet as error 1000, without
  // "cancelled" anywhere in the message.
  return text.contains('AuthorizationError error 1000');
}

/// Whether the auth server refused because the email, phone or identity
/// already belongs to a different account.
///
/// Matched loosely on purpose: the wording has changed between auth server
/// versions ("User already registered", "email address is already in use",
/// "Identity is already linked to another user").
bool isCredentialInUse(Object error) {
  if (error is! AuthException) return false;
  const codes = {
    'email_exists',
    'phone_exists',
    'user_already_exists',
    'identity_already_exists'
  };
  if (error.code != null && codes.contains(error.code)) return true;
  final message = error.message.toLowerCase();
  if (message.contains('email_exists')) return true;
  return message.contains('already') &&
      (message.contains('registered') ||
          message.contains('exists') ||
          message.contains('use') ||
          message.contains('linked'));
}

/// Whether the account has been banned (`auth.users.banned_until`). Its raw
/// message, "User is banned", tells the user nothing about what to do next,
/// so show your own.
bool isUserBanned(Object error) =>
    error is AuthException && error.code == 'user_banned';
