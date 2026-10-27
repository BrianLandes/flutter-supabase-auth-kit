import 'package:supabase/supabase.dart';

/// How an email address signs in, from the `account_signin_methods` function
/// in this kit's migrations.
///
/// Supabase's password reset answers "sent" for an unknown address and for an
/// account that only ever used Google or Apple, so the user waits for an email
/// that never comes. Ask first, and tell them what to do instead.
class SignInMethods {
  const SignInMethods({
    required this.accountExists,
    required this.hasPassword,
    this.providers = const [],
  });

  final bool accountExists;

  /// Whether the account has an email + password identity.
  final bool hasPassword;

  /// The other identities, e.g. `['google', 'apple']`.
  final List<String> providers;

  /// The first social provider, for "This account uses Google to sign in."
  String? get socialProvider =>
      providers.where((p) => p != 'email' && p != 'phone').firstOrNull;

  factory SignInMethods.fromRow(Map<String, dynamic> row) => SignInMethods(
        accountExists: row['account_exists'] == true,
        hasPassword: row['has_password'] == true,
        providers: [
          for (final p in (row['providers'] as List?) ?? const []) p.toString(),
        ],
      );

  @override
  String toString() =>
      'SignInMethods(exists: $accountExists, password: $hasPassword, providers: $providers)';
}

/// Looks up how [email] signs in. Returns null on any failure, so the caller
/// fails open and sends the reset anyway rather than blocking a real one.
///
/// The function answers "does this email have an account?" for anyone,
/// signed in or not. That's the point, and also an account-enumeration
/// oracle: rate-limit it or put a captcha in front before a public launch.
Future<SignInMethods?> lookUpSignInMethods(
  SupabaseClient client,
  String email, {
  String function = 'account_signin_methods',
}) async {
  try {
    final result =
        await client.rpc(function, params: {'p_email': email.trim()});
    final row =
        result is List ? (result.isEmpty ? null : result.first) : result;
    return row is Map<String, dynamic> ? SignInMethods.fromRow(row) : null;
  } catch (_) {
    return null;
  }
}
