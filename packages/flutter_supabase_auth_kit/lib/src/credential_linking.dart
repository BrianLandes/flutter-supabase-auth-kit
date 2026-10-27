import 'package:supabase/supabase.dart';

import 'errors.dart';

/// Attaching a phone number or email to the account that's already signed in.
///
/// **The rule this exists for:** Supabase Auth matches a sign-in against the
/// auth identity (`auth.users.email` / `auth.users.phone`) and never against
/// your `profiles` table. A credential saved only to `profiles` is invisible at
/// sign-in: the returning user gets a brand-new auth user, your new-user
/// trigger builds a second profile, and their real account is orphaned. It
/// happened in production twice, once for phones and once for emails.
///
/// So write the credential to the auth identity, which is what these do, and
/// treat any `profiles` column as a mirror of it.

enum PhoneLinkStatus {
  /// The phone is on `auth.users.phone` now. The project doesn't confirm phone
  /// changes, so no code was needed.
  linked,

  /// A code was texted. Collect it and call [confirmPhoneLink].
  codeSent,

  /// The number belongs to another account. Offer to sign in to that one.
  inUse,
}

enum EmailLinkStatus {
  /// The address is on `auth.users.email` now. Only when the project doesn't
  /// confirm email changes (local stacks, usually).
  linked,

  /// A confirmation link was emailed, and the address waits in
  /// `auth.users.new_email` until it's tapped, possibly on another device, possibly
  /// tomorrow, with the app closed. **Nothing is linked yet.** Don't tell the
  /// user it was saved; tell them to tap the link.
  confirmationSent,

  /// The address belongs to another account.
  inUse,
}

/// Starts linking [phoneE164] (e.g. `+15551234567`) to the signed-in user.
///
/// Throws [AuthException] for any failure other than the number being in use.
Future<PhoneLinkStatus> requestPhoneLink(
    GoTrueClient auth, String phoneE164) async {
  final digits = phoneE164.replaceAll(RegExp(r'[^0-9]'), '');
  try {
    final response = await auth.updateUser(UserAttributes(phone: phoneE164));
    // Supabase stores phones without the leading +.
    final stored = response.user?.phone?.replaceAll(RegExp(r'[^0-9]'), '');
    return stored == digits ? PhoneLinkStatus.linked : PhoneLinkStatus.codeSent;
  } on AuthException catch (e) {
    if (isCredentialInUse(e)) return PhoneLinkStatus.inUse;
    rethrow;
  }
}

/// Finishes a phone link with the texted [code]. Throws [AuthException] when
/// the code is wrong or expired (`classifyAuthError` says `expected`).
Future<void> confirmPhoneLink(
        GoTrueClient auth, String phoneE164, String code) =>
    auth.verifyOTP(
        phone: phoneE164, token: code.trim(), type: OtpType.phoneChange);

/// Texts a fresh code for a pending phone link. The auth server rate-limits
/// this; wait about a minute between sends.
Future<void> resendPhoneLinkCode(GoTrueClient auth, String phoneE164) =>
    auth.resend(type: OtpType.phoneChange, phone: phoneE164);

/// Links [email] to the signed-in user.
///
/// [redirectTo] is where the confirmation link lands, usually your app's deep
/// link (e.g. `io.supabase.myapp://login-callback/`). It **must** be on the
/// project's redirect allow-list (Dashboard → Authentication → URL
/// Configuration), or the link dead-ends on your site URL in a browser.
///
/// With "secure email change" on, a user who already has an email may have to
/// confirm from both the old and the new address.
///
/// Throws [AuthException] for any failure other than the address being in use.
Future<EmailLinkStatus> requestEmailLink(GoTrueClient auth, String email,
    {String? redirectTo}) async {
  final normalized = email.trim().toLowerCase();
  try {
    final response = await auth.updateUser(
      UserAttributes(email: normalized),
      emailRedirectTo: redirectTo,
    );
    return response.user?.email?.toLowerCase() == normalized
        ? EmailLinkStatus.linked
        : EmailLinkStatus.confirmationSent;
  } on AuthException catch (e) {
    if (isCredentialInUse(e)) return EmailLinkStatus.inUse;
    rethrow;
  }
}
