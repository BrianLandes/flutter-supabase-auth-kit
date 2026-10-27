// A GoogleTokenProvider for google_sign_in 7.x. Copy it into your app.
// (For 6.x, see the package README.)
import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';
import 'package:google_sign_in/google_sign_in.dart';

/// Call once at startup: google_sign_in 7 must be initialized exactly once.
///
/// [serverClientId] is your **web** OAuth client ID, the one in your Supabase
/// Google provider settings. Android needs it to mint an ID token.
/// [clientId] is the iOS client ID.
Future<void> initGoogleSignIn(
        {required String serverClientId, String? clientId}) =>
    GoogleSignIn.instance
        .initialize(serverClientId: serverClientId, clientId: clientId);

/// Runs the Google picker. A cancellation throws a GoogleSignInException whose
/// text says "canceled", which the kit recognizes and turns into null.
Future<GoogleTokens?> googleTokensV7() async {
  final account = await GoogleSignIn.instance.authenticate();
  return (idToken: account.authentication.idToken, accessToken: null);
}
