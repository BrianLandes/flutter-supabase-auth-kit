// Run with `flutter create . && flutter run` from this directory, after
// filling in your Supabase project and Google client IDs.
import 'package:flutter/material.dart';
import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

import 'google_tokens.dart';

const _supabaseUrl = 'https://YOUR-PROJECT.supabase.co';
const _supabaseKey = 'YOUR-PUBLISHABLE-KEY';
const _googleWebClientId = 'YOUR-WEB-CLIENT-ID.apps.googleusercontent.com';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Supabase.initialize(url: _supabaseUrl, publishableKey: _supabaseKey);
  await initGoogleSignIn(serverClientId: _googleWebClientId);
  runApp(const MaterialApp(home: SignInPage()));
}

class SignInPage extends StatefulWidget {
  const SignInPage({super.key});

  @override
  State<SignInPage> createState() => _SignInPageState();
}

class _SignInPageState extends State<SignInPage> {
  late final _social = NativeSocialAuth(
    Supabase.instance.client,
    googleTokens: googleTokensV7,
    // Apple sends the name once, on the first authorization. Keep it.
    onAppleName: (name) => Supabase.instance.client.auth.updateUser(
      UserAttributes(data: {'full_name': name}),
    ),
    log: (event) => debugPrint('$event'),
  );

  Future<void> _run(Future<AuthResponse?> Function() signIn) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      final response = await signIn();
      if (response == null) return; // the user closed the sheet
      messenger.showSnackBar(
          SnackBar(content: Text('Signed in as ${response.user?.id}')));
    } on AuthException catch (e) {
      final text = switch (classifyAuthError(e)) {
        AuthErrorKind.cancelled => null,
        _ when isUserBanned(e) => 'This account has been suspended.',
        _ => e.message,
      };
      if (text != null) messenger.showSnackBar(SnackBar(content: Text(text)));
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('flutter_supabase_auth_kit')),
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              FilledButton(
                  onPressed: () => _run(_social.signInWithApple),
                  child: const Text('Continue with Apple')),
              const SizedBox(height: 12),
              FilledButton(
                  onPressed: () => _run(_social.signInWithGoogle),
                  child: const Text('Continue with Google')),
            ],
          ),
        ),
      );
}
