import 'package:flutter_supabase_auth_kit/flutter_supabase_auth_kit.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:supabase/supabase.dart';

User _user({Map<String, dynamic> appMetadata = const {}}) => User(
      id: 'user-1',
      appMetadata: appMetadata,
      userMetadata: const {},
      aud: 'authenticated',
      createdAt: '2026-10-23T00:00:00Z',
    );

void main() {
  group('appleFullName', () {
    test('joins the parts Apple sent', () {
      expect(appleFullName(' Ada ', 'Lovelace'), 'Ada Lovelace');
      expect(appleFullName('Ada', null), 'Ada');
      expect(appleFullName(null, 'Lovelace'), 'Lovelace');
    });

    test('is empty on a repeat authorization, when Apple sends none', () {
      expect(appleFullName(null, null), isEmpty);
      expect(appleFullName('', '  '), isEmpty);
    });
  });

  group('hasAppleIdentity', () {
    test('recognises an Apple sign-in', () {
      expect(
        hasAppleIdentity(
          _user(
            appMetadata: {
              'provider': 'apple',
              'providers': ['apple'],
            },
          ),
        ),
        isTrue,
      );
    });

    test('recognises an Apple ID linked to a guest', () {
      expect(
        hasAppleIdentity(
          _user(
            appMetadata: {
              'provider': 'anonymous',
              'providers': ['anonymous', 'apple'],
            },
          ),
        ),
        isTrue,
      );
    });

    test('is false for other providers', () {
      expect(
        hasAppleIdentity(
          _user(
            appMetadata: {
              'provider': 'google',
              'providers': ['google'],
            },
          ),
        ),
        isFalse,
      );
      expect(hasAppleIdentity(_user()), isFalse);
    });
  });
}
