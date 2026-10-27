import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:supabase/supabase.dart';

/// A [SupabaseClient] whose HTTP goes to [respond], recording every request.
/// The real auth, functions and PostgREST clients run on top, so request
/// shapes and session handling are exercised for real.
class FakeSupabase {
  FakeSupabase(this.respond) {
    client = SupabaseClient(
      'https://project.supabase.co',
      'anon-key',
      // supabase_flutter supplies this; email changes use PKCE and need it.
      authOptions: AuthClientOptions(pkceAsyncStorage: _MemoryStorage()),
      httpClient: MockClient((request) async {
        requests.add(request);
        final r = await respond(request);
        return http.Response(r.body, r.statusCode,
            headers: {'content-type': 'application/json', ...r.headers},
            request: request);
      }),
    );
  }

  final Future<http.Response> Function(http.Request request) respond;
  final requests = <http.Request>[];
  late final SupabaseClient client;

  Iterable<http.Request> to(String pathPart) =>
      requests.where((r) => r.url.toString().contains(pathPart));

  Map<String, dynamic> bodyOf(http.Request r) =>
      jsonDecode(r.body) as Map<String, dynamic>;
}

/// An unsigned JWT with [claims], enough for the client to read expiry from.
String fakeJwt(Map<String, Object?> claims) {
  String part(Object o) =>
      base64Url.encode(utf8.encode(json.encode(o))).replaceAll('=', '');
  return '${part({'alg': 'HS256'})}.${part(claims)}.sig';
}

Map<String, Object?> userJson(
        {String id = 'user-1',
        String? email,
        String? phone,
        String? newEmail}) =>
    {
      'id': id,
      'aud': 'authenticated',
      'role': 'authenticated',
      'email': email,
      'phone': phone,
      'new_email': newEmail,
      'created_at': '2026-10-27T00:00:00Z',
      'app_metadata': {
        'provider': 'apple',
        'providers': ['apple']
      },
      'user_metadata': <String, Object?>{},
    };

http.Response sessionResponse({String userId = 'user-1'}) {
  final exp =
      DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch ~/
          1000;
  return http.Response(
    jsonEncode({
      'access_token':
          fakeJwt({'sub': userId, 'exp': exp, 'role': 'authenticated'}),
      'token_type': 'bearer',
      'expires_in': 3600,
      'expires_at': exp,
      'refresh_token': 'refresh-$userId',
      'user': userJson(id: userId),
    }),
    200,
  );
}

http.Response authError(int status, String message, {String? code}) =>
    http.Response(
        jsonEncode({
          'code': status,
          'error_code': code,
          'msg': message,
          'message': message
        }),
        status);

class _MemoryStorage extends GotrueAsyncStorage {
  final _values = <String, String>{};

  @override
  Future<String?> getItem({required String key}) async => _values[key];

  @override
  Future<void> removeItem({required String key}) async => _values.remove(key);

  @override
  Future<void> setItem({required String key, required String value}) async =>
      _values[key] = value;
}
