/// Something the kit noticed that your logs should know about.
///
/// The kit never logs on its own and never shows UI. It reports here, and you
/// route it to your error reporter.
class AuthKitEvent {
  const AuthKitEvent(this.name,
      {this.error, this.stackTrace, this.details = const {}});

  /// What happened, e.g. `google.null_id_token` or `apple.nonce_mismatch`.
  final String name;
  final Object? error;
  final StackTrace? stackTrace;

  /// Context that tells cases apart. Never tokens, never personal data.
  final Map<String, Object?> details;

  @override
  String toString() =>
      'AuthKitEvent($name, $details${error == null ? '' : ', $error'})';
}

typedef AuthKitLogger = void Function(AuthKitEvent event);
