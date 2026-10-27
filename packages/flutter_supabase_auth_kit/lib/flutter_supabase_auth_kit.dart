/// Native Google and Apple sign-in, credential linking and auth error handling
/// for Flutter apps on Supabase.
library;

export 'src/apple_id_token.dart'
    show
        appleFullName,
        appleIdTokenDiagnostics,
        appleIdTokenHasNonce,
        hasAppleIdentity,
        isNoncePresenceMismatch,
        withAppleNonceRetry;
export 'src/credential_linking.dart'
    show
        EmailLinkStatus,
        PhoneLinkStatus,
        confirmPhoneLink,
        requestEmailLink,
        requestPhoneLink,
        resendPhoneLinkCode;
export 'src/errors.dart'
    show
        AuthErrorKind,
        classifyAuthError,
        expectedAuthErrorCodes,
        isAuthFlowCancellation,
        isCredentialInUse,
        isUserBanned;
export 'src/events.dart' show AuthKitEvent, AuthKitLogger;
export 'src/native_social_auth.dart'
    show
        AppleCredential,
        AppleCredentialProvider,
        GoogleTokenProvider,
        GoogleTokens,
        NativeSocialAuth,
        generateRawNonce,
        nativeAppleCredential;
export 'src/sign_in_methods.dart' show SignInMethods, lookUpSignInMethods;
