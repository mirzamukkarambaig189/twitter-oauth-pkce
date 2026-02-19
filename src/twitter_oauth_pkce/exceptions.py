"""Exceptions for the twitter-oauth-pkce package."""


class OAuthError(Exception):
    """Base exception for all OAuth errors."""


class OAuthInvalidStateError(OAuthError):
    """Raised when the OAuth state is invalid, tampered, or not found in the store."""


class OAuthStateExpiredError(OAuthError):
    """Raised when the OAuth state has exceeded its maximum age."""


class OAuthTokenExchangeError(OAuthError):
    """Raised when the authorization code or refresh token exchange with X fails."""


class OAuthRevokeError(OAuthError):
    """Raised when token revocation with X fails."""


class OAuthAPIError(OAuthError):
    """Raised when an X API call returns a non-200 response."""


class OAuthMissingCredentialsError(OAuthError):
    """Raised when required OAuth credentials are missing or empty."""
