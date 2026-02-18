"""Exceptions for the twitter-oauth-pkce package."""


class OAuthError(Exception):
    """Base exception for all OAuth errors."""


class OAuthInvalidStateError(OAuthError):
    """Raised when the OAuth state is invalid, tampered, or not found in the store."""


class OAuthStateExpiredError(OAuthError):
    """Raised when the OAuth state has exceeded its maximum age."""


class OAuthTokenExchangeError(OAuthError):
    """Raised when the authorization code exchange with Twitter fails."""


class OAuthMissingCredentialsError(OAuthError):
    """Raised when required OAuth credentials are missing or empty."""
