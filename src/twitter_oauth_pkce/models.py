"""Data models for the twitter-oauth-pkce package."""

from dataclasses import dataclass


@dataclass
class OAuthTokens:
    """Holds the tokens returned after a successful OAuth token exchange.

    Attributes:
        access_token: Bearer token used to authenticate API requests.
        refresh_token: Token used to obtain a new access token; may be None
            if the offline.access scope was not granted.
        expires_in: Lifetime of the access token in seconds.
        token_type: Token type, typically "bearer".
        scope: List of scopes actually granted by X.
            May differ from what was requested if the user partially denied.
            Empty list if the token response did not include a scope field.
    """

    access_token: str
    refresh_token: str | None
    expires_in: int
    token_type: str = "bearer"
    scope: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.scope is None:
            self.scope = []
