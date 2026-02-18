"""Twitter OAuth 2.0 + PKCE service."""

import logging
from urllib.parse import urlencode

import requests
import tweepy

from twitter_oauth_pkce.constants import MIN_STATE_SECRET_LENGTH, OAUTH_SCOPES
from twitter_oauth_pkce.exceptions import (
    OAuthMissingCredentialsError,
    OAuthInvalidStateError,
    OAuthTokenExchangeError,
)
from twitter_oauth_pkce._internal.pkce_store import PKCEStore
from twitter_oauth_pkce._internal.security import StateManager
from twitter_oauth_pkce.models import OAuthTokens

logger = logging.getLogger(__name__)


class TwitterOAuthService:
    """Orchestrates the Twitter OAuth 2.0 + PKCE authorization flow.

    This service handles the full server-side OAuth flow:

    1. :meth:`generate_authorization_url` — build the Twitter authorization URL
       with a signed state parameter and PKCE challenge.
    2. :meth:`exchange_code_for_tokens` — validate the callback state, retrieve
       the stored PKCE verifier, and exchange the authorization code for tokens.
    3. :meth:`get_authenticated_user_info` — fetch the authenticated user's
       Twitter profile using the access token.

    Args:
        client_id: Twitter OAuth 2.0 client ID (from the Developer Portal).
        client_secret: Twitter OAuth 2.0 client secret.
        redirect_uri: OAuth callback URI registered with your Twitter app.
        state_secret: Secret used to HMAC-sign state parameters.
            Must be at least ``MIN_STATE_SECRET_LENGTH`` characters.

    Raises:
        OAuthMissingCredentialsError: If *client_id* or *client_secret* is empty.
        ValueError: If *state_secret* is shorter than ``MIN_STATE_SECRET_LENGTH``.

    Example::

        service = TwitterOAuthService(
            client_id="your_client_id",
            client_secret="your_client_secret",
            redirect_uri="https://example.com/callback",
            state_secret="a_very_long_secret_key_of_32_chars",
        )

        # Step 1 — redirect the user to this URL
        url = service.generate_authorization_url(user_id=42)

        # Step 2 — in your callback handler
        tokens, user_id = service.exchange_code_for_tokens(code=code, state=state)

        # Step 3 — fetch profile
        profile = service.get_authenticated_user_info(tokens.access_token)
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        state_secret: str,
    ) -> None:
        if not client_id:
            raise OAuthMissingCredentialsError("client_id must not be empty")
        if not client_secret:
            raise OAuthMissingCredentialsError("client_secret must not be empty")
        if not state_secret or len(state_secret) < MIN_STATE_SECRET_LENGTH:
            raise ValueError(
                f"state_secret must be at least {MIN_STATE_SECRET_LENGTH} characters, "
                f"got {len(state_secret) if state_secret else 0}"
            )

        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._state_manager = StateManager(state_secret=state_secret)
        self._pkce_store = PKCEStore()

        logger.info("TwitterOAuthService initialized with redirect_uri=%s", redirect_uri)

    def generate_authorization_url(self, user_id: str | int) -> str:
        """Build a Twitter OAuth 2.0 authorization URL.

        Generates a signed CSRF state, a PKCE code verifier/challenge pair,
        stores the verifier, and returns the complete authorization URL.

        Args:
            user_id: An application-defined identifier for the user starting the
                OAuth flow. It is embedded in the signed state and returned by
                :meth:`exchange_code_for_tokens` after a successful callback.

        Returns:
            A ``https://twitter.com/i/oauth2/authorize?…`` URL to redirect the
            user to.
        """
        state = self._state_manager.encode_state(user_id)
        code_verifier = PKCEStore.generate_pkce_verifier()
        code_challenge = PKCEStore.generate_pkce_challenge(code_verifier)
        self._pkce_store.store(state, code_verifier, user_id)

        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": " ".join(OAUTH_SCOPES),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        url = f"https://twitter.com/i/oauth2/authorize?{urlencode(params)}"

        logger.debug(
            "Generated authorization URL for user_id=%s state=%.16s…", user_id, state
        )
        return url

    def exchange_code_for_tokens(
        self, code: str, state: str
    ) -> tuple[OAuthTokens, str | int]:
        """Exchange an authorization code for OAuth access tokens.

        Validates the state signature and expiry, retrieves the stored PKCE
        verifier, then performs the token exchange with Twitter.

        Args:
            code: The authorization code received in the OAuth callback.
            state: The state parameter received in the OAuth callback.

        Returns:
            A ``(OAuthTokens, user_id)`` tuple where *user_id* is the value
            passed to :meth:`generate_authorization_url`.

        Raises:
            OAuthInvalidStateError: If the state is invalid, tampered, or was
                already consumed.
            OAuthStateExpiredError: If the state has exceeded its TTL.
            OAuthTokenExchangeError: If the token exchange with Twitter fails.
        """
        logger.info("Starting token exchange")

        # Validate state and extract user_id
        user_id = self._state_manager.decode_state(state)
        logger.debug("State decoded — user_id=%s", user_id)

        # Retrieve the PKCE verifier (one-time use)
        result = self._pkce_store.retrieve_and_remove(state)
        if result is None:
            raise OAuthInvalidStateError(
                "State not found in store — it may have expired or already been used"
            )

        code_verifier, stored_user_id = result

        # Sanity check: user_id in state must match what was stored
        if stored_user_id != user_id:
            raise OAuthInvalidStateError(
                "user_id mismatch between state and PKCE store — possible tampering"
            )

        # Exchange the code for tokens via tweepy
        try:
            handler = tweepy.OAuth2UserHandler(
                client_id=self._client_id,
                redirect_uri=self._redirect_uri,
                scope=OAUTH_SCOPES,
                client_secret=self._client_secret,
            )
            handler._client.code_verifier = code_verifier

            auth_response = f"{self._redirect_uri}?code={code}&state={state}"
            token_response = handler.fetch_token(auth_response)

            tokens = OAuthTokens(
                access_token=token_response["access_token"],
                refresh_token=token_response.get("refresh_token"),
                expires_in=token_response.get("expires_in", 7200),
                token_type=token_response.get("token_type", "bearer"),
            )

            logger.info("Token exchange successful for user_id=%s", user_id)
            return tokens, user_id

        except Exception as exc:
            logger.error("Token exchange failed: %s", exc)
            raise OAuthTokenExchangeError(
                f"Failed to exchange code for tokens: {exc}"
            ) from exc

    def get_authenticated_user_info(
        self,
        access_token: str,
        connection_timeout: float = 5.0,
        read_timeout: float = 15.0,
    ) -> dict:
        """Fetch the authenticated user's Twitter profile.

        Calls the Twitter API v2 ``GET /2/users/me`` endpoint.

        Args:
            access_token: Bearer token from :attr:`OAuthTokens.access_token`.
            connection_timeout: TCP connection timeout in seconds.
            read_timeout: Response read timeout in seconds.

        Returns:
            A dict with a ``"data"`` key containing the user's profile fields::

                {
                    "data": {
                        "id": "123456789",
                        "name": "Display Name",
                        "username": "handle",
                        "profile_image_url": "https://…",
                        "description": "Bio",
                        "public_metrics": {
                            "followers_count": 100,
                            "following_count": 50,
                            "tweet_count": 200,
                            "listed_count": 5,
                            "like_count": 300,
                        },
                        "verified": False,
                        "created_at": "2020-01-01T00:00:00.000Z",
                    }
                }

        Raises:
            Exception: If the Twitter API returns a non-200 status code.
        """
        user_fields = ",".join([
            "id", "name", "username", "profile_image_url",
            "description", "public_metrics", "verified", "created_at",
        ])
        url = f"https://api.twitter.com/2/users/me?user.fields={user_fields}"
        headers = {"Authorization": f"Bearer {access_token}"}

        logger.debug("GET %s", url)
        resp = requests.get(url, headers=headers, timeout=(connection_timeout, read_timeout))

        if resp.status_code != 200:
            logger.error("Twitter API %d: %s", resp.status_code, resp.text)
            raise Exception(
                f"{resp.status_code} {resp.reason}: "
                f"{resp.json().get('detail', resp.text)}"
            )

        data = resp.json().get("data", {})
        logger.info("Retrieved profile for @%s", data.get("username"))

        return {
            "data": {
                "id": data.get("id"),
                "name": data.get("name"),
                "username": data.get("username"),
                "profile_image_url": data.get("profile_image_url"),
                "description": data.get("description"),
                "public_metrics": data.get("public_metrics", {}),
                "verified": data.get("verified", False),
                "created_at": data.get("created_at"),
            }
        }
