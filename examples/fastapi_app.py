"""FastAPI example: X (Twitter) OAuth 2.0 + PKCE flow using twitter-oauth-pkce.

Install example dependencies (do NOT add these to the library's pyproject.toml):

    pip install fastapi "uvicorn[standard]" jinja2 python-multipart itsdangerous

Install the library from the repo root:

    pip install -e path/to/twitter-oauth-pkce/

Set environment variables:

    export TWITTER_CLIENT_ID="..."
    export TWITTER_CLIENT_SECRET="..."
    export TWITTER_REDIRECT_URI="http://localhost:8000/auth/callback"
    export STATE_SECRET="a-cryptographically-random-string-of-at-least-32-chars"
    export SESSION_SECRET="another-random-secret-for-cookie-signing"  # optional

Run from the repo root:

    uvicorn examples.fastapi_app:app --reload

Or from inside the examples/ directory:

    uvicorn fastapi_app:app --reload

Then open http://localhost:8000 in your browser.
"""

import logging
import os
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from twitter_oauth_pkce import (
    TwitterOAuthService,
    OAuthError,
    OAuthStateExpiredError,
    OAuthInvalidStateError,
    OAuthTokenExchangeError,
    OAuthRevokeError,
    OAuthAPIError,
    OAuthMissingCredentialsError,
    SCOPE_TWEET_READ,
    SCOPE_USERS_READ,
    SCOPE_OFFLINE_ACCESS,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — read from environment, fail fast if any required var is absent
# ---------------------------------------------------------------------------


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(
            f"Required environment variable '{name}' is not set. "
            "See the module docstring for setup instructions."
        )
    return value


CLIENT_ID = _require_env("TWITTER_CLIENT_ID")
CLIENT_SECRET = _require_env("TWITTER_CLIENT_SECRET")
REDIRECT_URI = _require_env("TWITTER_REDIRECT_URI")
STATE_SECRET = _require_env("STATE_SECRET")
# SESSION_SECRET can share the value of STATE_SECRET in development,
# but should be a distinct secret in production.
SESSION_SECRET = os.environ.get("SESSION_SECRET", STATE_SECRET)

# ---------------------------------------------------------------------------
# OAuth service — single instance per process
# (The PKCE verifier store is in-memory and not shared across processes.)
# ---------------------------------------------------------------------------

try:
    oauth = TwitterOAuthService(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        state_secret=STATE_SECRET,
    )
except (OAuthMissingCredentialsError, ValueError) as exc:
    raise SystemExit(f"Failed to initialise TwitterOAuthService: {exc}") from exc

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="twitter-oauth-pkce FastAPI example")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="x_oauth_session",
    max_age=3600,       # 1 hour — matches X access token lifetime
    https_only=False,   # set True in production (requires HTTPS)
    same_site="lax",
)

# ---------------------------------------------------------------------------
# Jinja2 templates — resolved relative to this file so the app works
# regardless of the working directory it is launched from
# ---------------------------------------------------------------------------

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("access_token"))


def _error_page(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    """Render the login page with an error banner."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "error": message},
        status_code=status_code,
    )


def _upgrade_profile_image(url: str | None) -> str | None:
    """Swap X's _normal (48 px) thumbnail for the 400 px variant."""
    if url:
        return url.replace("_normal", "_400x400").replace("http://", "https://")
    return url


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    if _is_authenticated(request):
        return RedirectResponse(url="/profile", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/auth/twitter")
def auth_twitter(request: Request) -> RedirectResponse:
    """Start the OAuth flow: generate the authorization URL and redirect to X."""
    # A UUID serves as the user_id for this stateless example.
    # In a real app, pass your internal user or session ID instead.
    user_id = str(uuid.uuid4())

    auth_url = oauth.generate_authorization_url(
        user_id=user_id,
        scopes=[SCOPE_TWEET_READ, SCOPE_USERS_READ, SCOPE_OFFLINE_ACCESS],
    )

    logger.info("Redirecting user_id=%s to X for authorization", user_id)
    return RedirectResponse(url=auth_url, status_code=302)


@app.get("/auth/callback", response_class=HTMLResponse)
def auth_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
) -> HTMLResponse:
    """Handle the OAuth callback from X.

    X redirects here with either:
      - ?code=<auth_code>&state=<state>  on success
      - ?error=<reason>                  when the user denies access
    """
    if error:
        logger.warning("OAuth callback received error from X: %s", error)
        return _error_page(
            request,
            f"Authorization was denied or cancelled: {error}",
        )

    if not code or not state:
        return _error_page(
            request,
            "Invalid callback: missing 'code' or 'state' query parameters.",
        )

    try:
        # Authorization codes expire in 30 seconds — exchange immediately.
        tokens, user_id = oauth.exchange_code_for_tokens(code=code, state=state)
    except OAuthStateExpiredError:
        logger.warning("OAuth state expired during callback")
        return _error_page(
            request,
            "Your login session expired (the authorization link is older than 5 minutes). "
            "Please try signing in again.",
        )
    except OAuthInvalidStateError as exc:
        logger.warning("OAuth invalid state during callback: %s", exc)
        return _error_page(
            request,
            "The state parameter is invalid or was already used — this may indicate a CSRF "
            "attempt. Please try signing in again.",
        )
    except OAuthTokenExchangeError as exc:
        logger.error("Token exchange failed: %s", exc)
        return _error_page(
            request,
            f"Failed to exchange the authorization code for tokens: {exc}",
            status_code=502,
        )
    except OAuthError as exc:
        logger.error("Unexpected OAuth error during callback: %s", exc)
        return _error_page(request, f"An OAuth error occurred: {exc}", status_code=500)

    request.session["access_token"] = tokens.access_token
    request.session["refresh_token"] = tokens.refresh_token or ""
    request.session["user_id"] = str(user_id)

    logger.info("OAuth flow completed for user_id=%s", user_id)
    return RedirectResponse(url="/profile", status_code=302)


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request) -> HTMLResponse:
    """Fetch and display the authenticated user's X profile.

    Transparently refreshes the access token if it appears to be expired.
    """
    if not _is_authenticated(request):
        return RedirectResponse(url="/", status_code=302)

    access_token = request.session["access_token"]
    refresh_token = request.session.get("refresh_token", "")

    try:
        user_info = oauth.get_authenticated_user_info(access_token)
    except OAuthAPIError as exc:
        if not refresh_token:
            logger.error("X API error with no refresh token available: %s", exc)
            return _error_page(
                request,
                "Your session has expired. Please sign in again.",
                status_code=401,
            )

        # Attempt a silent token refresh
        logger.info("Access token expired, attempting silent refresh")
        try:
            new_tokens = oauth.refresh_tokens(refresh_token)
        except OAuthTokenExchangeError as refresh_exc:
            logger.error("Token refresh failed: %s", refresh_exc)
            request.session.clear()
            return _error_page(
                request,
                "Your session has expired and could not be refreshed. Please sign in again.",
                status_code=401,
            )

        # Always persist the new tokens — X may rotate the refresh token
        request.session["access_token"] = new_tokens.access_token
        request.session["refresh_token"] = new_tokens.refresh_token or ""

        try:
            user_info = oauth.get_authenticated_user_info(new_tokens.access_token)
        except OAuthAPIError as api_exc:
            logger.error("Profile fetch failed even after token refresh: %s", api_exc)
            return _error_page(request, f"X API error: {api_exc}", status_code=502)

    data = user_info.get("data", {})
    metrics = data.get("public_metrics", {})

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": {
                "name": data.get("name"),
                "username": data.get("username"),
                "profile_image_url": _upgrade_profile_image(data.get("profile_image_url")),
                "description": data.get("description") or "",
                "verified": data.get("verified", False),
                "followers_count": metrics.get("followers_count", 0),
                "following_count": metrics.get("following_count", 0),
                "tweet_count": metrics.get("tweet_count", 0),
                "like_count": metrics.get("like_count", 0),
            },
        },
    )


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    """Revoke tokens and clear the session."""
    for token_key in ("access_token", "refresh_token"):
        token = request.session.get(token_key, "")
        if token:
            try:
                oauth.revoke_token(token)
                logger.info("Revoked %s", token_key)
            except OAuthRevokeError as exc:
                # Non-fatal: always clear the local session regardless
                logger.warning("Failed to revoke %s: %s", token_key, exc)

    request.session.clear()
    return RedirectResponse(url="/", status_code=302)
