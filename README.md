# twitter-oauth-pkce

A minimal, framework-agnostic Python library for the X (Twitter) OAuth 2.0 + PKCE authorization flow.

- No framework dependencies — works with FastAPI, Flask, Django, or plain scripts
- CSRF protection via HMAC-SHA256 signed state parameters
- PKCE (S256) for secure authorization code exchange
- Thread-safe in-memory PKCE verifier store with automatic TTL expiry
- Token refresh and revocation built-in
- All X OAuth 2.0 scopes available as named constants
- Stdlib `logging` — bring your own log handler

## Requirements

- Python 3.10+
- `cachetools >= 7.0`
- `requests >= 2.32`

## Installation

```bash
pip install twitter-oauth-pkce
```

Or from source:

```bash
pip install -e path/to/twitter-oauth-pkce/
```

## Quickstart

```python
from twitter_oauth_pkce import TwitterOAuthService

service = TwitterOAuthService(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    redirect_uri="https://yourapp.com/oauth/callback",
    state_secret="a-secret-of-at-least-32-characters!!",
)
```

### Step 1 — Redirect the user

```python
# user_id can be any str or int that identifies the user in your system
url = service.generate_authorization_url(user_id=42)
redirect(url)  # send the user to X
```

### Step 2 — Handle the callback

> **Warning:** Authorization codes expire in **30 seconds**. Call
> `exchange_code_for_tokens` immediately inside your callback handler.

```python
# In your /oauth/callback route handler:
tokens, user_id = service.exchange_code_for_tokens(
    code=request.query_params["code"],
    state=request.query_params["state"],
)
# tokens.access_token   — use this to call the X API
# tokens.refresh_token  — persist this to refresh access later
# tokens.scope          — list of scopes actually granted, e.g. ["tweet.read", "users.read"]
# user_id               — the value you passed in Step 1
```

### Step 3 — Fetch the X profile

```python
profile = service.get_authenticated_user_info(tokens.access_token)
x_id     = profile["data"]["id"]
username = profile["data"]["username"]
```

### Step 4 — Refresh an expiring access token

Access tokens are valid for **2 hours**. Use the refresh token to get a new
one without re-prompting the user (requires `offline.access` scope).

```python
new_tokens = service.refresh_tokens(tokens.refresh_token)
# Always persist the new refresh token — X may rotate it
```

### Step 5 — Revoke a token (logout)

```python
service.revoke_token(tokens.access_token)   # invalidate access token
# or
service.revoke_token(tokens.refresh_token)  # invalidate refresh token
```

---

## API reference

### `TwitterOAuthService(client_id, client_secret, redirect_uri, state_secret)`

| Parameter | Type | Description |
|---|---|---|
| `client_id` | `str` | X OAuth 2.0 client ID (from the Developer Portal) |
| `client_secret` | `str` | X OAuth 2.0 client secret |
| `redirect_uri` | `str` | Callback URI registered in the X Developer Portal |
| `state_secret` | `str` | HMAC signing key — must be at least 32 characters |

#### `generate_authorization_url(user_id, scopes=None) -> str`

Returns the `https://x.com/i/oauth2/authorize?…` URL to redirect the user to.
Stores a one-time PKCE verifier that expires in 5 minutes.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `user_id` | `str \| int` | — | App-defined identifier embedded in the signed state |
| `scopes` | `list[str] \| None` | `OAUTH_SCOPES` | Scopes to request — see [Scopes](#scopes) below |

#### `exchange_code_for_tokens(code, state) -> tuple[OAuthTokens, str | int]`

Validates the signed state, retrieves the stored PKCE verifier, and exchanges
the authorization code for tokens. Returns `(OAuthTokens, user_id)`.

#### `refresh_tokens(refresh_token) -> OAuthTokens`

Exchanges a refresh token for a new access token using `grant_type=refresh_token`.
Always persist the returned `refresh_token` — X may rotate it on each refresh.

#### `revoke_token(token) -> None`

Calls `POST /2/oauth2/revoke` to immediately invalidate an access or refresh token.
Use this to implement logout.

#### `get_authenticated_user_info(access_token) -> dict`

Calls `GET /2/users/me` and returns a dict with a `"data"` key:

```python
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
```

---

### `OAuthTokens`

```python
@dataclass
class OAuthTokens:
    access_token: str        # Bearer token for API requests (valid 2 hours)
    refresh_token: str | None  # Use with refresh_tokens() — None if offline.access not granted
    expires_in: int          # Token lifetime in seconds
    token_type: str          # "bearer"
    scope: list[str]         # Scopes actually granted, e.g. ["tweet.read", "users.read"]
```

---

### Exceptions

All exceptions inherit from `OAuthError`.

| Exception | Raised when |
|---|---|
| `OAuthMissingCredentialsError` | `client_id` or `client_secret` is empty |
| `OAuthInvalidStateError` | State is malformed, tampered, or already consumed |
| `OAuthStateExpiredError` | State is older than 5 minutes |
| `OAuthTokenExchangeError` | Token exchange or refresh with X fails |
| `OAuthRevokeError` | Token revocation with X fails |
| `OAuthAPIError` | A call to the X API returns a non-200 response |

```python
from twitter_oauth_pkce import (
    OAuthError,
    OAuthStateExpiredError,
    OAuthTokenExchangeError,
    OAuthRevokeError,
)

try:
    tokens, user_id = service.exchange_code_for_tokens(code, state)
except OAuthStateExpiredError:
    # Ask the user to start the flow again
    ...
except OAuthTokenExchangeError:
    # Code already used, expired (30s window), or X rejected the request
    ...
except OAuthError as e:
    # Catch-all for any other OAuth error
    ...
```

---

## Scopes

Pass a `scopes` list to `generate_authorization_url()` to request exactly the
permissions your app needs. All available scopes are exported as named constants:

```python
from twitter_oauth_pkce import (
    SCOPE_TWEET_READ,
    SCOPE_TWEET_WRITE,
    SCOPE_USERS_READ,
    SCOPE_OFFLINE_ACCESS,
    # … see full list below
)

url = service.generate_authorization_url(
    user_id=42,
    scopes=[SCOPE_TWEET_READ, SCOPE_TWEET_WRITE, SCOPE_USERS_READ, SCOPE_OFFLINE_ACCESS],
)
```

The default (`OAUTH_SCOPES`) is `[SCOPE_TWEET_READ, SCOPE_USERS_READ, SCOPE_OFFLINE_ACCESS]`.

### Full scope reference

| Constant | Scope string | Description |
|---|---|---|
| `SCOPE_TWEET_READ` | `tweet.read` | Read tweets on behalf of the user |
| `SCOPE_TWEET_WRITE` | `tweet.write` | Post and delete tweets |
| `SCOPE_TWEET_MODERATE_WRITE` | `tweet.moderate.write` | Hide/unhide replies |
| `SCOPE_USERS_READ` | `users.read` | Read user profile information |
| `SCOPE_USERS_EMAIL` | `users.email` | Read user email address *(requires approval)* |
| `SCOPE_FOLLOWS_READ` | `follows.read` | Read follower/following lists |
| `SCOPE_FOLLOWS_WRITE` | `follows.write` | Follow/unfollow accounts |
| `SCOPE_SPACE_READ` | `space.read` | Read Spaces |
| `SCOPE_MUTE_READ` | `mute.read` | Read muted accounts |
| `SCOPE_MUTE_WRITE` | `mute.write` | Mute/unmute accounts |
| `SCOPE_LIKE_READ` | `like.read` | Read liked tweets |
| `SCOPE_LIKE_WRITE` | `like.write` | Like/unlike tweets |
| `SCOPE_LIST_READ` | `list.read` | Read lists |
| `SCOPE_LIST_WRITE` | `list.write` | Create/manage lists |
| `SCOPE_BLOCK_READ` | `block.read` | Read blocked accounts |
| `SCOPE_BLOCK_WRITE` | `block.write` | Block/unblock accounts |
| `SCOPE_BOOKMARK_READ` | `bookmark.read` | Read bookmarks |
| `SCOPE_BOOKMARK_WRITE` | `bookmark.write` | Add/remove bookmarks |
| `SCOPE_DM_READ` | `dm.read` | Read direct messages |
| `SCOPE_DM_WRITE` | `dm.write` | Send direct messages |
| `SCOPE_MEDIA_WRITE` | `media.write` | Upload media |
| `SCOPE_OFFLINE_ACCESS` | `offline.access` | Enable refresh token issuance |

---

## Logging

The library uses standard `logging` and emits nothing by default:

```python
import logging
logging.getLogger("twitter_oauth_pkce").setLevel(logging.DEBUG)
```

---

## Security notes

- State parameters are signed with HMAC-SHA256 and expire after 300 seconds.
- PKCE verifiers are stored in a thread-safe TTL cache and consumed exactly once.
- Signature comparison uses `hmac.compare_digest` to prevent timing attacks.
- Authorization codes issued by X expire in **30 seconds** — exchange them immediately.
- Access tokens are valid for **2 hours** — use `refresh_tokens()` to renew silently.
- `state_secret` must be at least 32 characters; use a cryptographically random value in production:

```python
import secrets
state_secret = secrets.token_hex(32)  # 64-char hex string
```

---

## License

MIT
