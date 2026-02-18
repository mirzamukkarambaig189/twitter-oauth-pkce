# twitter-oauth-pkce

A minimal, framework-agnostic Python library for the Twitter OAuth 2.0 + PKCE authorization flow.

- No framework dependencies — works with FastAPI, Flask, Django, or plain scripts
- CSRF protection via HMAC-SHA256 signed state parameters
- PKCE (S256) support for secure server-side flows
- Thread-safe in-memory PKCE verifier store with automatic TTL expiry
- Stdlib `logging` — bring your own log handler

## Requirements

- Python 3.10+
- `tweepy >= 4.15`
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
redirect(url)  # send the user to Twitter
```

### Step 2 — Handle the callback

```python
# In your /oauth/callback route handler:
tokens, user_id = service.exchange_code_for_tokens(
    code=request.query_params["code"],
    state=request.query_params["state"],
)
# tokens.access_token  — use this to call the Twitter API
# user_id              — the value you passed in Step 1
```

### Step 3 — Fetch the Twitter profile

```python
profile = service.get_authenticated_user_info(tokens.access_token)
twitter_id = profile["data"]["id"]
username   = profile["data"]["username"]
```

## API reference

### `TwitterOAuthService(client_id, client_secret, redirect_uri, state_secret)`

| Parameter | Type | Description |
|---|---|---|
| `client_id` | `str` | Twitter OAuth 2.0 client ID |
| `client_secret` | `str` | Twitter OAuth 2.0 client secret |
| `redirect_uri` | `str` | Callback URI registered in the Twitter Developer Portal |
| `state_secret` | `str` | HMAC signing key — must be at least 32 characters |

#### `generate_authorization_url(user_id) -> str`

Returns the `https://twitter.com/i/oauth2/authorize?…` URL to redirect the user to. Stores a one-time PKCE verifier that expires in 5 minutes.

#### `exchange_code_for_tokens(code, state) -> tuple[OAuthTokens, str | int]`

Validates the signed state, retrieves the stored PKCE verifier, and exchanges the authorization code for tokens. Returns `(OAuthTokens, user_id)`.

#### `get_authenticated_user_info(access_token, *, connection_timeout=5.0, read_timeout=15.0) -> dict`

Calls `GET /2/users/me` and returns a dict with a `"data"` key containing `id`, `name`, `username`, `profile_image_url`, `description`, `public_metrics`, `verified`, and `created_at`.

### `OAuthTokens`

```python
@dataclass
class OAuthTokens:
    access_token: str
    refresh_token: str | None
    expires_in: int
    token_type: str  # "bearer"
```

### Exceptions

All exceptions inherit from `OAuthError`.

| Exception | Raised when |
|---|---|
| `OAuthMissingCredentialsError` | `client_id` or `client_secret` is empty |
| `OAuthInvalidStateError` | State is malformed, tampered, or already consumed |
| `OAuthStateExpiredError` | State is older than 5 minutes |
| `OAuthTokenExchangeError` | Token exchange with Twitter fails |

```python
from twitter_oauth_pkce import OAuthError, OAuthStateExpiredError

try:
    tokens, user_id = service.exchange_code_for_tokens(code, state)
except OAuthStateExpiredError:
    # ask the user to start the flow again
    ...
except OAuthError as e:
    # handle all other OAuth errors
    ...
```

## Scopes

The library requests `tweet.read users.read offline.access` by default. You can inspect or override the constant:

```python
from twitter_oauth_pkce.constants import OAUTH_SCOPES
```

## Logging

The library uses standard `logging` and emits nothing by default. Configure it the same way you configure any Python logger:

```python
import logging
logging.getLogger("twitter_oauth_pkce").setLevel(logging.DEBUG)
```

## Security notes

- State parameters are signed with HMAC-SHA256 and expire after 300 seconds.
- PKCE verifiers are stored in a thread-safe TTL cache and consumed exactly once.
- Signature comparison uses `hmac.compare_digest` to prevent timing attacks.
- `state_secret` must be at least 32 characters; use a cryptographically random value in production.

```python
import secrets
state_secret = secrets.token_hex(32)  # 64-char hex string
```

## License

MIT
