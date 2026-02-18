"""Constants for the twitter-oauth-pkce package."""

# How long (in seconds) a state parameter remains valid after generation.
STATE_EXPIRY_SECONDS: int = 300

# Number of random bytes used to generate the nonce embedded in the state.
NONCE_LENGTH: int = 8

# Minimum length enforced for the HMAC state_secret.
MIN_STATE_SECRET_LENGTH: int = 32

# Twitter OAuth 2.0 scopes requested during authorization.
OAUTH_SCOPES: list[str] = ["tweet.read", "users.read", "offline.access"]

# Maximum number of concurrent in-flight PKCE entries held in memory.
PKCE_STORE_MAX_SIZE: int = 10_000
