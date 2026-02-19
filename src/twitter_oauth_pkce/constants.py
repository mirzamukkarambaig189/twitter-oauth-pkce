"""Constants for the twitter-oauth-pkce package."""

# How long (in seconds) a state parameter remains valid after generation.
STATE_EXPIRY_SECONDS: int = 300

# Number of random bytes used to generate the nonce embedded in the state.
NONCE_LENGTH: int = 8

# Minimum length enforced for the HMAC state_secret.
MIN_STATE_SECRET_LENGTH: int = 32

# Maximum number of concurrent in-flight PKCE entries held in memory.
PKCE_STORE_MAX_SIZE: int = 10_000

# ---------------------------------------------------------------------------
# X OAuth 2.0 scopes
# Pass any combination of these to generate_authorization_url(scopes=[...]).
# ---------------------------------------------------------------------------

# Read scopes
SCOPE_TWEET_READ = "tweet.read"  # Read tweets on behalf of the user
SCOPE_USERS_READ = "users.read"  # Read user profile information
SCOPE_FOLLOWS_READ = "follows.read"  # Read follower/following lists
SCOPE_SPACE_READ = "space.read"  # Read Spaces
SCOPE_MUTE_READ = "mute.read"  # Read muted accounts
SCOPE_LIKE_READ = "like.read"  # Read liked tweets
SCOPE_LIST_READ = "list.read"  # Read lists
SCOPE_BLOCK_READ = "block.read"  # Read blocked accounts
SCOPE_BOOKMARK_READ = "bookmark.read"  # Read bookmarks
SCOPE_DM_READ = "dm.read"  # Read direct messages
SCOPE_USERS_EMAIL = "users.email"  # Read user email address (requires approval)

# Write scopes
SCOPE_TWEET_WRITE = "tweet.write"  # Post and delete tweets
SCOPE_TWEET_MODERATE_WRITE = "tweet.moderate.write"  # Hide/unhide replies
SCOPE_FOLLOWS_WRITE = "follows.write"  # Follow/unfollow accounts
SCOPE_MUTE_WRITE = "mute.write"  # Mute/unmute accounts
SCOPE_LIKE_WRITE = "like.write"  # Like/unlike tweets
SCOPE_LIST_WRITE = "list.write"  # Create/manage lists
SCOPE_BLOCK_WRITE = "block.write"  # Block/unblock accounts
SCOPE_BOOKMARK_WRITE = "bookmark.write"  # Add/remove bookmarks
SCOPE_DM_WRITE = "dm.write"  # Send direct messages
SCOPE_MEDIA_WRITE = "media.write"  # Upload media

# Special scope — enables refresh token issuance for long-lived access
SCOPE_OFFLINE_ACCESS = "offline.access"

# Default scopes requested when none are specified.
# Grants read-only access to tweets and user profile, plus refresh token support.
OAUTH_SCOPES: list[str] = [SCOPE_TWEET_READ, SCOPE_USERS_READ, SCOPE_OFFLINE_ACCESS]
