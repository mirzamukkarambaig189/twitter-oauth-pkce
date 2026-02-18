"""Thread-safe TTL-based storage for PKCE code verifiers."""

import base64
import hashlib
import logging
import secrets
import threading

from cachetools import TTLCache

from twitter_oauth_pkce.constants import PKCE_STORE_MAX_SIZE, STATE_EXPIRY_SECONDS

logger = logging.getLogger(__name__)


class PKCEStore:
    """Thread-safe TTL cache for PKCE code verifiers.

    Each entry maps an OAuth state string to a (code_verifier, user_id) tuple
    and expires automatically after STATE_EXPIRY_SECONDS.

    Args:
        max_size: Maximum number of concurrent in-flight entries.
    """

    def __init__(self, max_size: int = PKCE_STORE_MAX_SIZE) -> None:
        self._store: TTLCache[str, tuple[str, str | int]] = TTLCache(
            maxsize=max_size,
            ttl=STATE_EXPIRY_SECONDS,
        )
        self._lock = threading.Lock()

    def store(self, state: str, code_verifier: str, user_id: str | int) -> None:
        """Store a code verifier keyed by OAuth state.

        Args:
            state: The OAuth state string used as the lookup key.
            code_verifier: The PKCE code verifier to store.
            user_id: An application-defined identifier for the user initiating
                the OAuth flow (e.g. a database ID or Telegram user ID).
        """
        with self._lock:
            self._store[state] = (code_verifier, user_id)
        logger.debug("Stored code verifier for user_id=%s state=%.16s…", user_id, state)

    def retrieve_and_remove(self, state: str) -> tuple[str, str | int] | None:
        """Retrieve and atomically remove a code verifier by state.

        This is a one-time operation — the entry is deleted on retrieval so it
        cannot be replayed.

        Args:
            state: The OAuth state string used as the lookup key.

        Returns:
            A ``(code_verifier, user_id)`` tuple if found, otherwise ``None``.
        """
        with self._lock:
            entry = self._store.pop(state, None)

        if entry is None:
            logger.debug("State not found in PKCE store: %.16s…", state)
            return None

        code_verifier, user_id = entry
        logger.debug(
            "Retrieved and removed code verifier for user_id=%s state=%.16s…",
            user_id,
            state,
        )
        return code_verifier, user_id

    @staticmethod
    def generate_pkce_verifier() -> str:
        """Generate a cryptographically random PKCE code verifier.

        Returns:
            A 43-character base64url-encoded string (32 bytes of entropy).
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")

    @staticmethod
    def generate_pkce_challenge(code_verifier: str) -> str:
        """Derive a PKCE S256 code challenge from a code verifier.

        Args:
            code_verifier: The PKCE code verifier to hash.

        Returns:
            A base64url-encoded SHA-256 hash of the verifier (no padding).
        """
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")
