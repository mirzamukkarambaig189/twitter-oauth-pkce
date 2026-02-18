"""HMAC-SHA256 state encoding and decoding for OAuth CSRF protection."""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time

from twitter_oauth_pkce.constants import MIN_STATE_SECRET_LENGTH, NONCE_LENGTH, STATE_EXPIRY_SECONDS
from twitter_oauth_pkce.exceptions import OAuthInvalidStateError, OAuthStateExpiredError

logger = logging.getLogger(__name__)


class StateManager:
    """Encodes and decodes OAuth state parameters with HMAC-SHA256 signatures.

    State format (before base64url encoding)::

        <json_payload>.<hmac_hex_signature>

    where the JSON payload contains::

        {"uid": <user_id>, "ts": <unix_timestamp>, "n": "<nonce>"}

    Args:
        state_secret: Secret key used for HMAC signing.
            Must be at least ``MIN_STATE_SECRET_LENGTH`` characters.

    Raises:
        ValueError: If *state_secret* is shorter than ``MIN_STATE_SECRET_LENGTH``.
    """

    def __init__(self, state_secret: str) -> None:
        if not state_secret or len(state_secret) < MIN_STATE_SECRET_LENGTH:
            raise ValueError(
                f"state_secret must be at least {MIN_STATE_SECRET_LENGTH} characters, "
                f"got {len(state_secret) if state_secret else 0}"
            )
        self._secret = state_secret.encode()
        self._hash_algo = hashlib.sha256

    def encode_state(self, user_id: str | int) -> str:
        """Encode *user_id* into a signed, base64url-safe state string.

        Args:
            user_id: An application-defined identifier to embed in the state
                (e.g. a database ID or Telegram user ID).

        Returns:
            A base64url-encoded signed state string safe for use in URLs.
        """
        timestamp = int(time.time())
        nonce = secrets.token_hex(NONCE_LENGTH)

        payload = json.dumps({"uid": user_id, "ts": timestamp, "n": nonce})
        signature = hmac.new(self._secret, payload.encode(), self._hash_algo).hexdigest()

        state_data = f"{payload}.{signature}"
        encoded = base64.urlsafe_b64encode(state_data.encode()).decode()

        logger.debug("Encoded state for user_id=%s length=%d", user_id, len(encoded))
        return encoded

    def decode_state(self, state: str) -> str | int:
        """Decode and validate a signed state string.

        Args:
            state: A base64url-encoded state string previously produced by
                :meth:`encode_state`.

        Returns:
            The *user_id* that was embedded when the state was created.

        Raises:
            OAuthInvalidStateError: If the state is malformed, the signature
                does not match, or required fields are missing.
            OAuthStateExpiredError: If the state is older than
                ``STATE_EXPIRY_SECONDS``.
        """
        # 1. Base64url decode
        try:
            state_data = base64.urlsafe_b64decode(state.encode()).decode()
        except Exception as exc:
            raise OAuthInvalidStateError(f"Malformed base64url state: {exc}") from exc

        # 2. Split payload and signature
        try:
            payload, received_sig = state_data.rsplit(".", 1)
        except ValueError as exc:
            raise OAuthInvalidStateError(
                "State format invalid — expected '<payload>.<signature>'"
            ) from exc

        # 3. Verify HMAC signature (constant-time)
        expected_sig = hmac.new(self._secret, payload.encode(), self._hash_algo).hexdigest()
        if not hmac.compare_digest(expected_sig, received_sig):
            raise OAuthInvalidStateError("State signature verification failed")

        # 4. Parse JSON
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise OAuthInvalidStateError(f"State payload is not valid JSON: {exc}") from exc

        # 5. Validate required fields
        missing = [f for f in ("uid", "ts", "n") if f not in data]
        if missing:
            raise OAuthInvalidStateError(f"State payload missing fields: {missing}")

        # 6. Check expiry
        age = int(time.time()) - data["ts"]
        if age > STATE_EXPIRY_SECONDS:
            raise OAuthStateExpiredError(
                f"State expired after {age}s (max {STATE_EXPIRY_SECONDS}s)"
            )

        logger.debug("Decoded state for user_id=%s age=%ds", data["uid"], age)
        return data["uid"]
