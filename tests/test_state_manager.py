"""Tests for StateManager — HMAC-SHA256 OAuth state encoding/decoding."""

import base64
import json
import time

import pytest

from twitter_oauth_pkce._internal.security import StateManager
from twitter_oauth_pkce.exceptions import OAuthInvalidStateError, OAuthStateExpiredError

SECRET = "a" * 32  # minimum-length valid secret


class TestStateManagerInit:
    def test_accepts_valid_secret(self):
        StateManager(state_secret=SECRET)  # should not raise

    def test_rejects_short_secret(self):
        with pytest.raises(ValueError, match="at least 32"):
            StateManager(state_secret="tooshort")

    def test_rejects_empty_secret(self):
        with pytest.raises(ValueError):
            StateManager(state_secret="")


class TestEncodeState:
    def test_returns_string(self):
        sm = StateManager(SECRET)
        assert isinstance(sm.encode_state(42), str)

    def test_is_base64url(self):
        sm = StateManager(SECRET)
        state = sm.encode_state(42)
        # Should decode without error
        base64.urlsafe_b64decode(state + "==")

    def test_unique_per_call(self):
        sm = StateManager(SECRET)
        states = {sm.encode_state(1) for _ in range(20)}
        assert len(states) == 20  # nonce ensures uniqueness

    def test_int_and_str_user_ids_accepted(self):
        sm = StateManager(SECRET)
        sm.encode_state(42)
        sm.encode_state("user-abc")


class TestDecodeState:
    def test_roundtrip_int_user_id(self):
        sm = StateManager(SECRET)
        state = sm.encode_state(42)
        assert sm.decode_state(state) == 42

    def test_roundtrip_str_user_id(self):
        sm = StateManager(SECRET)
        state = sm.encode_state("user-abc")
        assert sm.decode_state(state) == "user-abc"

    def test_tampered_signature_raises(self):
        sm = StateManager(SECRET)
        state = sm.encode_state(1)
        # Flip the last character
        tampered = state[:-1] + ("A" if state[-1] != "A" else "B")
        with pytest.raises(OAuthInvalidStateError):
            sm.decode_state(tampered)

    def test_wrong_secret_raises(self):
        sm1 = StateManager("a" * 32)
        sm2 = StateManager("b" * 32)
        state = sm1.encode_state(1)
        with pytest.raises(OAuthInvalidStateError, match="signature"):
            sm2.decode_state(state)

    def test_garbage_input_raises(self):
        sm = StateManager(SECRET)
        with pytest.raises(OAuthInvalidStateError):
            sm.decode_state("not-valid-base64!!!")

    def test_expired_state_raises(self, monkeypatch):
        sm = StateManager(SECRET)
        # Encode at t=0, decode at t=301 (past 300s TTL)
        monkeypatch.setattr(time, "time", lambda: 1_000_000.0)
        state = sm.encode_state(1)
        monkeypatch.setattr(time, "time", lambda: 1_000_301.0)
        with pytest.raises(OAuthStateExpiredError):
            sm.decode_state(state)

    def test_fresh_state_not_expired(self, monkeypatch):
        sm = StateManager(SECRET)
        monkeypatch.setattr(time, "time", lambda: 1_000_000.0)
        state = sm.encode_state(1)
        monkeypatch.setattr(time, "time", lambda: 1_000_299.0)
        assert sm.decode_state(state) == 1  # should not raise

    def test_missing_uid_field_raises(self):
        sm = StateManager(SECRET)
        # Build a valid-signature state but without uid
        import hmac as hmac_mod
        import hashlib

        payload = json.dumps({"ts": int(time.time()), "n": "abc"})
        sig = hmac_mod.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        raw = base64.urlsafe_b64encode(f"{payload}.{sig}".encode()).decode()
        with pytest.raises(OAuthInvalidStateError, match="missing fields"):
            sm.decode_state(raw)

    def test_no_dot_separator_raises(self):
        sm = StateManager(SECRET)
        # base64url encode something without a dot
        raw = base64.urlsafe_b64encode(b"nodothere").decode()
        with pytest.raises(OAuthInvalidStateError):
            sm.decode_state(raw)
