"""Tests for PKCEStore — thread-safe TTL cache for PKCE code verifiers."""

import base64
import hashlib
import threading
import time

import pytest

from twitter_oauth_pkce._internal.pkce_store import PKCEStore


class TestGeneratePkceVerifier:
    def test_returns_string(self):
        assert isinstance(PKCEStore.generate_pkce_verifier(), str)

    def test_length_is_43(self):
        # 32 bytes base64url-encoded without padding = 43 chars
        assert len(PKCEStore.generate_pkce_verifier()) == 43

    def test_no_padding(self):
        verifier = PKCEStore.generate_pkce_verifier()
        assert "=" not in verifier

    def test_url_safe_characters_only(self):
        for _ in range(20):
            verifier = PKCEStore.generate_pkce_verifier()
            assert all(
                c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                for c in verifier
            )

    def test_unique_per_call(self):
        verifiers = {PKCEStore.generate_pkce_verifier() for _ in range(50)}
        assert len(verifiers) == 50


class TestGeneratePkceChallenge:
    def test_is_sha256_of_verifier(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .decode()
            .rstrip("=")
        )
        assert PKCEStore.generate_pkce_challenge(verifier) == expected

    def test_no_padding(self):
        challenge = PKCEStore.generate_pkce_challenge(PKCEStore.generate_pkce_verifier())
        assert "=" not in challenge

    def test_different_verifiers_produce_different_challenges(self):
        v1 = PKCEStore.generate_pkce_verifier()
        v2 = PKCEStore.generate_pkce_verifier()
        assert PKCEStore.generate_pkce_challenge(v1) != PKCEStore.generate_pkce_challenge(v2)

    def test_deterministic(self):
        verifier = PKCEStore.generate_pkce_verifier()
        assert PKCEStore.generate_pkce_challenge(verifier) == PKCEStore.generate_pkce_challenge(
            verifier
        )


class TestPKCEStoreStoreAndRetrieve:
    def test_store_and_retrieve(self):
        store = PKCEStore()
        store.store("state1", "verifier1", user_id=42)
        result = store.retrieve_and_remove("state1")
        assert result == ("verifier1", 42)

    def test_retrieve_removes_entry(self):
        store = PKCEStore()
        store.store("state1", "verifier1", user_id=1)
        store.retrieve_and_remove("state1")
        assert store.retrieve_and_remove("state1") is None

    def test_retrieve_unknown_state_returns_none(self):
        store = PKCEStore()
        assert store.retrieve_and_remove("nonexistent") is None

    def test_string_user_id(self):
        store = PKCEStore()
        store.store("s", "v", user_id="user-abc")
        code_verifier, user_id = store.retrieve_and_remove("s")
        assert user_id == "user-abc"

    def test_multiple_entries_independent(self):
        store = PKCEStore()
        store.store("s1", "v1", user_id=1)
        store.store("s2", "v2", user_id=2)
        assert store.retrieve_and_remove("s1") == ("v1", 1)
        assert store.retrieve_and_remove("s2") == ("v2", 2)

    def test_overwrite_same_state(self):
        store = PKCEStore()
        store.store("s", "v1", user_id=1)
        store.store("s", "v2", user_id=2)
        assert store.retrieve_and_remove("s") == ("v2", 2)


class TestPKCEStoreThreadSafety:
    def test_concurrent_stores_and_retrieves(self):
        store = PKCEStore()
        results = {}
        errors = []

        def worker(i):
            state = f"state-{i}"
            verifier = f"verifier-{i}"
            store.store(state, verifier, user_id=i)
            result = store.retrieve_and_remove(state)
            if result != (verifier, i):
                errors.append(f"Mismatch for {i}: {result}")
            results[i] = result

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(results) == 50
