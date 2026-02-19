"""Tests for TwitterOAuthService — the main OAuth flow orchestrator."""

import json
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from twitter_oauth_pkce.constants import OAUTH_SCOPES, SCOPE_TWEET_WRITE
from twitter_oauth_pkce.exceptions import (
    OAuthAPIError,
    OAuthInvalidStateError,
    OAuthMissingCredentialsError,
    OAuthRevokeError,
    OAuthTokenExchangeError,
)
from twitter_oauth_pkce.service import TwitterOAuthService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SERVICE_KWARGS = dict(
    client_id="test-client-id",
    client_secret="test-client-secret",
    redirect_uri="https://example.com/callback",
    state_secret="a" * 32,
)


@pytest.fixture
def service():
    return TwitterOAuthService(**SERVICE_KWARGS)


def _mock_response(status_code: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = json.dumps(body)
    resp.reason = "OK" if status_code == 200 else "Bad Request"
    return resp


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestInit:
    def test_raises_on_empty_client_id(self):
        with pytest.raises(OAuthMissingCredentialsError, match="client_id"):
            TwitterOAuthService(**{**SERVICE_KWARGS, "client_id": ""})

    def test_raises_on_empty_client_secret(self):
        with pytest.raises(OAuthMissingCredentialsError, match="client_secret"):
            TwitterOAuthService(**{**SERVICE_KWARGS, "client_secret": ""})

    def test_raises_on_short_state_secret(self):
        with pytest.raises(ValueError, match="at least 32"):
            TwitterOAuthService(**{**SERVICE_KWARGS, "state_secret": "tooshort"})

    def test_valid_init_succeeds(self):
        svc = TwitterOAuthService(**SERVICE_KWARGS)
        assert svc._client_id == "test-client-id"
        assert svc._redirect_uri == "https://example.com/callback"


# ---------------------------------------------------------------------------
# generate_authorization_url
# ---------------------------------------------------------------------------


class TestGenerateAuthorizationUrl:
    def test_returns_x_domain(self, service):
        url = service.generate_authorization_url(user_id=1)
        assert url.startswith("https://x.com/i/oauth2/authorize")

    def test_contains_required_params(self, service):
        url = service.generate_authorization_url(user_id=1)
        assert "response_type=code" in url
        assert "client_id=test-client-id" in url
        assert "code_challenge_method=S256" in url
        assert "state=" in url
        assert "code_challenge=" in url

    def test_default_scopes_included(self, service):
        url = service.generate_authorization_url(user_id=1)
        for scope in OAUTH_SCOPES:
            assert scope in url

    def test_custom_scopes_override_default(self, service):
        url = service.generate_authorization_url(
            user_id=1, scopes=[SCOPE_TWEET_WRITE, "users.read"]
        )
        assert "tweet.write" in url
        assert "users.read" in url
        # offline.access is default but not in custom list
        assert "offline.access" not in url

    def test_different_calls_produce_different_states(self, service):
        url1 = service.generate_authorization_url(user_id=1)
        url2 = service.generate_authorization_url(user_id=1)
        # extract state param
        state1 = [p for p in url1.split("&") if p.startswith("state=")][0]
        state2 = [p for p in url2.split("&") if p.startswith("state=")][0]
        assert state1 != state2

    def test_int_and_str_user_id_accepted(self, service):
        service.generate_authorization_url(user_id=42)
        service.generate_authorization_url(user_id="user-abc")


# ---------------------------------------------------------------------------
# exchange_code_for_tokens
# ---------------------------------------------------------------------------


class TestExchangeCodeForTokens:
    def _generate_state(self, service, user_id=1):
        url = service.generate_authorization_url(user_id=user_id)
        return parse_qs(urlparse(url).query)["state"][0]

    def test_success_returns_tokens_and_user_id(self, service):
        state = self._generate_state(service, user_id=99)
        token_body = {
            "access_token": "at123",
            "refresh_token": "rt456",
            "expires_in": 7200,
            "token_type": "bearer",
            "scope": "tweet.read users.read",
        }
        with patch("requests.post", return_value=_mock_response(200, token_body)):
            tokens, user_id = service.exchange_code_for_tokens(code="code123", state=state)

        assert tokens.access_token == "at123"
        assert tokens.refresh_token == "rt456"
        assert tokens.expires_in == 7200
        assert tokens.scope == ["tweet.read", "users.read"]
        assert user_id == 99

    def test_raises_on_invalid_state(self, service):
        with pytest.raises(OAuthInvalidStateError):
            service.exchange_code_for_tokens(code="x", state="not-a-valid-state")

    def test_raises_when_state_not_in_store(self, service):
        # Generate a valid signed state but don't call generate_authorization_url
        # (so nothing is stored in the PKCE store)
        state = service._state_manager.encode_state(1)
        with pytest.raises(OAuthInvalidStateError, match="not found in store"):
            service.exchange_code_for_tokens(code="x", state=state)

    def test_state_consumed_after_first_use(self, service):
        state = self._generate_state(service, user_id=1)
        token_body = {"access_token": "at", "refresh_token": None, "expires_in": 7200}
        with patch("requests.post", return_value=_mock_response(200, token_body)):
            service.exchange_code_for_tokens(code="code", state=state)

        # Second call with the same state must fail
        with pytest.raises(OAuthInvalidStateError):
            service.exchange_code_for_tokens(code="code", state=state)

    def test_raises_on_token_endpoint_error(self, service):
        state = self._generate_state(service, user_id=1)
        with patch("requests.post", return_value=_mock_response(400, {"error": "bad_request"})):
            with pytest.raises(OAuthTokenExchangeError, match="400"):
                service.exchange_code_for_tokens(code="code", state=state)

    def test_raises_on_network_error(self, service):
        state = self._generate_state(service, user_id=1)
        with patch("requests.post", side_effect=ConnectionError("timeout")):
            with pytest.raises(OAuthTokenExchangeError, match="timeout"):
                service.exchange_code_for_tokens(code="code", state=state)

    def test_scope_defaults_to_empty_list_when_absent(self, service):
        state = self._generate_state(service, user_id=1)
        token_body = {"access_token": "at", "refresh_token": None, "expires_in": 7200}
        with patch("requests.post", return_value=_mock_response(200, token_body)):
            tokens, _ = service.exchange_code_for_tokens(code="code", state=state)
        assert tokens.scope == []


# ---------------------------------------------------------------------------
# refresh_tokens
# ---------------------------------------------------------------------------


class TestRefreshTokens:
    def test_success_returns_new_tokens(self, service):
        token_body = {
            "access_token": "new-at",
            "refresh_token": "new-rt",
            "expires_in": 7200,
            "token_type": "bearer",
            "scope": "tweet.read users.read offline.access",
        }
        with patch("requests.post", return_value=_mock_response(200, token_body)):
            tokens = service.refresh_tokens("old-rt")

        assert tokens.access_token == "new-at"
        assert tokens.refresh_token == "new-rt"
        assert tokens.scope == ["tweet.read", "users.read", "offline.access"]

    def test_posts_to_token_endpoint(self, service):
        token_body = {"access_token": "at", "refresh_token": None, "expires_in": 7200}
        with patch("requests.post", return_value=_mock_response(200, token_body)) as mock_post:
            service.refresh_tokens("old-rt")

        call_args = mock_post.call_args
        assert call_args[0][0] == TwitterOAuthService._TOKEN_ENDPOINT
        assert call_args[1]["data"]["grant_type"] == "refresh_token"
        assert call_args[1]["data"]["refresh_token"] == "old-rt"

    def test_raises_on_error_response(self, service):
        with patch("requests.post", return_value=_mock_response(401, {"error": "invalid_token"})):
            with pytest.raises(OAuthTokenExchangeError, match="401"):
                service.refresh_tokens("bad-rt")

    def test_raises_on_network_error(self, service):
        with patch("requests.post", side_effect=ConnectionError("network")):
            with pytest.raises(OAuthTokenExchangeError):
                service.refresh_tokens("rt")


# ---------------------------------------------------------------------------
# revoke_token
# ---------------------------------------------------------------------------


class TestRevokeToken:
    def test_success_returns_none(self, service):
        with patch("requests.post", return_value=_mock_response(200, {})):
            result = service.revoke_token("some-token")
        assert result is None

    def test_posts_to_revoke_endpoint(self, service):
        with patch("requests.post", return_value=_mock_response(200, {})) as mock_post:
            service.revoke_token("tok")

        call_args = mock_post.call_args
        assert call_args[0][0] == TwitterOAuthService._REVOKE_ENDPOINT
        assert call_args[1]["data"]["token"] == "tok"

    def test_raises_on_error_response(self, service):
        with patch("requests.post", return_value=_mock_response(400, {"error": "bad"})):
            with pytest.raises(OAuthRevokeError, match="400"):
                service.revoke_token("tok")

    def test_raises_on_network_error(self, service):
        with patch("requests.post", side_effect=ConnectionError("timeout")):
            with pytest.raises(OAuthRevokeError):
                service.revoke_token("tok")


# ---------------------------------------------------------------------------
# get_authenticated_user_info
# ---------------------------------------------------------------------------


class TestGetAuthenticatedUserInfo:
    USER_DATA = {
        "id": "123",
        "name": "Test User",
        "username": "testuser",
        "profile_image_url": "https://example.com/pic.jpg",
        "description": "Bio",
        "public_metrics": {"followers_count": 10},
        "verified": False,
        "created_at": "2020-01-01T00:00:00.000Z",
    }

    def test_success_returns_data(self, service):
        with patch("requests.get", return_value=_mock_response(200, {"data": self.USER_DATA})):
            profile = service.get_authenticated_user_info("access-token")

        assert profile["data"]["username"] == "testuser"
        assert profile["data"]["id"] == "123"

    def test_sends_bearer_auth_header(self, service):
        with patch(
            "requests.get", return_value=_mock_response(200, {"data": self.USER_DATA})
        ) as mock_get:
            service.get_authenticated_user_info("my-token")

        headers = mock_get.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer my-token"

    def test_calls_x_api_domain(self, service):
        with patch(
            "requests.get", return_value=_mock_response(200, {"data": self.USER_DATA})
        ) as mock_get:
            service.get_authenticated_user_info("token")

        url = mock_get.call_args[0][0]
        assert "api.x.com" in url

    def test_raises_oauth_api_error_on_non_200(self, service):
        with patch("requests.get", return_value=_mock_response(401, {"detail": "Unauthorized"})):
            with pytest.raises(OAuthAPIError, match="401"):
                service.get_authenticated_user_info("bad-token")

    def test_uses_class_level_timeout(self, service):
        with patch(
            "requests.get", return_value=_mock_response(200, {"data": self.USER_DATA})
        ) as mock_get:
            service.get_authenticated_user_info("token")

        assert mock_get.call_args[1]["timeout"] == TwitterOAuthService._TIMEOUT
