"""Tests for OAuthTokens data model."""


from twitter_oauth_pkce.models import OAuthTokens


class TestOAuthTokens:
    def test_required_fields(self):
        t = OAuthTokens(access_token="at", refresh_token="rt", expires_in=7200)
        assert t.access_token == "at"
        assert t.refresh_token == "rt"
        assert t.expires_in == 7200

    def test_defaults(self):
        t = OAuthTokens(access_token="at", refresh_token=None, expires_in=7200)
        assert t.token_type == "bearer"
        assert t.scope == []

    def test_scope_defaults_to_empty_list(self):
        t = OAuthTokens(access_token="at", refresh_token=None, expires_in=7200)
        assert isinstance(t.scope, list)
        assert t.scope == []

    def test_scope_accepts_list(self):
        t = OAuthTokens(
            access_token="at",
            refresh_token=None,
            expires_in=7200,
            scope=["tweet.read", "users.read"],
        )
        assert t.scope == ["tweet.read", "users.read"]

    def test_scope_instances_are_independent(self):
        # Mutable default must not be shared between instances
        t1 = OAuthTokens(access_token="a", refresh_token=None, expires_in=1)
        t2 = OAuthTokens(access_token="b", refresh_token=None, expires_in=1)
        t1.scope.append("tweet.read")
        assert t2.scope == []

    def test_refresh_token_can_be_none(self):
        t = OAuthTokens(access_token="at", refresh_token=None, expires_in=7200)
        assert t.refresh_token is None

    def test_custom_token_type(self):
        t = OAuthTokens(access_token="at", refresh_token=None, expires_in=7200, token_type="MAC")
        assert t.token_type == "MAC"
