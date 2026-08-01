from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from rdt_cli.auth import Credential
from rdt_cli.client import RedditClient
from rdt_cli.config import RuntimeConfig
from rdt_cli.exceptions import RedditApiError
from rdt_cli.fingerprint import BrowserFingerprint
from rdt_cli.session import SessionState
from rdt_cli.transports import ReadTransport


def test_validate_session_success_updates_username_and_capabilities() -> None:
    cred = Credential(cookies={"reddit_session": "abc"})
    with RedditClient(cred) as client:
        with patch.object(client, "_get", return_value={"name": "spez", "modhash": "mh"}):
            result = client.validate_session()

    assert result["authenticated"] is True
    assert result["username"] == "spez"
    assert "write" in result["capabilities"]


def test_validate_session_failure_preserves_read_capability() -> None:
    cred = Credential(cookies={"reddit_session": "abc"})
    with RedditClient(cred) as client:
        with patch.object(client, "_get", side_effect=RedditApiError("boom")):
            result = client.validate_session()

    assert result["authenticated"] is False
    assert result["capabilities"] == ["read"]
    assert result["error"] == "boom"


def test_get_user_saved_uses_saved_endpoint() -> None:
    cred = Credential(cookies={"reddit_session": "abc"})
    with RedditClient(cred) as client:
        with patch.object(client, "_get", return_value={"ok": True}) as mock_get:
            data = client.get_user_saved("spez", limit=5, after="t3_next")

    assert data == {"ok": True}
    mock_get.assert_called_once_with("/user/spez/saved.json", params={"limit": 5, "raw_json": 1, "after": "t3_next"})


def test_get_user_upvoted_uses_upvoted_endpoint() -> None:
    cred = Credential(cookies={"reddit_session": "abc"})
    with RedditClient(cred) as client:
        with patch.object(client, "_get", return_value={"ok": True}) as mock_get:
            data = client.get_user_upvoted("spez", limit=7)

    assert data == {"ok": True}
    mock_get.assert_called_once_with("/user/spez/upvoted.json", params={"limit": 7, "raw_json": 1})


def test_get_more_comments_uses_api_morechildren() -> None:
    cred = Credential(cookies={"reddit_session": "abc"})
    with RedditClient(cred) as client:
        with patch.object(client, "_get", return_value={"json": {"data": {"things": []}}}) as mock_get:
            data = client.get_more_comments("abc123", ["c3", "c4"], sort="top")

    assert data["json"]["data"]["things"] == []
    mock_get.assert_called_once_with(
        "/api/morechildren.json",
        params={
            "api_type": "json",
            "link_id": "t3_abc123",
            "children": "c3,c4",
            "sort": "top",
            "limit_children": False,
            "raw_json": 1,
        },
    )


def _read_transport() -> ReadTransport:
    return ReadTransport(
        SessionState.from_credential(Credential(cookies={"reddit_session": "secret", "tracking": "discard"})),
        config=RuntimeConfig(),
        fingerprint=BrowserFingerprint.chrome133_mac(),
        request_delay=0,
    )


def test_transport_scopes_auth_cookies_to_reddit_and_disables_redirects() -> None:
    transport = _read_transport()
    try:
        cookies = list(transport.client.cookies.jar)
        assert [(cookie.name, cookie.domain) for cookie in cookies] == [
            ("reddit_session", ".reddit.com")
        ]
        assert transport.client.follow_redirects is False
        reddit_request = transport.client.build_request("GET", "/api/me.json")
        foreign_request = transport.client.build_request("GET", "https://example.invalid/steal")
        assert "cookie" in reddit_request.headers
        assert "cookie" not in foreign_request.headers
    finally:
        transport.close()


def test_transport_rejects_cross_origin_request_before_network() -> None:
    transport = _read_transport()
    try:
        with patch.object(transport.client, "request") as request:
            with pytest.raises(RedditApiError, match="outside www.reddit.com"):
                transport.request("GET", "https://example.invalid/steal")
            request.assert_not_called()
    finally:
        transport.close()


def test_transport_allows_relative_reddit_request() -> None:
    transport = _read_transport()
    try:
        transport._validate_request_target("/r/python.json")
    finally:
        transport.close()


def test_transport_rejects_redirect_response() -> None:
    transport = _read_transport()
    request = httpx.Request("GET", "https://www.reddit.com/api/me.json")
    response = httpx.Response(
        302,
        headers={"location": "https://example.invalid/steal"},
        request=request,
    )
    try:
        with patch.object(transport.client, "request", return_value=response):
            with pytest.raises(RedditApiError, match="refusing to forward credentials"):
                transport.request("GET", "/api/me.json")
    finally:
        transport.close()
