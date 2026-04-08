import unittest
from unittest.mock import Mock, patch

from ow.ow_api import OWClient
from steam.steam_api import RetryPolicy, SteamClient


class _FakeResponse:
    def __init__(self, status_code: int, *, headers: dict[str, str] | None = None, text: str = "") -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeSession:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = list(responses)

    def request(self, method: str, url: str, timeout: int, **kwargs):  # noqa: ANN001
        return self._responses.pop(0)


class HttpClientTests(unittest.TestCase):
    def test_steam_client_closes_retry_response_before_retrying(self) -> None:
        client = SteamClient(policy=RetryPolicy(retries=1, backoff=0.0, request_delay=0.0))
        first = _FakeResponse(503)
        second = _FakeResponse(200)

        with patch("steam.steam_api.requests.request", side_effect=[first, second]):
            response = client.request("get", "https://example.com/mod", timeout=5)

        self.assertIs(response, second)
        self.assertTrue(first.closed)
        self.assertFalse(second.closed)

    def test_ow_client_closes_retry_response_before_retrying(self) -> None:
        client = OWClient("https://example.com", "demo", "secret", timeout=5, retries=1, retry_backoff=0.0)
        first = _FakeResponse(503)
        second = _FakeResponse(200)
        client.session = _FakeSession([first, second])

        response = client.request("get", "/mods")

        self.assertIs(response, second)
        self.assertTrue(first.closed)
        self.assertFalse(second.closed)

    def test_ow_client_closes_unauthorized_response_before_reauth(self) -> None:
        client = OWClient("https://example.com", "demo", "secret", timeout=5, retries=0, retry_backoff=0.0)
        unauthorized = _FakeResponse(401)
        success = _FakeResponse(200)
        client.session = _FakeSession([unauthorized, success])
        client.login = Mock()

        response = client.request("get", "/mods")

        self.assertIs(response, success)
        self.assertTrue(unauthorized.closed)
        client.login.assert_called_once()


if __name__ == "__main__":
    unittest.main()
