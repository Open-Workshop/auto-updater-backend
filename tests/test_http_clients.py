import base64
import json
import unittest
from unittest.mock import Mock, patch

import steam.steam_api as steam_api_module
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


def _fake_token(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"header.{encoded}.signature"


class _InitResponse:
    def __init__(
        self,
        *,
        url: str = "https://api.openworkshop.miskler.ru/resources/upload-init",
        headers: dict[str, str] | None = None,
        payload: dict | None = None,
        status_code: int = 200,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class HttpClientTests(unittest.TestCase):
    def test_steam_client_closes_retry_response_before_retrying(self) -> None:
        client = SteamClient(policy=RetryPolicy(retries=1, backoff=0.0, request_delay=0.0))
        first = _FakeResponse(503)
        second = _FakeResponse(200)

        with patch.object(steam_api_module.requests, "request", side_effect=[first, second]):
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

    def test_transfer_from_init_uses_explicit_ws_url(self) -> None:
        client = OWClient("https://example.com", "demo", "secret", timeout=5, retries=0, retry_backoff=0.0)
        response = _InitResponse(
            payload={
                "transfer_url": "https://storage.openworkshop.miskler.ru/transfer/upload?token=abc",
                "ws_url": "https://storage.openworkshop.miskler.ru/transfer/ws/42?token=abc",
            }
        )

        transfer = client._transfer_from_init(response)

        self.assertIsNotNone(transfer)
        self.assertEqual(
            transfer.transfer_url,
            "https://storage.openworkshop.miskler.ru/transfer/upload?token=abc",
        )
        self.assertEqual(
            transfer.ws_url,
            "wss://storage.openworkshop.miskler.ru/transfer/ws/42?token=abc",
        )

    def test_transfer_from_init_derives_ws_url_from_token_job_id(self) -> None:
        client = OWClient("https://example.com", "demo", "secret", timeout=5, retries=0, retry_backoff=0.0)
        token = _fake_token({"job_id": 123})
        response = _InitResponse(
            headers={
                "Location": f"https://storage.openworkshop.miskler.ru/transfer/upload?token={token}"
            },
            status_code=307,
        )

        transfer = client._transfer_from_init(response)

        self.assertIsNotNone(transfer)
        self.assertEqual(
            transfer.ws_url,
            f"wss://storage.openworkshop.miskler.ru/transfer/ws/123?token={token}",
        )

    def test_storage_progress_update_uses_repack_percent_field(self) -> None:
        progress = OWClient._storage_progress_update(
            {
                "event": "progress",
                "stage": "repacking",
                "bytes": 1048576,
                "total": 2097152,
                "percent": 37,
            }
        )

        self.assertEqual(progress.stage, "repacking")
        self.assertEqual(progress.percent, 37)
        self.assertEqual(progress.sent_bytes, 1048576)
        self.assertEqual(progress.total_bytes, 2097152)
        self.assertTrue(progress.explicit_percent)

    def test_storage_progress_update_falls_back_to_bytes_ratio(self) -> None:
        progress = OWClient._storage_progress_update(
            {
                "event": "progress",
                "stage": "uploading",
                "bytes": 50,
                "total": 200,
            }
        )

        self.assertEqual(progress.stage, "uploading")
        self.assertEqual(progress.percent, 25)
        self.assertEqual(progress.sent_bytes, 50)
        self.assertEqual(progress.total_bytes, 200)
        self.assertFalse(progress.explicit_percent)


if __name__ == "__main__":
    unittest.main()
