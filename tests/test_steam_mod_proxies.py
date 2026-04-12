import unittest
from contextlib import asynccontextmanager
from unittest.mock import Mock, patch

from aiohttp_socks._errors import ProxyError, ProxyTimeoutError

from core.http_utils import ProxyPool, RetryPolicy
from steam.steam_mod import SteamWorkshopClient


class _FakeSession:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class SteamModProxyTests(unittest.IsolatedAsyncioTestCase):
    def test_proxy_pool_skips_reserved_proxy_until_cooldown_expires(self) -> None:
        pool = ProxyPool(["socks5://bad", "socks5://good"])

        pool.reserve("socks5://bad", 120.0, now=10.0)

        self.assertEqual(pool.next(now=10.0), "socks5://good")
        self.assertEqual(pool.next(now=50.0), "socks5://good")
        self.assertEqual(pool.next(now=131.0), "socks5://bad")

    async def test_socks_proxy_uses_aiohttp_socks_connector(self) -> None:
        client = SteamWorkshopClient()
        session_factory = Mock(side_effect=_FakeSession)
        connector_factory = Mock(return_value="connector")
        with patch("steam.steam_mod.aiohttp.ClientSession", session_factory):
            with patch("steam.steam_mod.ProxyConnector.from_url", connector_factory):
                async with client._session_for_request(
                    15,
                    "socks5://user:pass@46.8.223.44:3001",
                    None,
                ) as (session, proxy_arg):
                    self.assertIsInstance(session, _FakeSession)
                    self.assertIsNone(proxy_arg)
        connector_factory.assert_called_once_with("socks5://user:pass@46.8.223.44:3001")
        self.assertEqual(
            session_factory.call_args.kwargs["connector"],
            "connector",
        )

    async def test_http_proxy_reuses_existing_session(self) -> None:
        client = SteamWorkshopClient()
        existing_session = object()
        async with client._session_for_request(
            15,
            "http://user:pass@46.8.223.44:3000",
            existing_session,
        ) as (session, proxy_arg):
            self.assertIs(session, existing_session)
            self.assertEqual(proxy_arg, "http://user:pass@46.8.223.44:3000")

    async def test_fetch_mod_handles_proxy_error(self) -> None:
        client = SteamWorkshopClient()

        class _BrokenResponse:
            async def __aenter__(self):
                raise ProxyError("Connection refused by destination host")

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _BrokenSession:
            def get(self, *args, **kwargs):
                return _BrokenResponse()

        result = await client.fetch_mod(
            "12345",
            timeout=5,
            proxy="socks5://user:pass@46.8.223.44:3001",
            session=_BrokenSession(),
            language="english",
        )
        self.assertIsNone(result)

    async def test_fetch_mod_handles_proxy_timeout_and_reserves_proxy(self) -> None:
        bad_proxy = "socks5://user:pass@46.8.223.44:3001"
        good_proxy = "socks5://user:pass@46.8.223.45:3001"
        client = SteamWorkshopClient(
            policy=RetryPolicy(retries=1, backoff=0.0, request_delay=0.0),
            proxies=[bad_proxy, good_proxy],
        )
        reserve = Mock(wraps=client.proxy_pool.reserve)
        client.proxy_pool.reserve = reserve
        attempted_proxies: list[str | None] = []

        class _TimeoutResponse:
            async def __aenter__(self):
                raise ProxyTimeoutError("Proxy connection timed out: 60")

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _OkResponse:
            status = 200
            headers: dict[str, str] = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self) -> str:
                return (
                    '<div class="workshopItemTitle">Example</div>'
                    '<div class="workshopItemDescription">Desc</div>'
                )

        class _Session:
            def __init__(self, chosen_proxy: str | None) -> None:
                self.chosen_proxy = chosen_proxy

            def get(self, *args, **kwargs):
                if self.chosen_proxy == bad_proxy:
                    return _TimeoutResponse()
                return _OkResponse()

        @asynccontextmanager
        async def _fake_session_for_request(timeout_value, chosen_proxy, session):
            del timeout_value, session
            attempted_proxies.append(chosen_proxy)
            yield _Session(chosen_proxy), None

        with patch.object(client, "_session_for_request", _fake_session_for_request):
            result = await client.fetch_mod("12345", timeout=5, language="english")

        self.assertIsNotNone(result)
        self.assertEqual(attempted_proxies, [bad_proxy, good_proxy])
        reserve.assert_called_once_with(bad_proxy, 120.0)


if __name__ == "__main__":
    unittest.main()
