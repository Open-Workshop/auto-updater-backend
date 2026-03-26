import unittest
from unittest.mock import Mock, patch

from aiohttp_socks._errors import ProxyError

from steam_mod import SteamWorkshopClient


class _FakeSession:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class SteamModProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_socks_proxy_uses_aiohttp_socks_connector(self) -> None:
        client = SteamWorkshopClient()
        session_factory = Mock(side_effect=_FakeSession)
        connector_factory = Mock(return_value="connector")
        with patch("steam_mod.aiohttp.ClientSession", session_factory):
            with patch("steam_mod.ProxyConnector.from_url", connector_factory):
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


if __name__ == "__main__":
    unittest.main()
