import unittest

from http_utils import parse_proxy_url


class ProxyParsingTests(unittest.TestCase):
    def test_parse_http_proxy(self) -> None:
        proxy = parse_proxy_url("http://user:pass@46.8.223.44:3000")
        self.assertEqual(proxy.scheme, "http")
        self.assertEqual(proxy.host, "46.8.223.44")
        self.assertEqual(proxy.port, 3000)
        self.assertEqual(proxy.username, "user")
        self.assertEqual(proxy.password, "pass")
        self.assertTrue(proxy.is_http)

    def test_parse_socks_proxy(self) -> None:
        proxy = parse_proxy_url("socks5://user:pass@46.8.223.44:3001")
        self.assertEqual(proxy.scheme, "socks5")
        self.assertEqual(proxy.port, 3001)
        self.assertTrue(proxy.is_socks)

    def test_reject_invalid_proxy(self) -> None:
        with self.assertRaises(ValueError):
            parse_proxy_url("ftp://example.com:21")


if __name__ == "__main__":
    unittest.main()
