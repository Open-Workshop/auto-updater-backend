import unittest

from core.proxy_stats import (
    ProxyStatsCollector,
    format_proxy_window_label,
    normalize_proxy_endpoint,
    parse_proxy_window_spec,
    proxy_error_type,
)


class ProxyStatsTests(unittest.TestCase):
    def test_snapshot_groups_by_proxy_endpoint_and_respects_window(self) -> None:
        collector = ProxyStatsCollector(recent_window_seconds=3600.0)
        collector.record(
            proxy="http://user:pass@proxy.example:3000",
            success=True,
            elapsed_seconds=0.25,
            now=100.0,
        )
        collector.record(
            proxy="http://other:creds@proxy.example:3000",
            success=False,
            elapsed_seconds=0.75,
            error_type="ProxyTimeoutError",
            now=120.0,
        )
        collector.record(
            proxy="http://proxy.example:3001",
            success=True,
            elapsed_seconds=1.0,
            now=20.0,
        )

        snapshot = collector.snapshot(window_seconds=30.0, now=130.0)

        self.assertEqual(snapshot["proxyCount"], 1)
        self.assertEqual(snapshot["totalCalls"], 2)
        self.assertEqual(snapshot["successCalls"], 1)
        self.assertEqual(snapshot["failureCalls"], 1)
        self.assertEqual(snapshot["recentRequests"], 2)
        self.assertEqual(snapshot["errorCounts"], {"ProxyTimeoutError": 1})
        self.assertAlmostEqual(snapshot["averageResponseMs"], 500.0)
        self.assertEqual(snapshot["windowLabel"], "30s")
        self.assertEqual(snapshot["proxies"][0]["proxyKey"], "http://proxy.example:3000")
        self.assertEqual(snapshot["proxies"][0]["proxyLabel"], "http://proxy.example:3000")
        self.assertEqual(snapshot["proxies"][0]["totalCalls"], 2)
        self.assertEqual(snapshot["proxies"][0]["errorCounts"], {"ProxyTimeoutError": 1})

    def test_snapshot_prunes_outside_recent_window(self) -> None:
        collector = ProxyStatsCollector(recent_window_seconds=3600.0)
        collector.record(
            proxy="http://proxy.example:3000",
            success=True,
            elapsed_seconds=1.0,
            now=1.0,
        )
        collector.record(
            proxy="http://proxy.example:3000",
            success=True,
            elapsed_seconds=1.0,
            now=101.0,
        )

        snapshot = collector.snapshot(window_seconds=5.0, now=101.0)

        self.assertEqual(snapshot["proxyCount"], 1)
        self.assertEqual(snapshot["totalCalls"], 1)
        self.assertEqual(snapshot["proxies"][0]["totalCalls"], 1)

    def test_proxy_error_type_normalizes_http_and_dns_failures(self) -> None:
        self.assertEqual(proxy_error_type(status_code=503), "HTTP_503")
        self.assertEqual(
            proxy_error_type(RuntimeError("Temporary failure in name resolution")),
            "DNSError",
        )
        self.assertEqual(proxy_error_type(ValueError("boom")), "ValueError")

    def test_window_parser_supports_presets_and_second_suffixes(self) -> None:
        seconds, label = parse_proxy_window_spec("1h")
        self.assertEqual(seconds, 3600.0)
        self.assertEqual(label, "1h")

        seconds, label = parse_proxy_window_spec("90m")
        self.assertEqual(seconds, 5400.0)
        self.assertEqual(label, "90m")

        seconds, label = parse_proxy_window_spec("3600")
        self.assertEqual(seconds, 3600.0)
        self.assertEqual(label, "1h")

    def test_normalize_proxy_endpoint_strips_credentials(self) -> None:
        self.assertEqual(
            normalize_proxy_endpoint("socks5://user:pass@46.8.223.44:3001"),
            "socks5://46.8.223.44:3001",
        )
        self.assertEqual(format_proxy_window_label(86400.0), "24h")


if __name__ == "__main__":
    unittest.main()
