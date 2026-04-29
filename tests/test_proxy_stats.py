import unittest

from core.proxy_stats import ProxyStatsCollector, proxy_error_type


class ProxyStatsTests(unittest.TestCase):
    def test_snapshot_aggregates_success_failure_and_recent_window(self) -> None:
        collector = ProxyStatsCollector(recent_window_seconds=10.0)
        collector.record(proxy="http://proxy", success=True, elapsed_seconds=0.25, now=1.0)
        collector.record(
            proxy="http://proxy",
            success=False,
            elapsed_seconds=0.75,
            error_type="ProxyTimeoutError",
            now=2.0,
        )
        collector.record(
            proxy=None,
            success=False,
            elapsed_seconds=99.0,
            error_type="ProxyTimeoutError",
            now=3.0,
        )

        snapshot = collector.snapshot(now=3.0)

        self.assertEqual(snapshot["totalCalls"], 2)
        self.assertEqual(snapshot["successCalls"], 1)
        self.assertEqual(snapshot["failureCalls"], 1)
        self.assertEqual(snapshot["recentRequests"], 2)
        self.assertEqual(snapshot["errorCounts"], {"ProxyTimeoutError": 1})
        self.assertAlmostEqual(snapshot["averageResponseMs"], 500.0)

        collector.reset()
        snapshot = collector.snapshot(now=12.0)
        self.assertEqual(snapshot["totalCalls"], 0)
        self.assertEqual(snapshot["recentRequests"], 0)

    def test_proxy_error_type_normalizes_http_and_dns_failures(self) -> None:
        self.assertEqual(proxy_error_type(status_code=503), "HTTP_503")
        self.assertEqual(
            proxy_error_type(RuntimeError("Temporary failure in name resolution")),
            "DNSError",
        )
        self.assertEqual(proxy_error_type(ValueError("boom")), "ValueError")


if __name__ == "__main__":
    unittest.main()
