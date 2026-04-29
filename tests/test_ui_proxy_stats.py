from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

try:
    from ui.ui_proxy_stats import _fetch_proxy_snapshot, _load_proxy_statistics
except ModuleNotFoundError:
    _fetch_proxy_snapshot = None
    _load_proxy_statistics = None


@unittest.skipUnless(
    _load_proxy_statistics is not None and _fetch_proxy_snapshot is not None,
    "ui dependencies are not installed",
)
class UIProxyStatsTests(unittest.TestCase):
    def test_fetch_proxy_snapshot_normalizes_flat_proxy_payload(self) -> None:
        settings = SimpleNamespace(namespace="auto-updater")
        summary = {"name": "demo-a", "parser": {"podName": "demo-parser-0"}}
        raw_payload = {
            "generatedAt": "2026-04-29T11:15:00+00:00",
            "windowSeconds": 3600.0,
            "windowLabel": "1h",
            "instanceName": "demo-a",
            "workloadId": "parser",
            "podName": "demo-parser-0",
            "proxyConfigured": True,
            "proxyPoolSize": 1,
            "proxyScope": "mod_pages",
            "stats": {
                "windowSeconds": 3600.0,
                "windowLabel": "1h",
                "totalCalls": 3,
                "successCalls": 2,
                "failureCalls": 1,
                "totalElapsedSeconds": 1.5,
                "averageResponseMs": 500.0,
                "recentRequests": 3,
                "recentWindowSeconds": 3600.0,
                "requestsPerSecond": 3 / 3600.0,
                "requestsPerMinute": 3 / 60.0,
                "errorCounts": {"ProxyError": 1},
                "proxyCount": 1,
            },
            "proxies": [
                {
                    "proxyKey": "socks5://10.0.0.9:3001",
                    "proxyLabel": "socks5://10.0.0.9:3001",
                    "totalCalls": 3,
                    "successCalls": 2,
                    "failureCalls": 1,
                    "totalElapsedSeconds": 1.5,
                    "averageResponseMs": 500.0,
                    "recentRequests": 3,
                    "recentWindowSeconds": 3600.0,
                    "windowSeconds": 3600.0,
                    "windowLabel": "1h",
                    "requestsPerSecond": 3 / 3600.0,
                    "requestsPerMinute": 3 / 60.0,
                    "errorCounts": {"ProxyError": 1},
                }
            ],
        }
        response = Mock()
        response.ok = True
        response.json.return_value = raw_payload

        with patch("ui.ui_proxy_stats.requests.get", return_value=response):
            payload = _fetch_proxy_snapshot(
                settings,
                summary,
                window_spec="1h",
                window_seconds=3600.0,
            )

        self.assertEqual(payload["proxyCount"], 1)
        self.assertEqual(payload["stats"]["totalCalls"], 3)
        self.assertEqual(payload["proxies"][0]["stats"]["totalCalls"], 3)
        self.assertEqual(payload["proxies"][0]["stats"]["failureCalls"], 1)

    def test_merge_same_proxy_across_multiple_pods(self) -> None:
        settings = SimpleNamespace(namespace="auto-updater")
        summaries = [
            {"name": "demo-a", "parser": {"podName": "demo-parser-0"}},
            {"name": "demo-b", "parser": {"podName": "demo-parser-1"}},
        ]

        def fake_fetch(_settings, summary, *, window_spec, window_seconds):
            pod_name = str(summary.get("parser", {}).get("podName") or "")
            success_calls = 4 if pod_name == "demo-parser-0" else 1
            failure_calls = 0 if pod_name == "demo-parser-0" else 2
            total_calls = success_calls + failure_calls
            elapsed_seconds = 1.0 if pod_name == "demo-parser-0" else 0.75
            proxy_stats = {
                "totalCalls": total_calls,
                "successCalls": success_calls,
                "failureCalls": failure_calls,
                "totalElapsedSeconds": elapsed_seconds,
                "averageResponseMs": (elapsed_seconds / total_calls) * 1000.0,
                "recentRequests": total_calls,
                "recentWindowSeconds": window_seconds,
                "windowSeconds": window_seconds,
                "windowLabel": window_spec,
                "requestsPerSecond": total_calls / window_seconds,
                "requestsPerMinute": (total_calls / window_seconds) * 60.0,
                "errorCounts": {"ProxyTimeoutError": failure_calls} if failure_calls else {},
                "failureRate": (failure_calls / total_calls) if total_calls else 0.0,
                "topError": {
                    "label": "ProxyTimeoutError" if failure_calls else "",
                    "count": failure_calls,
                },
            }
            return {
                "instanceName": str(summary.get("name") or ""),
                "podName": pod_name,
                "reachable": True,
                "proxyConfigured": True,
                "proxyCount": 1,
                "windowSeconds": window_seconds,
                "windowLabel": window_spec,
                "stats": proxy_stats,
                "proxies": [
                    {
                        "proxyKey": "socks5://10.0.0.9:3001",
                        "proxyLabel": "socks5://10.0.0.9:3001",
                        **proxy_stats,
                    }
                ],
                "error": "",
                "generatedAt": "2026-04-29T11:15:00+00:00",
            }

        with (
            patch("ui.ui_proxy_stats._load_instance_summaries", return_value=summaries),
            patch("ui.ui_proxy_stats._fetch_proxy_snapshot", side_effect=fake_fetch),
        ):
            payload = _load_proxy_statistics(settings, window_spec="1h")

        self.assertEqual(payload["window"]["spec"], "1h")
        self.assertEqual(payload["summary"]["proxyCount"], 1)
        self.assertEqual(payload["summary"]["podsWithSuccess"], 2)
        self.assertEqual(payload["summary"]["degradedProxies"], 1)
        self.assertEqual(payload["summary"]["healthyProxies"], 0)
        self.assertEqual(payload["summary"]["totalCalls"], 7)
        self.assertEqual(payload["summary"]["failureCalls"], 2)
        self.assertEqual(payload["summary"]["errorCounts"], {"ProxyTimeoutError": 2})
        self.assertEqual(payload["sources"]["total"], 2)
        self.assertEqual(payload["sources"]["responded"], 2)
        self.assertEqual(len(payload["proxies"]), 1)
        proxy = payload["proxies"][0]
        self.assertEqual(proxy["proxyKey"], "socks5://10.0.0.9:3001")
        self.assertEqual(proxy["podCount"], 2)
        self.assertEqual(proxy["workingPodCount"], 2)
        self.assertEqual(proxy["stats"]["totalCalls"], 7)
        self.assertEqual(proxy["stats"]["successCalls"], 5)
        self.assertEqual(proxy["stats"]["failureCalls"], 2)


if __name__ == "__main__":
    unittest.main()
