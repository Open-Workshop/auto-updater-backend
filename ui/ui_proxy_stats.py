from __future__ import annotations

"""Proxy telemetry aggregation for the UI service."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import requests

from core.proxy_stats import format_proxy_window_label, parse_proxy_window_spec
from kube.mirror_instance import parser_service_url
from ui.ui_common import UISettings
from ui.ui_instance import _load_instance_summaries


PROXY_STATS_TIMEOUT_SECONDS = 4.0


def _utcnow_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _empty_proxy_stats(window_seconds: float = 3600.0) -> dict[str, Any]:
    return {
        "totalCalls": 0,
        "successCalls": 0,
        "failureCalls": 0,
        "totalElapsedSeconds": 0.0,
        "averageResponseMs": None,
        "recentRequests": 0,
        "recentWindowSeconds": window_seconds,
        "windowSeconds": window_seconds,
        "windowLabel": format_proxy_window_label(window_seconds),
        "requestsPerSecond": 0.0,
        "requestsPerMinute": 0.0,
        "errorCounts": {},
        "healthyProxies": 0,
        "degradedProxies": 0,
        "brokenProxies": 0,
        "proxyCount": 0,
        "proxies": [],
    }


def _status_for_proxy(*, total_calls: int, success_calls: int, failure_calls: int) -> tuple[str, str, int]:
    if total_calls <= 0:
        return "Idle", "muted", 20
    if success_calls <= 0 and failure_calls > 0:
        return "Broken", "error", 40
    if success_calls > 0 and failure_calls > 0:
        return "Degraded", "warning", 30
    return "Healthy", "healthy", 10


def _sort_error_counts(error_counts: dict[str, int]) -> dict[str, int]:
    return {
        key: value
        for key, value in sorted(error_counts.items(), key=lambda item: (-int(item[1]), item[0]))
    }


def _stats_payload(item: dict[str, Any]) -> dict[str, Any]:
    stats = item.get("stats")
    if isinstance(stats, dict):
        return dict(stats)
    return dict(item)


def _normalize_stats(stats: dict[str, Any], window_seconds: float) -> dict[str, Any]:
    total_calls = int(stats.get("totalCalls") or stats.get("recentRequests") or 0)
    success_calls = int(stats.get("successCalls") or 0)
    failure_calls = int(stats.get("failureCalls") or 0)
    total_elapsed_seconds = float(stats.get("totalElapsedSeconds") or 0.0)
    average_response_ms = (
        float(stats["averageResponseMs"])
        if stats.get("averageResponseMs") is not None
        else None
    )
    requests_per_second = float(stats.get("requestsPerSecond") or 0.0)
    if not requests_per_second and window_seconds > 0:
        requests_per_second = total_calls / window_seconds
    requests_per_minute = float(stats.get("requestsPerMinute") or requests_per_second * 60.0)
    error_counts = _sort_error_counts({str(key): int(value) for key, value in dict(stats.get("errorCounts") or {}).items()})
    top_error = next(iter(error_counts.items()), (None, 0))
    return {
        "totalCalls": total_calls,
        "successCalls": success_calls,
        "failureCalls": failure_calls,
        "totalElapsedSeconds": total_elapsed_seconds,
        "averageResponseMs": average_response_ms,
        "recentRequests": total_calls,
        "recentWindowSeconds": window_seconds,
        "windowSeconds": window_seconds,
        "windowLabel": stats.get("windowLabel") or format_proxy_window_label(window_seconds),
        "requestsPerSecond": requests_per_second,
        "requestsPerMinute": requests_per_minute,
        "errorCounts": error_counts,
        "failureRate": (failure_calls / total_calls) if total_calls else 0.0,
        "topError": {
            "label": top_error[0] or "",
            "count": int(top_error[1] or 0),
        },
    }


def _normalize_source_entry(item: dict[str, Any], window_seconds: float) -> dict[str, Any]:
    stats = _normalize_stats(_stats_payload(item), window_seconds)
    pod_name = str(item.get("podName") or "").strip()
    instance_name = str(item.get("instanceName") or "").strip()
    proxy_count = int(item.get("proxyCount") or len(list(item.get("proxies") or [])))
    return {
        "instanceName": instance_name,
        "podName": pod_name,
        "reachable": bool(item.get("reachable")),
        "proxyConfigured": bool(item.get("proxyConfigured")),
        "proxyCount": proxy_count,
        "error": str(item.get("error") or ""),
        "windowSeconds": window_seconds,
        "windowLabel": str(item.get("windowLabel") or stats["windowLabel"]),
        "stats": stats,
        "proxies": list(item.get("proxies") or []),
        "generatedAt": str(item.get("generatedAt") or _utcnow_iso()),
    }


def _fetch_proxy_snapshot(
    settings: UISettings,
    summary: dict[str, Any],
    *,
    window_spec: str,
    window_seconds: float,
) -> dict[str, Any]:
    name = str(summary.get("name") or "")
    parser_info = dict(summary.get("parser") or {})
    pod_name = str(parser_info.get("podName") or "")
    url = parser_service_url(name, settings.namespace).rstrip("/") + "/api/v1/proxy-stats"
    try:
        response = requests.get(
            url,
            params={"window": window_spec},
            timeout=PROXY_STATS_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )
        payload = response.json()
        if not response.ok:
            raise RuntimeError(str(payload.get("error") or f"HTTP {response.status_code}"))
    except Exception as exc:
        return {
            "instanceName": name,
            "podName": pod_name,
            "reachable": False,
            "proxyConfigured": False,
            "proxyCount": 0,
            "windowSeconds": window_seconds,
            "windowLabel": window_spec,
            "stats": _empty_proxy_stats(window_seconds),
            "proxies": [],
            "error": str(exc),
            "generatedAt": _utcnow_iso(),
        }

    window_seconds = float(payload.get("windowSeconds") or 0.0)
    window_label = str(payload.get("windowLabel") or window_spec)
    stats = _normalize_stats(dict(payload.get("stats") or {}), window_seconds or 3600.0)
    proxy_items: list[dict[str, Any]] = []
    for proxy in list(payload.get("proxies") or []):
        proxy_stats = _normalize_stats(
            _stats_payload(dict(proxy or {})),
            window_seconds or stats["windowSeconds"],
        )
        proxy_key = str(proxy.get("proxyKey") or proxy.get("proxyLabel") or "").strip()
        proxy_label = str(proxy.get("proxyLabel") or proxy_key or "proxy").strip() or "proxy"
        proxy_items.append(
            {
                "proxyKey": proxy_key or proxy_label,
                "proxyLabel": proxy_label,
                "stats": proxy_stats,
            }
        )
    return {
        "instanceName": name,
        "podName": str(payload.get("podName") or pod_name or ""),
        "reachable": True,
        "proxyConfigured": bool(payload.get("proxyConfigured")),
        "proxyCount": int(payload.get("proxyCount") or len(proxy_items)),
        "windowSeconds": window_seconds or stats["windowSeconds"],
        "windowLabel": window_label,
        "stats": stats,
        "proxies": proxy_items,
        "error": "",
        "generatedAt": str(payload.get("generatedAt") or _utcnow_iso()),
    }


def _aggregate_proxy_stats(
    proxies: list[dict[str, Any]],
    *,
    source_total: int,
    source_responded: int,
    window_seconds: float,
) -> dict[str, Any]:
    total_calls = 0
    success_calls = 0
    failure_calls = 0
    total_elapsed_seconds = 0.0
    error_counts: Counter[str] = Counter()
    pods_with_success: set[str] = set()
    pods_with_traffic: set[str] = set()
    healthy_proxies = 0
    degraded_proxies = 0
    broken_proxies = 0

    for proxy in proxies:
        stats = dict(proxy.get("stats") or {})
        total_calls += int(stats.get("totalCalls") or 0)
        success_calls += int(stats.get("successCalls") or 0)
        failure_calls += int(stats.get("failureCalls") or 0)
        total_elapsed_seconds += float(stats.get("totalElapsedSeconds") or 0.0)
        error_counts.update(dict(stats.get("errorCounts") or {}))
        pods_with_success.update(set(proxy.get("podsWorking") or []))
        pods_with_traffic.update(set(proxy.get("podsSeen") or []))

        status = str(proxy.get("statusLabel") or "")
        if status == "Healthy":
            healthy_proxies += 1
        elif status == "Degraded":
            degraded_proxies += 1
        elif status == "Broken":
            broken_proxies += 1

    average_response_ms = (
        (total_elapsed_seconds / total_calls) * 1000.0 if total_calls else None
    )
    requests_per_second = total_calls / window_seconds if window_seconds else 0.0
    requests_per_minute = requests_per_second * 60.0
    failure_rate = (failure_calls / total_calls) if total_calls else 0.0
    error_breakdown = [
        {"label": label, "count": count}
        for label, count in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "proxyCount": len(proxies),
        "sourcePodsTotal": source_total,
        "sourcePodsResponded": source_responded,
        "sourcePodsMissing": max(0, source_total - source_responded),
        "podsWithSuccess": len(pods_with_success),
        "podsWithTraffic": len(pods_with_traffic),
        "totalCalls": total_calls,
        "successCalls": success_calls,
        "failureCalls": failure_calls,
        "failureRate": failure_rate,
        "averageResponseMs": average_response_ms,
        "recentRequests": total_calls,
        "recentWindowSeconds": window_seconds,
        "requestsPerSecond": requests_per_second,
        "requestsPerMinute": requests_per_minute,
        "errorCounts": dict(error_counts),
        "errorBreakdown": error_breakdown,
        "healthyProxies": healthy_proxies,
        "degradedProxies": degraded_proxies,
        "brokenProxies": broken_proxies,
    }


def _finalize_proxy_bucket(
    bucket: dict[str, Any],
    *,
    window_seconds: float,
) -> dict[str, Any]:
    stats = _normalize_stats(dict(bucket.get("stats") or {}), window_seconds)
    pods_seen = sorted(set(bucket.get("podsSeen") or []))
    pods_working = sorted(set(bucket.get("podsWorking") or []))
    status_label, status_tone, status_severity = _status_for_proxy(
        total_calls=int(stats.get("totalCalls") or 0),
        success_calls=int(stats.get("successCalls") or 0),
        failure_calls=int(stats.get("failureCalls") or 0),
    )
    return {
        "proxyKey": str(bucket.get("proxyKey") or ""),
        "proxyLabel": str(bucket.get("proxyLabel") or bucket.get("proxyKey") or ""),
        "statusLabel": status_label,
        "statusTone": status_tone,
        "statusSeverity": status_severity,
        "podsSeen": pods_seen,
        "podsWorking": pods_working,
        "podCount": len(pods_seen),
        "workingPodCount": len(pods_working),
        "sources": list(bucket.get("sources") or []),
        "stats": stats,
    }


def _merge_proxy_sources(items: list[dict[str, Any]], window_seconds: float) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for item in items:
        pod_name = str(item.get("podName") or "").strip()
        instance_name = str(item.get("instanceName") or "").strip()
        for proxy in list(item.get("proxies") or []):
            proxy_data = dict(proxy or {})
            stats = _normalize_stats(_stats_payload(proxy_data), window_seconds)
            proxy_key = str(proxy.get("proxyKey") or proxy.get("proxyLabel") or "").strip()
            if not proxy_key:
                continue
            proxy_label = str(proxy.get("proxyLabel") or proxy_key).strip() or proxy_key
            bucket = buckets.setdefault(
                proxy_key,
                {
                    "proxyKey": proxy_key,
                    "proxyLabel": proxy_label,
                    "stats": {
                        "totalCalls": 0,
                        "successCalls": 0,
                        "failureCalls": 0,
                        "totalElapsedSeconds": 0.0,
                        "errorCounts": Counter(),
                    },
                    "podsSeen": set(),
                    "podsWorking": set(),
                    "sources": [],
                },
            )
            bucket["proxyLabel"] = proxy_label
            bucket["stats"]["totalCalls"] += int(stats.get("totalCalls") or 0)
            bucket["stats"]["successCalls"] += int(stats.get("successCalls") or 0)
            bucket["stats"]["failureCalls"] += int(stats.get("failureCalls") or 0)
            bucket["stats"]["totalElapsedSeconds"] += float(stats.get("totalElapsedSeconds") or 0.0)
            bucket["stats"]["errorCounts"].update(dict(stats.get("errorCounts") or {}))
            if pod_name:
                bucket["podsSeen"].add(pod_name)
                if int(stats.get("successCalls") or 0) > 0:
                    bucket["podsWorking"].add(pod_name)
            bucket["sources"].append(
                {
                    "instanceName": instance_name,
                    "podName": pod_name,
                    "windowSeconds": window_seconds,
                    "windowLabel": str(item.get("windowLabel") or stats.get("windowLabel") or "1h"),
                    "stats": stats,
                }
            )

    proxies = []
    for bucket in buckets.values():
        proxies.append(
            {
                **_finalize_proxy_bucket(bucket, window_seconds=window_seconds),
            }
        )
    proxies.sort(
        key=lambda item: (
            -int(item.get("statusSeverity") or 20),
            -int((dict(item.get("stats") or {})).get("failureCalls") or 0),
            -int((dict(item.get("stats") or {})).get("totalCalls") or 0),
            str(item.get("proxyLabel") or "").lower(),
        )
    )
    return proxies


def _load_proxy_statistics(
    settings: UISettings,
    *,
    window_spec: str | None = None,
) -> dict[str, Any]:
    summaries = _load_instance_summaries(settings)
    selected_window_seconds, selected_window_label = parse_proxy_window_spec(window_spec)
    items: list[dict[str, Any]] = []
    if summaries:
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(summaries)))) as executor:
            futures = {
                executor.submit(
                    _fetch_proxy_snapshot,
                    settings,
                    summary,
                    window_spec=selected_window_label,
                    window_seconds=selected_window_seconds,
                ): summary
                for summary in summaries
            }
            for future in as_completed(futures):
                items.append(_normalize_source_entry(future.result(), selected_window_seconds))

    source_total = len(summaries)
    source_responded = sum(1 for item in items if bool(item.get("reachable")))
    proxies = _merge_proxy_sources(items, selected_window_seconds)
    summary = _aggregate_proxy_stats(
        proxies,
        source_total=source_total,
        source_responded=source_responded,
        window_seconds=selected_window_seconds,
    )
    return {
        "generatedAt": _utcnow_iso(),
        "window": {
            "spec": selected_window_label,
            "seconds": selected_window_seconds,
            "label": selected_window_label,
        },
        "summary": summary,
        "proxies": proxies,
        "errorBreakdown": summary["errorBreakdown"],
        "sources": {
            "total": source_total,
            "responded": source_responded,
            "missing": summary["sourcePodsMissing"],
        },
    }
