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


def _empty_proxy_detail(window_seconds: float = 3600.0, bucket_count: int = 24) -> dict[str, Any]:
    bucket_count = max(1, int(bucket_count))
    bucket_size_seconds = window_seconds / bucket_count if bucket_count else window_seconds
    buckets = [
        {
            "index": index,
            "label": f"Bucket {index + 1:02d}",
            "rangeLabel": f"{format_proxy_window_label(max(0.0, window_seconds - (index * bucket_size_seconds)))} ago to {format_proxy_window_label(max(0.0, window_seconds - ((index + 1) * bucket_size_seconds)))} ago",
            "startSecondsAgo": max(0.0, window_seconds - (index * bucket_size_seconds)),
            "endSecondsAgo": max(0.0, window_seconds - ((index + 1) * bucket_size_seconds)),
            "totalCalls": 0,
            "successCalls": 0,
            "failureCalls": 0,
            "totalElapsedSeconds": 0.0,
            "averageResponseMs": None,
            "failureRate": 0.0,
            "errorCounts": {},
            "topError": {"label": "", "count": 0},
        }
        for index in range(bucket_count)
    ]
    return {
        "proxyKey": "",
        "proxyLabel": "",
        "found": False,
        "bucketCount": bucket_count,
        "bucketSizeSeconds": bucket_size_seconds,
        "buckets": buckets,
        "recentFailures": [],
        "stats": {
            "proxyKey": "",
            "proxyLabel": "",
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
        },
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


def _normalize_detail_bucket(bucket: dict[str, Any], window_seconds: float) -> dict[str, Any]:
    stats = _normalize_stats(_stats_payload(bucket), window_seconds)
    return {
        "index": int(bucket.get("index") or 0),
        "label": str(bucket.get("label") or f"Bucket {int(bucket.get('index') or 0) + 1:02d}"),
        "rangeLabel": str(bucket.get("rangeLabel") or ""),
        "startSecondsAgo": float(bucket.get("startSecondsAgo") or 0.0),
        "endSecondsAgo": float(bucket.get("endSecondsAgo") or 0.0),
        "totalCalls": int(stats.get("totalCalls") or 0),
        "successCalls": int(stats.get("successCalls") or 0),
        "failureCalls": int(stats.get("failureCalls") or 0),
        "totalElapsedSeconds": float(stats.get("totalElapsedSeconds") or 0.0),
        "averageResponseMs": stats.get("averageResponseMs"),
        "failureRate": float(stats.get("failureRate") or 0.0),
        "errorCounts": dict(stats.get("errorCounts") or {}),
        "topError": dict(stats.get("topError") or {"label": "", "count": 0}),
    }


def _normalize_recent_failure(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "ageSeconds": float(item.get("ageSeconds") or 0.0),
        "elapsedSeconds": float(item.get("elapsedSeconds") or 0.0),
        "errorType": str(item.get("errorType") or "UnknownError"),
        "bucketIndex": int(item.get("bucketIndex") or 0),
        "instanceName": str(item.get("instanceName") or ""),
        "podName": str(item.get("podName") or ""),
    }


def _normalize_detail_entry(item: dict[str, Any], window_seconds: float) -> dict[str, Any]:
    stats = _normalize_stats(_stats_payload(item), window_seconds)
    buckets = [
        _normalize_detail_bucket(bucket, window_seconds)
        for bucket in list(item.get("buckets") or [])
    ]
    bucket_count = int(item.get("bucketCount") or len(buckets) or 24)
    if not buckets and bucket_count > 0:
        buckets = _empty_proxy_detail(window_seconds, bucket_count)["buckets"]
    return {
        "instanceName": str(item.get("instanceName") or ""),
        "podName": str(item.get("podName") or ""),
        "reachable": bool(item.get("reachable", True)),
        "proxyConfigured": bool(item.get("proxyConfigured")),
        "windowSeconds": window_seconds,
        "windowLabel": str(item.get("windowLabel") or stats["windowLabel"]),
        "proxyKey": str(item.get("proxyKey") or stats.get("proxyKey") or ""),
        "proxyLabel": str(item.get("proxyLabel") or stats.get("proxyLabel") or ""),
        "found": bool(item.get("found")),
        "bucketCount": bucket_count,
        "bucketSizeSeconds": float(item.get("bucketSizeSeconds") or (window_seconds / max(1, bucket_count))),
        "stats": stats,
        "buckets": buckets,
        "recentFailures": [
            _normalize_recent_failure(failure)
            for failure in list(item.get("recentFailures") or [])
        ],
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


def _fetch_proxy_detail_snapshot(
    settings: UISettings,
    summary: dict[str, Any],
    *,
    proxy_key: str,
    window_spec: str,
    window_seconds: float,
) -> dict[str, Any]:
    name = str(summary.get("name") or "")
    parser_info = dict(summary.get("parser") or {})
    pod_name = str(parser_info.get("podName") or "")
    url = parser_service_url(name, settings.namespace).rstrip("/") + "/api/v1/proxy-stats/detail"
    try:
        response = requests.get(
            url,
            params={"proxy": proxy_key, "window": window_spec},
            timeout=PROXY_STATS_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )
        payload = response.json()
        if not response.ok:
            raise RuntimeError(str(payload.get("error") or f"HTTP {response.status_code}"))
    except Exception as exc:
        empty = _empty_proxy_detail(window_seconds)
        empty.update(
            {
                "instanceName": name,
                "podName": pod_name,
                "reachable": False,
                "proxyConfigured": False,
                "windowSeconds": window_seconds,
                "windowLabel": window_spec,
                "error": str(exc),
                "generatedAt": _utcnow_iso(),
            }
        )
        return empty

    detail = _normalize_detail_entry(dict(payload or {}), window_seconds)
    detail.update(
        {
            "instanceName": name,
            "podName": str(payload.get("podName") or pod_name or ""),
            "reachable": True,
            "proxyConfigured": bool(payload.get("proxyConfigured")),
            "windowSeconds": float(payload.get("windowSeconds") or window_seconds),
            "windowLabel": str(payload.get("windowLabel") or window_spec),
            "error": "",
            "generatedAt": str(payload.get("generatedAt") or _utcnow_iso()),
        }
    )
    if not detail.get("proxyKey"):
        detail["proxyKey"] = proxy_key
    if not detail.get("proxyLabel"):
        detail["proxyLabel"] = proxy_key
    return detail


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


def _merge_proxy_detail_sources(
    items: list[dict[str, Any]],
    *,
    proxy_key: str,
    window_seconds: float,
) -> dict[str, Any]:
    bucket_count = 24
    merged = _empty_proxy_detail(window_seconds, bucket_count)
    merged["proxyKey"] = proxy_key
    merged["proxyLabel"] = proxy_key

    buckets = merged["buckets"]
    recent_failures: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    pods_seen: set[str] = set()
    pods_working: set[str] = set()
    source_total = len(items)
    source_responded = 0
    total_calls = 0
    success_calls = 0
    failure_calls = 0
    total_elapsed_seconds = 0.0
    error_counts: Counter[str] = Counter()
    max_bucket_count = bucket_count
    bucket_size_seconds = window_seconds / bucket_count if bucket_count else window_seconds

    for item in items:
        detail = _normalize_detail_entry(dict(item or {}), window_seconds)
        if detail.get("bucketCount"):
            max_bucket_count = max(max_bucket_count, int(detail.get("bucketCount") or bucket_count))
        if not detail.get("found"):
            continue
        source_responded += 1
        pod_name = str(detail.get("podName") or "").strip()
        instance_name = str(detail.get("instanceName") or "").strip()
        stats = dict(detail.get("stats") or {})
        total_calls += int(stats.get("totalCalls") or 0)
        success_calls += int(stats.get("successCalls") or 0)
        failure_calls += int(stats.get("failureCalls") or 0)
        total_elapsed_seconds += float(stats.get("totalElapsedSeconds") or 0.0)
        error_counts.update(dict(stats.get("errorCounts") or {}))
        if pod_name:
            pods_seen.add(pod_name)
            if int(stats.get("successCalls") or 0) > 0:
                pods_working.add(pod_name)
        sources.append(
            {
                "instanceName": instance_name,
                "podName": pod_name,
                "windowSeconds": window_seconds,
                "windowLabel": str(detail.get("windowLabel") or format_proxy_window_label(window_seconds)),
                "stats": stats,
            }
        )

        for bucket in list(detail.get("buckets") or []):
            index = int(bucket.get("index") or 0)
            if index < 0:
                continue
            while index >= len(buckets):
                buckets.append(
                    {
                        "index": len(buckets),
                        "label": f"Bucket {len(buckets) + 1:02d}",
                        "rangeLabel": f"{format_proxy_window_label(max(0.0, window_seconds - (len(buckets) * bucket_size_seconds)))} ago to {format_proxy_window_label(max(0.0, window_seconds - ((len(buckets) + 1) * bucket_size_seconds)))} ago",
                        "startSecondsAgo": max(0.0, window_seconds - (len(buckets) * bucket_size_seconds)),
                        "endSecondsAgo": max(0.0, window_seconds - ((len(buckets) + 1) * bucket_size_seconds)),
                        "totalCalls": 0,
                        "successCalls": 0,
                        "failureCalls": 0,
                        "totalElapsedSeconds": 0.0,
                        "averageResponseMs": None,
                        "failureRate": 0.0,
                        "errorCounts": {},
                        "topError": {"label": "", "count": 0},
                    }
                )
            merged_bucket = buckets[index]
            merged_bucket["totalCalls"] += int(bucket.get("totalCalls") or 0)
            merged_bucket["successCalls"] += int(bucket.get("successCalls") or 0)
            merged_bucket["failureCalls"] += int(bucket.get("failureCalls") or 0)
            merged_bucket["totalElapsedSeconds"] += float(bucket.get("totalElapsedSeconds") or 0.0)
            merged_errors = Counter(dict(merged_bucket.get("errorCounts") or {}))
            merged_errors.update(dict(bucket.get("errorCounts") or {}))
            merged_bucket["errorCounts"] = dict(merged_errors)

        for failure in list(detail.get("recentFailures") or []):
            recent_failures.append(
                {
                    **_normalize_recent_failure(failure),
                    "instanceName": instance_name,
                    "podName": pod_name,
                }
            )

    normalized_buckets = []
    for index, bucket in enumerate(buckets[:max_bucket_count]):
        total = int(bucket.get("totalCalls") or 0)
        failures = int(bucket.get("failureCalls") or 0)
        error_counts_bucket = _sort_error_counts({str(key): int(value) for key, value in dict(bucket.get("errorCounts") or {}).items()})
        top_error = next(iter(error_counts_bucket.items()), (None, 0))
        normalized_buckets.append(
            {
                "index": index,
                "label": str(bucket.get("label") or f"Bucket {index + 1:02d}"),
                "rangeLabel": str(bucket.get("rangeLabel") or ""),
                "startSecondsAgo": float(bucket.get("startSecondsAgo") or 0.0),
                "endSecondsAgo": float(bucket.get("endSecondsAgo") or 0.0),
                "totalCalls": total,
                "successCalls": int(bucket.get("successCalls") or 0),
                "failureCalls": failures,
                "totalElapsedSeconds": float(bucket.get("totalElapsedSeconds") or 0.0),
                "averageResponseMs": (
                    (float(bucket.get("totalElapsedSeconds") or 0.0) / total) * 1000.0 if total else None
                ),
                "failureRate": (failures / total) if total else 0.0,
                "errorCounts": error_counts_bucket,
                "topError": {
                    "label": top_error[0] or "",
                    "count": int(top_error[1] or 0),
                },
            }
        )

    recent_failures.sort(key=lambda item: float(item.get("ageSeconds") or 0.0))
    recent_failures = recent_failures[:12]
    summary = {
        "proxyCount": 1 if (total_calls > 0 or source_responded > 0) else 0,
        "sourcePodsTotal": source_total,
        "sourcePodsResponded": source_responded,
        "sourcePodsMissing": max(0, source_total - source_responded),
        "podsWithSuccess": len(pods_working),
        "podsWithTraffic": len(pods_seen),
        "totalCalls": total_calls,
        "successCalls": success_calls,
        "failureCalls": failure_calls,
        "failureRate": (failure_calls / total_calls) if total_calls else 0.0,
        "averageResponseMs": (total_elapsed_seconds / total_calls) * 1000.0 if total_calls else None,
        "recentRequests": total_calls,
        "recentWindowSeconds": window_seconds,
        "requestsPerSecond": total_calls / window_seconds if window_seconds else 0.0,
        "requestsPerMinute": (total_calls / window_seconds * 60.0) if window_seconds else 0.0,
        "errorCounts": dict(error_counts),
        "errorBreakdown": [
            {"label": label, "count": count}
            for label, count in sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        "topError": {
            "label": "",
            "count": 0,
        },
        "healthyProxies": 1 if total_calls > 0 and failure_calls == 0 else 0,
        "degradedProxies": 1 if total_calls > 0 and 0 < failure_calls < total_calls else 0,
        "brokenProxies": 1 if total_calls > 0 and success_calls == 0 and failure_calls > 0 else 0,
    }
    if summary["errorBreakdown"]:
        summary["topError"] = {
            "label": summary["errorBreakdown"][0]["label"],
            "count": summary["errorBreakdown"][0]["count"],
        }
    merged["found"] = bool(source_responded > 0)
    merged["bucketCount"] = len(normalized_buckets)
    merged["bucketSizeSeconds"] = bucket_size_seconds
    merged["buckets"] = normalized_buckets
    merged["recentFailures"] = recent_failures
    merged["podsSeen"] = sorted(pods_seen)
    merged["podsWorking"] = sorted(pods_working)
    merged["stats"] = {
        "proxyKey": proxy_key,
        "proxyLabel": proxy_key,
        "totalCalls": total_calls,
        "successCalls": success_calls,
        "failureCalls": failure_calls,
        "totalElapsedSeconds": total_elapsed_seconds,
        "averageResponseMs": summary["averageResponseMs"],
        "recentRequests": total_calls,
        "recentWindowSeconds": window_seconds,
        "windowSeconds": window_seconds,
        "windowLabel": format_proxy_window_label(window_seconds),
        "requestsPerSecond": summary["requestsPerSecond"],
        "requestsPerMinute": summary["requestsPerMinute"],
        "errorCounts": _sort_error_counts(dict(error_counts)),
        "failureRate": summary["failureRate"],
        "topError": {
            "label": summary["errorBreakdown"][0]["label"] if summary["errorBreakdown"] else "",
            "count": summary["errorBreakdown"][0]["count"] if summary["errorBreakdown"] else 0,
        },
    }
    merged["sources"] = sources
    merged["summary"] = summary
    return merged


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


def _load_proxy_detail(
    settings: UISettings,
    *,
    proxy_key: str,
    window_spec: str | None = None,
) -> dict[str, Any]:
    summaries = _load_instance_summaries(settings)
    selected_window_seconds, selected_window_label = parse_proxy_window_spec(window_spec)
    items: list[dict[str, Any]] = []
    if summaries:
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(summaries)))) as executor:
            futures = {
                executor.submit(
                    _fetch_proxy_detail_snapshot,
                    settings,
                    summary,
                    proxy_key=proxy_key,
                    window_spec=selected_window_label,
                    window_seconds=selected_window_seconds,
                ): summary
                for summary in summaries
            }
            for future in as_completed(futures):
                items.append(_normalize_detail_entry(future.result(), selected_window_seconds))

    source_total = len(summaries)
    source_responded = sum(1 for item in items if bool(item.get("reachable")))
    merged = _merge_proxy_detail_sources(
        items,
        proxy_key=proxy_key,
        window_seconds=selected_window_seconds,
    )
    merged_summary = dict(merged.get("summary") or {})
    return {
        "generatedAt": _utcnow_iso(),
        "window": {
            "spec": selected_window_label,
            "seconds": selected_window_seconds,
            "label": selected_window_label,
        },
        "proxy": {
            "key": proxy_key,
            "label": str(merged.get("proxyLabel") or proxy_key),
        },
        "summary": merged_summary,
        "buckets": list(merged.get("buckets") or []),
        "recentFailures": list(merged.get("recentFailures") or []),
        "sources": {
            "total": source_total,
            "responded": source_responded,
            "missing": max(0, source_total - source_responded),
        },
        "podsSeen": list(merged.get("podsSeen") or []),
        "podsWorking": list(merged.get("podsWorking") or []),
        "sourceEntries": list(merged.get("sources") or []),
        "found": bool(merged.get("found")),
    }
