from __future__ import annotations

"""Proxy telemetry aggregation for the UI service."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import requests

from kube.mirror_instance import parser_service_url
from ui.ui_common import UISettings
from ui.ui_instance import _load_instance_summaries


PROXY_STATS_TIMEOUT_SECONDS = 4.0


def _utcnow_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _empty_proxy_stats() -> dict[str, Any]:
    return {
        "totalCalls": 0,
        "successCalls": 0,
        "failureCalls": 0,
        "totalElapsedSeconds": 0.0,
        "averageResponseMs": None,
        "recentRequests": 0,
        "recentWindowSeconds": 60.0,
        "requestsPerSecond": 0.0,
        "requestsPerMinute": 0.0,
        "errorCounts": {},
    }


def _proxy_status(
    *,
    reachable: bool,
    proxy_configured: bool,
    total_calls: int,
    success_calls: int,
    failure_calls: int,
) -> tuple[str, str]:
    if not reachable:
        return "Offline", "muted"
    if not proxy_configured:
        return "No proxy", "muted"
    if total_calls <= 0:
        return "Idle", "info"
    if success_calls > 0 and failure_calls > 0:
        return "Degraded", "warning"
    if success_calls > 0:
        return "Working", "healthy"
    return "Broken", "error"


def _fetch_proxy_snapshot(settings: UISettings, summary: dict[str, Any]) -> dict[str, Any]:
    name = str(summary.get("name") or "")
    parser_info = dict(summary.get("parser") or {})
    pod_name = str(parser_info.get("podName") or "")
    url = parser_service_url(name, settings.namespace).rstrip("/") + "/api/v1/proxy-stats"
    try:
        response = requests.get(
            url,
            timeout=PROXY_STATS_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )
        payload = response.json()
        if not response.ok:
            raise RuntimeError(str(payload.get("error") or f"HTTP {response.status_code}"))
    except Exception as exc:
        return {
            "name": name,
            "parserPod": pod_name,
            "health": str(summary.get("health") or ""),
            "healthTone": str(summary.get("healthTone") or "muted"),
            "enabled": bool(summary.get("enabled")),
            "reachable": False,
            "proxyConfigured": False,
            "proxyPoolSize": 0,
            "proxyScope": "",
            "error": str(exc),
            "stats": _empty_proxy_stats(),
            "urls": dict(summary.get("urls") or {}),
        }

    stats = dict(payload.get("stats") or {})
    total_calls = int(stats.get("totalCalls") or 0)
    success_calls = int(stats.get("successCalls") or 0)
    failure_calls = int(stats.get("failureCalls") or 0)
    total_elapsed_seconds = float(stats.get("totalElapsedSeconds") or 0.0)
    recent_requests = int(stats.get("recentRequests") or 0)
    recent_window_seconds = float(stats.get("recentWindowSeconds") or 60.0) or 60.0
    requests_per_second = recent_requests / recent_window_seconds
    requests_per_minute = requests_per_second * 60.0
    proxy_configured = bool(payload.get("proxyConfigured"))
    status_label, status_tone = _proxy_status(
        reachable=True,
        proxy_configured=proxy_configured,
        total_calls=total_calls,
        success_calls=success_calls,
        failure_calls=failure_calls,
    )
    error_counts = dict(stats.get("errorCounts") or {})
    sorted_errors = {
        key: value
        for key, value in sorted(
            error_counts.items(),
            key=lambda item: (-int(item[1]), item[0]),
        )
    }
    top_error = next(iter(sorted_errors.items()), (None, 0))
    average_response_ms = (
        float(stats["averageResponseMs"])
        if stats.get("averageResponseMs") is not None
        else None
    )
    return {
        "name": name,
        "parserPod": str(payload.get("podName") or pod_name or ""),
        "health": str(summary.get("health") or ""),
        "healthTone": str(summary.get("healthTone") or "muted"),
        "enabled": bool(summary.get("enabled")),
        "reachable": True,
        "proxyConfigured": proxy_configured,
        "proxyPoolSize": int(payload.get("proxyPoolSize") or 0),
        "proxyScope": str(payload.get("proxyScope") or ""),
        "statusLabel": status_label,
        "statusTone": status_tone,
        "statusSeverity": {
            "Offline": 50,
            "Broken": 40,
            "Degraded": 30,
            "Idle": 20,
            "No proxy": 10,
            "Working": 0,
        }.get(status_label, 20),
        "stats": {
            "totalCalls": total_calls,
            "successCalls": success_calls,
            "failureCalls": failure_calls,
            "totalElapsedSeconds": total_elapsed_seconds,
            "averageResponseMs": average_response_ms,
            "recentRequests": recent_requests,
            "recentWindowSeconds": recent_window_seconds,
            "requestsPerSecond": requests_per_second,
            "requestsPerMinute": requests_per_minute,
            "errorCounts": sorted_errors,
            "topError": {
                "label": top_error[0],
                "count": int(top_error[1] or 0),
            }
            if top_error[0]
            else {"label": "", "count": 0},
        },
        "urls": dict(summary.get("urls") or {}),
        "error": "",
        "generatedAt": str(payload.get("generatedAt") or _utcnow_iso()),
    }


def _aggregate_proxy_stats(items: list[dict[str, Any]]) -> dict[str, Any]:
    total_pods = len(items)
    configured_pods = 0
    working_pods = 0
    reachable_pods = 0
    total_calls = 0
    success_calls = 0
    failure_calls = 0
    total_elapsed_seconds = 0.0
    recent_requests = 0
    recent_window_seconds = 60.0
    error_counts: Counter[str] = Counter()

    for item in items:
        stats = dict(item.get("stats") or {})
        if bool(item.get("reachable")):
            reachable_pods += 1
        if bool(item.get("proxyConfigured")):
            configured_pods += 1
        status_label = str(item.get("statusLabel") or "")
        if status_label in {"Working", "Degraded"}:
            working_pods += 1
        total_calls += int(stats.get("totalCalls") or 0)
        success_calls += int(stats.get("successCalls") or 0)
        failure_calls += int(stats.get("failureCalls") or 0)
        total_elapsed_seconds += float(stats.get("totalElapsedSeconds") or 0.0)
        recent_requests += int(stats.get("recentRequests") or 0)
        recent_window_seconds = float(stats.get("recentWindowSeconds") or recent_window_seconds)
        error_counts.update(dict(stats.get("errorCounts") or {}))

    average_response_ms = (
        (total_elapsed_seconds / total_calls) * 1000.0 if total_calls else None
    )
    requests_per_second = recent_requests / recent_window_seconds if recent_window_seconds else 0.0
    requests_per_minute = requests_per_second * 60.0
    error_breakdown = [
        {"label": label, "count": count}
        for label, count in sorted(
            error_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    return {
        "podsTotal": total_pods,
        "podsReachable": reachable_pods,
        "podsConfigured": configured_pods,
        "podsWorking": working_pods,
        "totalCalls": total_calls,
        "successCalls": success_calls,
        "failureCalls": failure_calls,
        "averageResponseMs": average_response_ms,
        "recentRequests": recent_requests,
        "recentWindowSeconds": recent_window_seconds,
        "requestsPerSecond": requests_per_second,
        "requestsPerMinute": requests_per_minute,
        "errorCounts": dict(error_counts),
        "errorBreakdown": error_breakdown,
    }


def _load_proxy_statistics(settings: UISettings) -> dict[str, Any]:
    summaries = _load_instance_summaries(settings)
    if not summaries:
        return {
            "generatedAt": _utcnow_iso(),
            "summary": _aggregate_proxy_stats([]),
            "pods": [],
            "errorBreakdown": [],
        }

    items: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(summaries)))) as executor:
        futures = {
            executor.submit(_fetch_proxy_snapshot, settings, summary): summary
            for summary in summaries
        }
        for future in as_completed(futures):
            items.append(future.result())

    items.sort(
        key=lambda item: (
            -int(item.get("statusSeverity") or 20),
            str(item.get("name") or "").lower(),
        )
    )
    summary = _aggregate_proxy_stats(items)
    return {
        "generatedAt": _utcnow_iso(),
        "summary": summary,
        "pods": items,
        "errorBreakdown": summary["errorBreakdown"],
    }
