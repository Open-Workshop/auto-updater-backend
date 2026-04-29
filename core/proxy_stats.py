"""In-process proxy telemetry for Steam clients."""

from __future__ import annotations

import re
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from core.http_utils import is_dns_error, parse_proxy_url

DEFAULT_PROXY_WINDOW_SPEC = "1h"
DEFAULT_PROXY_WINDOW_SECONDS = 3600.0
DEFAULT_PROXY_RETENTION_SECONDS = 24 * 60 * 60.0
PROXY_WINDOW_PRESETS: tuple[tuple[str, float], ...] = (
    ("15m", 15 * 60.0),
    ("1h", 60 * 60.0),
    ("6h", 6 * 60 * 60.0),
    ("24h", 24 * 60 * 60.0),
)
_PRESET_WINDOWS = {spec: seconds for spec, seconds in PROXY_WINDOW_PRESETS}
_WINDOW_UNITS = {
    "s": 1.0,
    "m": 60.0,
    "h": 60.0 * 60.0,
    "d": 24.0 * 60.0 * 60.0,
}


def proxy_error_type(
    exc: Exception | None = None,
    *,
    status_code: int | None = None,
) -> str | None:
    """Normalize proxy failures into dashboard-friendly buckets."""
    if status_code is not None and status_code >= 400:
        return f"HTTP_{status_code}"
    if exc is None:
        return None
    if is_dns_error(exc):
        return "DNSError"
    return type(exc).__name__


def format_proxy_window_label(seconds: float) -> str:
    """Render a compact label for a time window."""
    value = max(1.0, float(seconds))
    for unit, scale in (("h", _WINDOW_UNITS["h"]), ("d", _WINDOW_UNITS["d"]), ("m", _WINDOW_UNITS["m"])):
        if value % scale == 0:
            return f"{int(value / scale)}{unit}"
    if value.is_integer():
        return f"{int(value)}s"
    return f"{value:.1f}s"


def parse_proxy_window_spec(
    value: str | None,
    *,
    default: str = DEFAULT_PROXY_WINDOW_SPEC,
) -> tuple[float, str]:
    """Parse a compact window spec like `15m` or `1h`."""
    raw = str(value or "").strip().lower()
    if not raw:
        raw = default
    if raw in _PRESET_WINDOWS:
        seconds = _PRESET_WINDOWS[raw]
        return seconds, raw
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", raw)
    if match:
        amount = float(match.group(1))
        unit = match.group(2) or "s"
        seconds = max(1.0, amount * _WINDOW_UNITS[unit])
        return seconds, format_proxy_window_label(seconds)
    fallback_seconds = _PRESET_WINDOWS.get(default, DEFAULT_PROXY_WINDOW_SECONDS)
    return fallback_seconds, default if default in _PRESET_WINDOWS else format_proxy_window_label(fallback_seconds)


def normalize_proxy_endpoint(proxy: str | None) -> str | None:
    """Return a safe endpoint identity without credentials."""
    raw = str(proxy or "").strip()
    if not raw:
        return None
    try:
        parsed = parse_proxy_url(raw)
    except ValueError:
        return None
    return f"{parsed.scheme}://{parsed.host.lower()}:{parsed.port}"


def _sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return {
        key: value
        for key, value in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    }


def _snapshot_stats(
    *,
    proxy_key: str,
    proxy_label: str,
    total_calls: int,
    success_calls: int,
    failure_calls: int,
    total_elapsed_seconds: float,
    error_counts: Counter[str],
    window_seconds: float,
) -> dict[str, Any]:
    average_response_ms = (
        (total_elapsed_seconds / total_calls) * 1000.0 if total_calls else None
    )
    requests_per_second = total_calls / window_seconds if window_seconds else 0.0
    requests_per_minute = requests_per_second * 60.0
    return {
        "proxyKey": proxy_key,
        "proxyLabel": proxy_label,
        "totalCalls": total_calls,
        "successCalls": success_calls,
        "failureCalls": failure_calls,
        "totalElapsedSeconds": total_elapsed_seconds,
        "averageResponseMs": average_response_ms,
        "recentRequests": total_calls,
        "recentWindowSeconds": window_seconds,
        "windowSeconds": window_seconds,
        "windowLabel": format_proxy_window_label(window_seconds),
        "requestsPerSecond": requests_per_second,
        "requestsPerMinute": requests_per_minute,
        "errorCounts": _sorted_counter(error_counts),
    }


def _empty_detail_bucket(
    *,
    index: int,
    bucket_count: int,
    bucket_size_seconds: float,
    window_seconds: float,
) -> dict[str, Any]:
    start_seconds_ago = max(0.0, window_seconds - (index * bucket_size_seconds))
    end_seconds_ago = max(0.0, window_seconds - ((index + 1) * bucket_size_seconds))
    return {
        "index": index,
        "label": f"Bucket {index + 1:02d}",
        "rangeLabel": f"{format_proxy_window_label(start_seconds_ago)} ago to {format_proxy_window_label(end_seconds_ago)} ago",
        "startSecondsAgo": start_seconds_ago,
        "endSecondsAgo": end_seconds_ago,
        "totalCalls": 0,
        "successCalls": 0,
        "failureCalls": 0,
        "totalElapsedSeconds": 0.0,
        "averageResponseMs": None,
        "failureRate": 0.0,
        "errorCounts": {},
        "topError": {"label": "", "count": 0},
    }


@dataclass(slots=True)
class ProxyEvent:
    timestamp: float
    success: bool
    elapsed_seconds: float
    error_type: str | None = None


@dataclass
class ProxySeries:
    proxy_key: str
    proxy_label: str
    events: deque[ProxyEvent] = field(default_factory=deque)

    def prune(self, cutoff: float) -> None:
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def snapshot(self, *, window_seconds: float, cutoff: float) -> dict[str, Any]:
        total_calls = 0
        success_calls = 0
        failure_calls = 0
        total_elapsed_seconds = 0.0
        error_counts: Counter[str] = Counter()
        for event in self.events:
            if event.timestamp < cutoff:
                continue
            total_calls += 1
            if event.success:
                success_calls += 1
            else:
                failure_calls += 1
                error_counts[event.error_type or "UnknownError"] += 1
            total_elapsed_seconds += event.elapsed_seconds
        return _snapshot_stats(
            proxy_key=self.proxy_key,
            proxy_label=self.proxy_label,
            total_calls=total_calls,
            success_calls=success_calls,
            failure_calls=failure_calls,
            total_elapsed_seconds=total_elapsed_seconds,
            error_counts=error_counts,
            window_seconds=window_seconds,
        )

    def snapshot_detail(
        self,
        *,
        window_seconds: float,
        cutoff: float,
        bucket_count: int = 24,
        now: float | None = None,
    ) -> dict[str, Any]:
        bucket_count = max(1, int(bucket_count))
        current_now = cutoff + window_seconds if now is None else float(now)
        bucket_size_seconds = window_seconds / bucket_count if bucket_count else window_seconds
        buckets = [
            _empty_detail_bucket(
                index=index,
                bucket_count=bucket_count,
                bucket_size_seconds=bucket_size_seconds,
                window_seconds=window_seconds,
            )
            for index in range(bucket_count)
        ]
        recent_failures: list[dict[str, Any]] = []
        total_calls = 0
        success_calls = 0
        failure_calls = 0
        total_elapsed_seconds = 0.0
        error_counts: Counter[str] = Counter()

        for event in self.events:
            if event.timestamp < cutoff:
                continue
            total_calls += 1
            bucket_index = 0
            if bucket_size_seconds > 0:
                bucket_index = int((event.timestamp - cutoff) / bucket_size_seconds)
            bucket_index = max(0, min(bucket_count - 1, bucket_index))
            bucket = buckets[bucket_index]
            bucket["totalCalls"] += 1
            bucket["totalElapsedSeconds"] += event.elapsed_seconds
            if event.success:
                success_calls += 1
                bucket["successCalls"] += 1
            else:
                failure_calls += 1
                bucket["failureCalls"] += 1
                bucket_error = str(event.error_type or "UnknownError")
                bucket["errorCounts"][bucket_error] = int(bucket["errorCounts"].get(bucket_error) or 0) + 1
                error_counts[bucket_error] += 1
                recent_failures.append(
                    {
                        "ageSeconds": max(0.0, current_now - event.timestamp),
                        "elapsedSeconds": event.elapsed_seconds,
                        "errorType": bucket_error,
                        "bucketIndex": bucket_index,
                    }
                )
            total_elapsed_seconds += event.elapsed_seconds

        for bucket in buckets:
            total = int(bucket["totalCalls"] or 0)
            failures = int(bucket["failureCalls"] or 0)
            bucket["averageResponseMs"] = (
                (float(bucket["totalElapsedSeconds"]) / total) * 1000.0 if total else None
            )
            bucket["failureRate"] = (failures / total) if total else 0.0
            bucket["errorCounts"] = _sorted_counter(
                Counter({str(key): int(value) for key, value in dict(bucket["errorCounts"]).items()})
            )
            top_error = next(iter(bucket["errorCounts"].items()), (None, 0))
            bucket["topError"] = {
                "label": top_error[0] or "",
                "count": int(top_error[1] or 0),
            }

        recent_failures.sort(key=lambda item: float(item.get("ageSeconds") or 0.0))
        return {
            "proxyKey": self.proxy_key,
            "proxyLabel": self.proxy_label,
            "found": True,
            "bucketCount": bucket_count,
            "bucketSizeSeconds": bucket_size_seconds,
            "buckets": buckets,
            "recentFailures": recent_failures,
            "stats": _snapshot_stats(
                proxy_key=self.proxy_key,
                proxy_label=self.proxy_label,
                total_calls=total_calls,
                success_calls=success_calls,
                failure_calls=failure_calls,
                total_elapsed_seconds=total_elapsed_seconds,
                error_counts=error_counts,
                window_seconds=window_seconds,
            ),
        }


class ProxyStatsCollector:
    """Thread-safe aggregate of proxied request outcomes."""

    def __init__(
        self,
        recent_window_seconds: float = DEFAULT_PROXY_WINDOW_SECONDS,
        retention_seconds: float = DEFAULT_PROXY_RETENTION_SECONDS,
    ) -> None:
        self.default_window_seconds = max(1.0, float(recent_window_seconds))
        self.retention_seconds = max(self.default_window_seconds, float(retention_seconds))
        self._lock = Lock()
        self._series: dict[str, ProxySeries] = {}

    def record(
        self,
        *,
        proxy: str | None,
        success: bool,
        elapsed_seconds: float,
        error_type: str | None = None,
        now: float | None = None,
    ) -> None:
        """Record a proxied request attempt."""
        proxy_key = normalize_proxy_endpoint(proxy)
        if not proxy_key:
            return
        current_now = time.monotonic() if now is None else float(now)
        duration = max(0.0, float(elapsed_seconds))
        event = ProxyEvent(
            timestamp=current_now,
            success=bool(success),
            elapsed_seconds=duration,
            error_type=str(error_type) if error_type else None,
        )
        retention_cutoff = current_now - self.retention_seconds
        with self._lock:
            series = self._series.get(proxy_key)
            if series is None:
                series = ProxySeries(proxy_key=proxy_key, proxy_label=proxy_key)
                self._series[proxy_key] = series
            series.events.append(event)
            series.prune(retention_cutoff)

    def reset(self) -> None:
        """Clear all collected stats."""
        with self._lock:
            self._series.clear()

    def snapshot(
        self,
        *,
        window_seconds: float | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Return a serialisable snapshot of the collected stats."""
        current_now = time.monotonic() if now is None else float(now)
        requested_window = (
            self.default_window_seconds if window_seconds is None else float(window_seconds)
        )
        selected_window = max(1.0, min(requested_window, self.retention_seconds))
        cutoff = current_now - selected_window

        proxies: list[dict[str, Any]] = []
        total_calls = 0
        success_calls = 0
        failure_calls = 0
        total_elapsed_seconds = 0.0
        error_counts: Counter[str] = Counter()

        with self._lock:
            empty_keys: list[str] = []
            for proxy_key, series in self._series.items():
                series.prune(current_now - self.retention_seconds)
                if not series.events:
                    empty_keys.append(proxy_key)
                    continue
                stats = series.snapshot(window_seconds=selected_window, cutoff=cutoff)
                if int(stats.get("totalCalls") or 0) <= 0:
                    continue
                proxies.append(stats)
                total_calls += int(stats.get("totalCalls") or 0)
                success_calls += int(stats.get("successCalls") or 0)
                failure_calls += int(stats.get("failureCalls") or 0)
                total_elapsed_seconds += float(stats.get("totalElapsedSeconds") or 0.0)
                error_counts.update(dict(stats.get("errorCounts") or {}))
            for proxy_key in empty_keys:
                self._series.pop(proxy_key, None)

        proxies.sort(key=lambda item: (-int(item.get("totalCalls") or 0), str(item.get("proxyLabel") or "")))
        average_response_ms = (
            (total_elapsed_seconds / total_calls) * 1000.0 if total_calls else None
        )
        requests_per_second = total_calls / selected_window if selected_window else 0.0
        requests_per_minute = requests_per_second * 60.0
        return {
            "windowSeconds": selected_window,
            "windowLabel": format_proxy_window_label(selected_window),
            "totalCalls": total_calls,
            "successCalls": success_calls,
            "failureCalls": failure_calls,
            "totalElapsedSeconds": total_elapsed_seconds,
            "averageResponseMs": average_response_ms,
            "recentRequests": total_calls,
            "recentWindowSeconds": selected_window,
            "requestsPerSecond": requests_per_second,
            "requestsPerMinute": requests_per_minute,
            "errorCounts": _sorted_counter(error_counts),
            "proxyCount": len(proxies),
            "proxies": proxies,
        }

    def snapshot_detail(
        self,
        *,
        proxy: str | None,
        window_seconds: float | None = None,
        bucket_count: int = 24,
        now: float | None = None,
    ) -> dict[str, Any]:
        proxy_key = normalize_proxy_endpoint(proxy)
        requested_window = (
            self.default_window_seconds if window_seconds is None else float(window_seconds)
        )
        selected_window = max(1.0, min(requested_window, self.retention_seconds))
        cutoff = (time.monotonic() if now is None else float(now)) - selected_window
        current_now = time.monotonic() if now is None else float(now)
        with self._lock:
            series = self._series.get(proxy_key or "")
            if series is None:
                return {
                    "proxyKey": proxy_key or "",
                    "proxyLabel": proxy_key or "",
                    "found": False,
                    "bucketCount": max(1, int(bucket_count)),
                    "bucketSizeSeconds": selected_window / max(1, int(bucket_count)),
                    "buckets": [
                        _empty_detail_bucket(
                            index=index,
                            bucket_count=max(1, int(bucket_count)),
                            bucket_size_seconds=selected_window / max(1, int(bucket_count)),
                            window_seconds=selected_window,
                        )
                        for index in range(max(1, int(bucket_count)))
                    ],
                    "recentFailures": [],
                    "stats": _snapshot_stats(
                        proxy_key=proxy_key or "",
                        proxy_label=proxy_key or "",
                        total_calls=0,
                        success_calls=0,
                        failure_calls=0,
                        total_elapsed_seconds=0.0,
                        error_counts=Counter(),
                        window_seconds=selected_window,
                    ),
                }
            series.prune(current_now - self.retention_seconds)
            return series.snapshot_detail(
                window_seconds=selected_window,
                cutoff=cutoff,
                bucket_count=bucket_count,
                now=current_now,
            )


_DEFAULT_PROXY_STATS = ProxyStatsCollector()


def record_proxy_request(
    *,
    proxy: str | None,
    success: bool,
    elapsed_seconds: float,
    error_type: str | None = None,
    now: float | None = None,
) -> None:
    _DEFAULT_PROXY_STATS.record(
        proxy=proxy,
        success=success,
        elapsed_seconds=elapsed_seconds,
        error_type=error_type,
        now=now,
    )


def reset_proxy_stats() -> None:
    _DEFAULT_PROXY_STATS.reset()


def snapshot_proxy_stats(
    *,
    window_seconds: float | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    return _DEFAULT_PROXY_STATS.snapshot(window_seconds=window_seconds, now=now)


def snapshot_proxy_detail(
    *,
    proxy: str | None,
    window_seconds: float | None = None,
    bucket_count: int = 24,
    now: float | None = None,
) -> dict[str, Any]:
    return _DEFAULT_PROXY_STATS.snapshot_detail(
        proxy=proxy,
        window_seconds=window_seconds,
        bucket_count=bucket_count,
        now=now,
    )
