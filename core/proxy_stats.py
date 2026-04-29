"""In-process proxy telemetry for Steam clients."""

from __future__ import annotations

import time
from collections import Counter, deque
from threading import Lock
from typing import Any

from core.http_utils import is_dns_error


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


class ProxyStatsCollector:
    """Thread-safe aggregate of proxied request outcomes."""

    def __init__(self, recent_window_seconds: float = 60.0) -> None:
        self.recent_window_seconds = max(1.0, float(recent_window_seconds))
        self._lock = Lock()
        self._total_calls = 0
        self._success_calls = 0
        self._failure_calls = 0
        self._elapsed_seconds = 0.0
        self._error_counts: Counter[str] = Counter()
        self._recent_timestamps: deque[float] = deque()

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
        if not proxy:
            return
        current_now = time.monotonic() if now is None else float(now)
        duration = max(0.0, float(elapsed_seconds))
        with self._lock:
            self._total_calls += 1
            if success:
                self._success_calls += 1
            else:
                self._failure_calls += 1
                if error_type:
                    self._error_counts[str(error_type)] += 1
            self._elapsed_seconds += duration
            self._recent_timestamps.append(current_now)
            self._cleanup_locked(current_now)

    def reset(self) -> None:
        """Clear all collected stats."""
        with self._lock:
            self._total_calls = 0
            self._success_calls = 0
            self._failure_calls = 0
            self._elapsed_seconds = 0.0
            self._error_counts.clear()
            self._recent_timestamps.clear()

    def _cleanup_locked(self, now: float) -> None:
        cutoff = now - self.recent_window_seconds
        while self._recent_timestamps and self._recent_timestamps[0] < cutoff:
            self._recent_timestamps.popleft()

    def snapshot(self, now: float | None = None) -> dict[str, Any]:
        """Return a serialisable snapshot of the collected stats."""
        current_now = time.monotonic() if now is None else float(now)
        with self._lock:
            self._cleanup_locked(current_now)
            total_calls = self._total_calls
            success_calls = self._success_calls
            failure_calls = self._failure_calls
            elapsed_seconds = self._elapsed_seconds
            recent_requests = len(self._recent_timestamps)
            error_counts = {
                key: value
                for key, value in sorted(
                    self._error_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )
            }

        average_response_ms = (
            (elapsed_seconds / total_calls) * 1000.0 if total_calls else None
        )
        requests_per_second = recent_requests / self.recent_window_seconds
        requests_per_minute = requests_per_second * 60.0
        return {
            "totalCalls": total_calls,
            "successCalls": success_calls,
            "failureCalls": failure_calls,
            "totalElapsedSeconds": elapsed_seconds,
            "averageResponseMs": average_response_ms,
            "recentRequests": recent_requests,
            "recentWindowSeconds": self.recent_window_seconds,
            "requestsPerSecond": requests_per_second,
            "requestsPerMinute": requests_per_minute,
            "errorCounts": error_counts,
        }


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


def snapshot_proxy_stats(now: float | None = None) -> dict[str, Any]:
    return _DEFAULT_PROXY_STATS.snapshot(now=now)
