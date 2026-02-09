from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

from http_utils import ProxyPool, RetryPolicy, mask_proxy, is_dns_error


@dataclass
class SteamStats:
    total: int = 0
    success: int = 0
    failed: int = 0
    by_endpoint: Dict[str, int] = field(default_factory=dict)

    def record(self, endpoint: str, ok: bool) -> None:
        self.total += 1
        if ok:
            self.success += 1
        else:
            self.failed += 1
        self.by_endpoint[endpoint] = self.by_endpoint.get(endpoint, 0) + 1

    def reset(self) -> None:
        self.total = 0
        self.success = 0
        self.failed = 0
        self.by_endpoint = {}

    def snapshot(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "success": self.success,
            "failed": self.failed,
            "by_endpoint": dict(self.by_endpoint),
        }


class SteamClient:
    def __init__(
        self,
        *,
        policy: RetryPolicy | None = None,
        proxies: List[str] | None = None,
        log_requests: bool = False,
    ) -> None:
        self.policy = policy or RetryPolicy(retries=2, backoff=1.0, request_delay=0.0)
        self.proxy_pool = ProxyPool(proxies)
        self.log_requests = bool(log_requests)
        self.stats = SteamStats()
        self._last_request_ts = 0.0

    def set_policy(self, retries: int, backoff: float, request_delay: float) -> None:
        self.policy = RetryPolicy(
            retries=retries,
            backoff=backoff,
            request_delay=request_delay,
            retry_statuses=set(self.policy.retry_statuses),
        )

    def set_proxy_pool(self, proxies: List[str]) -> None:
        self.proxy_pool.set(proxies)

    def set_log_requests(self, enabled: bool) -> None:
        self.log_requests = bool(enabled)

    def reset_stats(self) -> None:
        self.stats.reset()

    def snapshot_stats(self) -> Dict[str, Any]:
        return self.stats.snapshot()

    def request(self, method: str, url: str, timeout: int, **kwargs: Any) -> requests.Response:
        endpoint = self._endpoint_key(method, url)
        attempts = self.policy.retries + 1
        last_exc: Exception | None = None
        for attempt in range(1, attempts + 1):
            proxy = self.proxy_pool.next()
            if proxy:
                kwargs = dict(kwargs)
                kwargs["proxies"] = {"http": proxy, "https": proxy}

            if self.policy.request_delay > 0:
                now = time.monotonic()
                wait_for = self.policy.request_delay - (now - self._last_request_ts)
                if wait_for > 0:
                    time.sleep(wait_for)

            start = time.monotonic()
            try:
                response = requests.request(method, url, timeout=timeout, **kwargs)
            except requests.RequestException as exc:
                last_exc = exc
                self.stats.record(endpoint, False)
                if proxy and is_dns_error(exc) and not self.log_requests:
                    logging.warning(
                        "Steam proxy DNS error for url=%s via %s: %s",
                        url,
                        mask_proxy(proxy),
                        exc,
                    )
                if self.log_requests:
                    elapsed = time.monotonic() - start
                    if proxy and is_dns_error(exc):
                        logging.warning(
                            "Steam %s failed after %.2fs via %s: %s (%s) url=%s",
                            endpoint,
                            elapsed,
                            mask_proxy(proxy),
                            exc,
                            type(exc).__name__,
                            url,
                        )
                    else:
                        logging.warning(
                            "Steam %s failed after %.2fs via %s: %s (%s)",
                            endpoint,
                            elapsed,
                            mask_proxy(proxy),
                            exc,
                            type(exc).__name__,
                        )
                if attempt >= attempts:
                    raise
                self._sleep_backoff(attempt, exc, url=url, proxy=proxy)
                continue
            finally:
                self._last_request_ts = time.monotonic()

            ok = response.status_code < 400
            self.stats.record(endpoint, ok)
            if self.log_requests:
                elapsed = time.monotonic() - start
                size = response.headers.get("content-length") or "-"
                log_fn = logging.info if ok else logging.warning
                log_fn(
                    "Steam %s -> %s in %.2fs (size=%s, proxy=%s)",
                    endpoint,
                    response.status_code,
                    elapsed,
                    size,
                    mask_proxy(proxy),
                )

            if response.status_code in self.policy.retry_statuses and attempt < attempts:
                retry_after = response.headers.get("retry-after")
                if retry_after:
                    try:
                        time.sleep(float(retry_after))
                    except ValueError:
                        pass
                self._sleep_backoff(
                    attempt,
                    RuntimeError(f"HTTP {response.status_code}"),
                    url=url,
                    proxy=proxy,
                )
                continue
            return response

        if last_exc:
            raise last_exc
        return response

    def get_app_details(self, app_id: int, language: str, timeout: int) -> Dict[str, str]:
        url = "https://store.steampowered.com/api/appdetails"
        response = self.request(
            "get",
            url,
            params={"appids": app_id, "l": language},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        entry = payload.get(str(app_id), {})
        if not entry.get("success"):
            raise RuntimeError(f"Steam app {app_id} not found")
        data = entry.get("data", {})
        name = data.get("name", "")
        short_desc = data.get("short_description", "")
        full_desc = data.get("detailed_description", "")
        full_desc = re.sub(r"<[^>]+>", "", full_desc)
        return {
            "name": name,
            "short": short_desc,
            "description": full_desc,
        }

    def fetch_workshop_page_ids_html(
        self, app_id: int, page: int, language: str, timeout: int
    ) -> List[str]:
        url = "https://steamcommunity.com/workshop/browse/"
        params = {
            "appid": app_id,
            "browsesort": "mostrecent",
            "section": "readytouseitems",
            "p": page,
            "l": language,
        }
        response = self.request(
            "get",
            url,
            params=params,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=timeout,
        )
        if response.status_code != 200:
            return []
        return re.findall(r"data-publishedfileid=\"(\d+)\"", response.text)

    @staticmethod
    def _endpoint_key(method: str, url: str) -> str:
        parsed = urlparse(url)
        return f"{method.upper()} {parsed.netloc}{parsed.path}"

    def _sleep_backoff(
        self,
        attempt: int,
        exc: Exception,
        *,
        url: str | None = None,
        proxy: str | None = None,
    ) -> None:
        delay = self.policy.delay_for_attempt(attempt)
        if delay <= 0:
            return
        if url or proxy:
            logging.warning(
                "Steam retry %s/%s after error: %s (sleep %.1fs) url=%s proxy=%s",
                attempt,
                self.policy.retries,
                exc,
                delay,
                url or "-",
                mask_proxy(proxy),
            )
        else:
            logging.warning(
                "Steam retry %s/%s after error: %s (sleep %.1fs)",
                attempt,
                self.policy.retries,
                exc,
                delay,
            )
        time.sleep(delay)


_DEFAULT_CLIENT = SteamClient()


def set_steam_request_logging(enabled: bool) -> None:
    _DEFAULT_CLIENT.set_log_requests(enabled)


def set_steam_request_policy(retries: int, backoff: float, request_delay: float) -> None:
    _DEFAULT_CLIENT.set_policy(retries, backoff, request_delay)


def set_steam_proxy_pool(proxies: List[str]) -> None:
    _DEFAULT_CLIENT.set_proxy_pool(proxies)


def steam_stats_reset() -> None:
    _DEFAULT_CLIENT.reset_stats()


def steam_stats_snapshot() -> Dict[str, Any]:
    return _DEFAULT_CLIENT.snapshot_stats()


def steam_get_app_details(app_id: int, language: str, timeout: int) -> Dict[str, str]:
    return _DEFAULT_CLIENT.get_app_details(app_id, language, timeout)


def steam_fetch_workshop_page_ids_html(
    app_id: int, page: int, language: str, timeout: int
) -> List[str]:
    return _DEFAULT_CLIENT.fetch_workshop_page_ids_html(app_id, page, language, timeout)
