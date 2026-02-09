from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse
import random

DEFAULT_RETRY_STATUSES = {429, 500, 502, 503, 504}
_DNS_ERROR_TOKENS = (
    "name or service not known",
    "nodename nor servname provided",
    "temporary failure in name resolution",
    "failed to resolve",
    "cannot resolve",
    "getaddrinfo failed",
    "no address associated with hostname",
)


def clean_proxy_list(values: Iterable[str] | None) -> list[str]:
    cleaned: list[str] = []
    for proxy in values or []:
        value = proxy.strip()
        if not value:
            continue
        if value.lower() in {"none", "off", "direct"}:
            continue
        cleaned.append(value)
    return cleaned


class ProxyPool:
    def __init__(self, proxies: Iterable[str] | None = None) -> None:
        self._proxies = clean_proxy_list(proxies)
        self._index = 0

    def set(self, proxies: Iterable[str] | None) -> None:
        self._proxies = clean_proxy_list(proxies)
        self._index = 0

    def next(self) -> str | None:
        if not self._proxies:
            return None
        proxy = self._proxies[self._index % len(self._proxies)]
        self._index += 1
        return proxy

    def snapshot(self) -> list[str]:
        return list(self._proxies)


@dataclass
class RetryPolicy:
    retries: int = 0
    backoff: float = 0.0
    request_delay: float = 0.0
    retry_statuses: set[int] = field(default_factory=lambda: set(DEFAULT_RETRY_STATUSES))

    def __post_init__(self) -> None:
        self.retries = max(0, int(self.retries))
        self.backoff = max(0.0, float(self.backoff))
        self.request_delay = max(0.0, float(self.request_delay))
        if not self.retry_statuses:
            self.retry_statuses = set(DEFAULT_RETRY_STATUSES)

    def delay_for_attempt(self, attempt: int) -> float:
        if self.backoff <= 0:
            return 0.0
        delay = self.backoff * (2 ** (attempt - 1))
        delay += random.uniform(0.0, self.backoff)
        return delay


def mask_proxy(proxy: str | None) -> str:
    if not proxy:
        return "-"
    try:
        parsed = urlparse(proxy)
    except Exception:
        return proxy
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        if parsed.username:
            return f"{parsed.scheme}://{parsed.username}:***@{host}{port}"
        return f"{parsed.scheme}://{host}{port}"
    return proxy


def is_dns_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(token in message for token in _DNS_ERROR_TOKENS)
