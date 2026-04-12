from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse
import random
import time

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
        self._reserved_until: dict[str, float] = {}

    def set(self, proxies: Iterable[str] | None) -> None:
        self._proxies = clean_proxy_list(proxies)
        self._index = 0
        allowed = set(self._proxies)
        self._reserved_until = {
            proxy: reserved_until
            for proxy, reserved_until in self._reserved_until.items()
            if proxy in allowed
        }

    def reserve(
        self,
        proxy: str | None,
        cooldown_seconds: float,
        *,
        now: float | None = None,
    ) -> None:
        if not proxy:
            return
        delay = max(0.0, float(cooldown_seconds))
        if delay <= 0:
            return
        current_now = time.monotonic() if now is None else float(now)
        reserved_until = current_now + delay
        previous = self._reserved_until.get(proxy, 0.0)
        if reserved_until > previous:
            self._reserved_until[proxy] = reserved_until

    def next(self, *, now: float | None = None) -> str | None:
        if not self._proxies:
            return None
        current_now = time.monotonic() if now is None else float(now)
        fallback_index: int | None = None
        fallback_until = 0.0
        total = len(self._proxies)
        for offset in range(total):
            index = (self._index + offset) % total
            proxy = self._proxies[index]
            reserved_until = self._reserved_until.get(proxy, 0.0)
            if reserved_until <= current_now:
                self._index = index + 1
                return proxy
            if fallback_index is None or reserved_until < fallback_until:
                fallback_index = index
                fallback_until = reserved_until
        if fallback_index is None:
            return None
        proxy = self._proxies[fallback_index]
        self._index = fallback_index + 1
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


@dataclass(frozen=True)
class ParsedProxy:
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @property
    def is_socks(self) -> bool:
        return self.scheme in {"socks5", "socks5h"}

    @property
    def is_http(self) -> bool:
        return self.scheme in {"http", "https"}


def parse_proxy_url(value: str) -> ParsedProxy:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("proxy URL is empty")
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError(f"unsupported proxy scheme: {parsed.scheme or '-'}")
    if not parsed.hostname:
        raise ValueError("proxy host is required")
    if parsed.port is None:
        raise ValueError("proxy port is required")
    return ParsedProxy(
        scheme=scheme,
        host=parsed.hostname,
        port=int(parsed.port),
        username=parsed.username,
        password=parsed.password,
    )


def validate_proxy_url(value: str) -> None:
    parse_proxy_url(value)


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
