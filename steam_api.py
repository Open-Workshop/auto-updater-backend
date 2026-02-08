import logging
import random
import re
import time
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

_LOG_STEAM_REQUESTS = False
_STEAM_STATS = {"total": 0, "success": 0, "failed": 0, "by_endpoint": {}}
_STEAM_HTTP_RETRIES = 2
_STEAM_HTTP_BACKOFF = 1.0
_STEAM_REQUEST_DELAY = 0.0
_STEAM_LAST_REQUEST_TS = 0.0
_STEAM_RETRY_STATUSES = {429, 500, 502, 503, 504}
_STEAM_PROXY_POOL: List[str] = []
_STEAM_PROXY_INDEX = 0


def set_steam_request_logging(enabled: bool) -> None:
    global _LOG_STEAM_REQUESTS
    _LOG_STEAM_REQUESTS = bool(enabled)


def set_steam_request_policy(retries: int, backoff: float, request_delay: float) -> None:
    global _STEAM_HTTP_RETRIES, _STEAM_HTTP_BACKOFF, _STEAM_REQUEST_DELAY
    _STEAM_HTTP_RETRIES = max(0, int(retries))
    _STEAM_HTTP_BACKOFF = max(0.0, float(backoff))
    _STEAM_REQUEST_DELAY = max(0.0, float(request_delay))


def set_steam_proxy_pool(proxies: List[str]) -> None:
    global _STEAM_PROXY_POOL, _STEAM_PROXY_INDEX
    cleaned: List[str] = []
    for proxy in proxies or []:
        value = proxy.strip()
        if not value:
            continue
        if value.lower() in {"none", "off", "direct"}:
            continue
        cleaned.append(value)
    _STEAM_PROXY_POOL = cleaned
    _STEAM_PROXY_INDEX = 0


def steam_stats_reset() -> None:
    _STEAM_STATS["total"] = 0
    _STEAM_STATS["success"] = 0
    _STEAM_STATS["failed"] = 0
    _STEAM_STATS["by_endpoint"] = {}


def steam_stats_snapshot() -> Dict[str, Any]:
    snapshot = {
        "total": _STEAM_STATS["total"],
        "success": _STEAM_STATS["success"],
        "failed": _STEAM_STATS["failed"],
        "by_endpoint": dict(_STEAM_STATS["by_endpoint"]),
    }
    return snapshot


def _endpoint_key(method: str, url: str) -> str:
    parsed = urlparse(url)
    return f"{method.upper()} {parsed.netloc}{parsed.path}"


def _record_stat(endpoint: str, ok: bool) -> None:
    _STEAM_STATS["total"] += 1
    if ok:
        _STEAM_STATS["success"] += 1
    else:
        _STEAM_STATS["failed"] += 1
    _STEAM_STATS["by_endpoint"][endpoint] = _STEAM_STATS["by_endpoint"].get(endpoint, 0) + 1


def _next_proxy() -> str | None:
    global _STEAM_PROXY_INDEX
    if not _STEAM_PROXY_POOL:
        return None
    proxy = _STEAM_PROXY_POOL[_STEAM_PROXY_INDEX % len(_STEAM_PROXY_POOL)]
    _STEAM_PROXY_INDEX += 1
    return proxy


def _mask_proxy(proxy: str | None) -> str:
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


def _steam_request(method: str, url: str, timeout: int, **kwargs: Any) -> requests.Response:
    global _STEAM_LAST_REQUEST_TS
    endpoint = _endpoint_key(method, url)

    attempts = _STEAM_HTTP_RETRIES + 1
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        proxy = _next_proxy()
        if proxy:
            kwargs = dict(kwargs)
            kwargs["proxies"] = {"http": proxy, "https": proxy}

        if _STEAM_REQUEST_DELAY > 0:
            now = time.monotonic()
            wait_for = _STEAM_REQUEST_DELAY - (now - _STEAM_LAST_REQUEST_TS)
            if wait_for > 0:
                time.sleep(wait_for)

        start = time.monotonic()
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            last_exc = exc
            _record_stat(endpoint, False)
            if _LOG_STEAM_REQUESTS:
                elapsed = time.monotonic() - start
                logging.warning(
                    "Steam %s failed after %.2fs via %s: %s (%s)",
                    endpoint,
                    elapsed,
                    _mask_proxy(proxy),
                    exc,
                    type(exc).__name__,
                )
            if attempt >= attempts:
                raise
            _sleep_steam_backoff(attempt, exc)
            continue
        finally:
            _STEAM_LAST_REQUEST_TS = time.monotonic()

        ok = response.status_code < 400
        _record_stat(endpoint, ok)
        if _LOG_STEAM_REQUESTS:
            elapsed = time.monotonic() - start
            size = response.headers.get("content-length") or "-"
            log_fn = logging.info if ok else logging.warning
            log_fn(
                "Steam %s -> %s in %.2fs (size=%s, proxy=%s)",
                endpoint,
                response.status_code,
                elapsed,
                size,
                _mask_proxy(proxy),
            )

        if response.status_code in _STEAM_RETRY_STATUSES and attempt < attempts:
            retry_after = response.headers.get("retry-after")
            if retry_after:
                try:
                    time.sleep(float(retry_after))
                except ValueError:
                    pass
            _sleep_steam_backoff(
                attempt, RuntimeError(f"HTTP {response.status_code}")
            )
            continue
        return response

    if last_exc:
        raise last_exc
    return response


def _sleep_steam_backoff(attempt: int, exc: Exception) -> None:
    if _STEAM_HTTP_BACKOFF <= 0:
        return
    delay = _STEAM_HTTP_BACKOFF * (2 ** (attempt - 1))
    delay += random.uniform(0.0, _STEAM_HTTP_BACKOFF)
    logging.warning(
        "Steam retry %s/%s after error: %s (sleep %.1fs)",
        attempt,
        _STEAM_HTTP_RETRIES,
        exc,
        delay,
    )
    time.sleep(delay)


def steam_get_app_details(app_id: int, language: str, timeout: int) -> Dict[str, str]:
    url = "https://store.steampowered.com/api/appdetails"
    response = _steam_request(
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


def steam_fetch_workshop_page_ids_html(
    app_id: int,
    page: int,
    language: str,
    timeout: int,
) -> List[str]:
    url = "https://steamcommunity.com/workshop/browse/"
    params = {
        "appid": app_id,
        "browsesort": "mostrecent",
        "section": "readytouseitems",
        "p": page,
        "l": language,
    }
    response = _steam_request(
        "get",
        url,
        params=params,
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=timeout,
    )
    if response.status_code != 200:
        return []
    return re.findall(r"data-publishedfileid=\"(\d+)\"", response.text)

