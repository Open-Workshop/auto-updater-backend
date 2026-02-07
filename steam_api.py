import html
import logging
import random
import re
import time
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

from utils import normalize_image_url

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


def steam_list_workshop_ids_html(
    app_id: int,
    max_pages: int,
    max_items: int,
    delay: float,
    language: str,
    timeout: int,
) -> List[str]:
    ids: List[str] = []
    seen = set()
    page = 1
    while True:
        if max_pages > 0 and page > max_pages:
            break
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
            break
        page_ids = re.findall(r"data-publishedfileid=\"(\d+)\"", response.text)
        if not page_ids:
            break
        for item_id in page_ids:
            if item_id in seen:
                continue
            seen.add(item_id)
            ids.append(item_id)
            if max_items > 0 and len(ids) >= max_items:
                return ids
        page += 1
        if delay > 0:
            time.sleep(delay)
    return ids


def steam_get_published_file_details(
    ids: List[str], timeout: int
) -> Dict[str, Dict[str, Any]]:
    if not ids:
        return {}
    params: Dict[str, Any] = {"itemcount": len(ids)}
    for idx, item_id in enumerate(ids):
        params[f"publishedfileids[{idx}]"] = item_id
    response = _steam_request(
        "post",
        "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/",
        data=params,
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json().get("response", {})
    details: Dict[str, Dict[str, Any]] = {}
    for entry in payload.get("publishedfiledetails", []):
        file_id = entry.get("publishedfileid")
        if file_id:
            details[str(file_id)] = entry
    return details


def _extract_images_from_html(text: str) -> List[str]:
    normalized: List[str] = []
    seen = set()

    def add_url(raw: str) -> None:
        url = normalize_image_url(html.unescape(raw))
        if not url or url in seen:
            return
        seen.add(url)
        normalized.append(url)

    for key in ("rgFullScreenshotURLs", "rgScreenshotURLs"):
        match = re.search(rf"{key}\s*=\s*(\[.*?\])", text, flags=re.S)
        if match:
            block = match.group(1)
            for raw in re.findall(r"https?://[^\"'\s>]+", block):
                add_url(raw)

    for raw in re.findall(
        r"highlight_strip_item[^>]*highlight_strip_screenshot[^>]*>\s*<img[^>]+src=\"([^\"]+)\"",
        text,
        flags=re.I,
    ):
        add_url(raw)

    for raw in re.findall(
        r"https?://(?:images\.steamusercontent\.com|steamusercontent-a\.akamaihd\.net|steamuserimages-a\.akamaihd\.net)/ugc/[^\"'\s>]+",
        text,
        flags=re.I,
    ):
        add_url(raw)

    return normalized


def _extract_required_items_from_html(text: str) -> List[str]:
    required_block_match = re.search(
        r"<div class=\"requiredItemsContainer\" id=\"RequiredItems\">(.*?)</div>",
        text,
        flags=re.S | re.I,
    )
    block = required_block_match.group(1) if required_block_match else text
    ids = set()
    for pat in [
        r"workshop/filedetails/\?id=(\d+)",
        r"sharedfiles/filedetails/\?id=(\d+)",
    ]:
        for match in re.findall(pat, block):
            ids.add(match)
    return list(ids)


def steam_scrape_workshop_page(
    item_id: str,
    timeout: int,
    include_required: bool = True,
) -> tuple[List[str], List[str], bool]:
    url = f"https://steamcommunity.com/sharedfiles/filedetails/?id={item_id}"
    if include_required:
        url += "&requireditems=1"
    try:
        response = _steam_request(
            "get",
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        logging.warning("Steam scrape failed for %s: %s", item_id, exc)
        return [], [], False
    if response.status_code != 200:
        logging.warning(
            "Steam scrape failed for %s: HTTP %s",
            item_id,
            response.status_code,
        )
        return [], [], False
    text = response.text
    images = _extract_images_from_html(text)
    deps = _extract_required_items_from_html(text) if include_required else []
    return images, deps, True
