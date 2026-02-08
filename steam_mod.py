import asyncio
import hashlib
import logging
import mimetypes
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Mapping, Tuple
from urllib.parse import parse_qs, urlparse

import aiohttp
from selectolax.parser import HTMLParser

from utils import dedupe_images, ensure_dir, normalize_image_url

_STEAMMOD_PROXY_POOL: List[str] = []
_STEAMMOD_PROXY_INDEX = 0
_STEAMMOD_DEFAULT_TIMEOUT = 20
_STEAMMOD_IMAGE_CONCURRENCY = 6
_STEAMMOD_HTTP_RETRIES = 2
_STEAMMOD_HTTP_BACKOFF = 1.0
_STEAMMOD_REQUEST_DELAY = 0.0
_STEAMMOD_RETRY_STATUSES = {429, 500, 502, 503, 504}
_STEAMMOD_REQUEST_LOCKS: dict[int, asyncio.Lock] = {}
_STEAMMOD_LAST_REQUEST_TS: dict[int, float] = {}

ImageTarget = Tuple[str, str, str]
ImageDownload = Tuple[str, str, Path, str]


def set_steam_mod_proxy_pool(proxies: List[str]) -> None:
    global _STEAMMOD_PROXY_POOL, _STEAMMOD_PROXY_INDEX
    cleaned: List[str] = []
    for proxy in proxies or []:
        value = proxy.strip()
        if not value:
            continue
        if value.lower() in {"none", "off", "direct"}:
            continue
        cleaned.append(value)
    _STEAMMOD_PROXY_POOL = cleaned
    _STEAMMOD_PROXY_INDEX = 0


def set_steam_mod_request_policy(retries: int, backoff: float, request_delay: float) -> None:
    global _STEAMMOD_HTTP_RETRIES, _STEAMMOD_HTTP_BACKOFF, _STEAMMOD_REQUEST_DELAY
    _STEAMMOD_HTTP_RETRIES = max(0, int(retries))
    _STEAMMOD_HTTP_BACKOFF = max(0.0, float(backoff))
    _STEAMMOD_REQUEST_DELAY = max(0.0, float(request_delay))


def _next_proxy() -> str | None:
    global _STEAMMOD_PROXY_INDEX
    if not _STEAMMOD_PROXY_POOL:
        return None
    proxy = _STEAMMOD_PROXY_POOL[_STEAMMOD_PROXY_INDEX % len(_STEAMMOD_PROXY_POOL)]
    _STEAMMOD_PROXY_INDEX += 1
    return proxy


async def _respect_request_delay() -> None:
    if _STEAMMOD_REQUEST_DELAY <= 0:
        return
    loop = asyncio.get_running_loop()
    key = id(loop)
    lock = _STEAMMOD_REQUEST_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _STEAMMOD_REQUEST_LOCKS[key] = lock
    async with lock:
        now = time.monotonic()
        last_ts = _STEAMMOD_LAST_REQUEST_TS.get(key, 0.0)
        wait_for = _STEAMMOD_REQUEST_DELAY - (now - last_ts)
        if wait_for > 0:
            await asyncio.sleep(wait_for)
        _STEAMMOD_LAST_REQUEST_TS[key] = time.monotonic()


async def _sleep_backoff(attempt: int, exc: Exception) -> None:
    if _STEAMMOD_HTTP_BACKOFF <= 0:
        return
    delay = _STEAMMOD_HTTP_BACKOFF * (2 ** (attempt - 1))
    delay += random.uniform(0.0, _STEAMMOD_HTTP_BACKOFF)
    logging.warning(
        "Steam retry %s/%s after error: %s (sleep %.1fs)",
        attempt,
        _STEAMMOD_HTTP_RETRIES,
        exc,
        delay,
    )
    await asyncio.sleep(delay)


def _clean_text(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value).strip()


def _dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _parse_steam_date(value: str | None) -> int:
    if not value:
        return 0
    cleaned = _clean_text(value)
    if not cleaned:
        return 0
    cleaned = re.sub(r"^(posted|updated|created)\s*[:\-]\s*", "", cleaned, flags=re.I)
    cleaned = cleaned.replace("@", " ")
    cleaned = cleaned.replace("AM", "am").replace("PM", "pm")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    patterns = [
        "%d %b, %Y %I:%M%p",
        "%d %b, %Y %I:%M %p",
        "%d %b, %Y %H:%M",
        "%b %d, %Y %I:%M%p",
        "%b %d, %Y %I:%M %p",
        "%b %d, %Y %H:%M",
        "%d %b %Y %I:%M%p",
        "%d %b %Y %I:%M %p",
        "%d %b %Y %H:%M",
        "%b %d %Y %I:%M%p",
        "%b %d %Y %I:%M %p",
        "%b %d %Y %H:%M",
        "%d %b, %Y",
        "%b %d, %Y",
        "%d %b %Y",
        "%b %d %Y",
        "%d %b",
        "%b %d",
    ]
    for fmt in patterns:
        try:
            dt = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt:
            dt = dt.replace(year=datetime.now(timezone.utc).year)
        dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    return 0


def _extract_dependencies(html_text: str) -> List[str]:
    parser = HTMLParser(html_text)
    ids: List[str] = []
    seen = set()
    for node in parser.css("div#RequiredItems a"):
        href = node.attributes.get("href") or ""
        if not href:
            continue
        parsed = urlparse(href)
        query = parse_qs(parsed.query)
        item_ids = query.get("id") or []
        for item_id in item_ids:
            if not item_id or item_id in seen:
                continue
            seen.add(item_id)
            ids.append(item_id)
    return ids


def _extension_from_headers(headers: Mapping[str, str]) -> str:
    content_type = ""
    try:
        content_type = (headers.get("content-type") or "").split(";")[0].strip().lower()
    except Exception:
        content_type = ""
    if not content_type:
        return ""
    ext = mimetypes.guess_extension(content_type) or ""
    if ext == ".jpe":
        ext = ".jpg"
    return ext


class SteamMod:
    def __init__(self, item_id: str) -> None:
        self.item_id = str(item_id)
        self.title = ""
        self.description = ""
        self.tags: List[str] = []
        self.dependencies: List[str] = []
        self.logo = ""
        self.screenshots: List[str] = []
        self.size_text = ""
        self.created_at = ""
        self.updated_at = ""
        self.created_ts = 0
        self.updated_ts = 0
        self.page_ok = False

    async def load(
        self,
        *,
        timeout: int | None = None,
        proxy: str | None = None,
        session: aiohttp.ClientSession | None = None,
        language: str | None = None,
    ) -> bool:
        url = f"https://steamcommunity.com/sharedfiles/filedetails/?id={self.item_id}&requireditems=1"
        if language:
            url = f"{url}&l={language}"
        timeout_value = _STEAMMOD_DEFAULT_TIMEOUT if timeout is None else int(timeout)
        close_session = False

        if session is None:
            timeout_cfg = aiohttp.ClientTimeout(total=timeout_value)
            session = aiohttp.ClientSession(timeout=timeout_cfg)
            close_session = True

        html_text: str | None = None
        attempts = _STEAMMOD_HTTP_RETRIES + 1
        last_exc: Exception | None = None
        try:
            for attempt in range(1, attempts + 1):
                chosen_proxy = proxy if proxy is not None else _next_proxy()
                await _respect_request_delay()
                try:
                    async with session.get(
                        url,
                        headers={"User-Agent": "Mozilla/5.0"},
                        proxy=chosen_proxy,
                        timeout=timeout_value,
                    ) as response:
                        if response.status in _STEAMMOD_RETRY_STATUSES and attempt < attempts:
                            retry_after = response.headers.get("retry-after")
                            if retry_after:
                                try:
                                    await asyncio.sleep(float(retry_after))
                                except ValueError:
                                    pass
                            await _sleep_backoff(
                                attempt, RuntimeError(f"HTTP {response.status}")
                            )
                            continue
                        if response.status != 200:
                            logging.warning(
                                "Steam page fetch failed for %s: HTTP %s",
                                self.item_id,
                                response.status,
                            )
                            return False
                        html_text = await response.text()
                        break
                except aiohttp.ClientError as exc:
                    last_exc = exc
                    if attempt >= attempts:
                        logging.warning("Steam page fetch failed for %s: %s", self.item_id, exc)
                        return False
                    await _sleep_backoff(attempt, exc)
                    continue
        finally:
            if close_session and session is not None:
                await session.close()
        if html_text is None:
            if last_exc:
                logging.warning("Steam page fetch failed for %s: %s", self.item_id, last_exc)
            return False

        parser = HTMLParser(html_text)
        self.title = _clean_text(
            parser.css_first("div.workshopItemTitle").text()
            if parser.css_first("div.workshopItemTitle")
            else ""
        )
        description_node = parser.css_first("div.workshopItemDescription")
        self.description = _clean_text(description_node.text() if description_node else "")

        logo_node = parser.css_first(
            "div.col_right.responsive_local_menu div.workshopItemPreviewImageMain a img"
        )
        logo_url = normalize_image_url(
            logo_node.attributes.get("src") if logo_node else ""
        )
        self.logo = logo_url

        right_blocks = parser.css("div.rightDetailsBlock")
        if right_blocks:
            tag_nodes = right_blocks[0].css("a")
            tag_values = [_clean_text(node.text()) for node in tag_nodes if node.text()]
            self.tags = _dedupe_keep_order([t for t in tag_values if t])

        if len(right_blocks) > 1:
            stat_nodes = right_blocks[1].css(
                "div.detailsStatsContainerRight div.detailsStatRight"
            )
            stats = [_clean_text(node.text()) for node in stat_nodes if node.text()]
            self.size_text = stats[0] if len(stats) > 0 else ""
            self.created_at = stats[1] if len(stats) > 1 else ""
            self.updated_at = stats[2] if len(stats) > 2 else ""
            self.created_ts = _parse_steam_date(self.created_at)
            self.updated_ts = _parse_steam_date(self.updated_at)

        screenshot_nodes = parser.css("div.highlight_strip_screenshot img")
        screenshot_urls: List[str] = []
        for node in screenshot_nodes:
            raw_url = node.attributes.get("src") or node.attributes.get("data-src") or ""
            url = normalize_image_url(raw_url)
            if url:
                screenshot_urls.append(url)
        screenshot_urls = dedupe_images(screenshot_urls)

        if self.logo:
            images = dedupe_images([self.logo] + screenshot_urls)
            self.logo = images[0]
            self.screenshots = images[1:]
        else:
            self.screenshots = screenshot_urls

        self.dependencies = _extract_dependencies(html_text)
        self.page_ok = True
        return True

    async def download_images(
        self,
        dest_dir: Path,
        targets: List[ImageTarget],
        *,
        timeout: int | None = None,
        proxy: str | None = None,
        session: aiohttp.ClientSession | None = None,
        max_concurrency: int | None = None,
    ) -> List[ImageDownload]:
        if not targets:
            return []
        ensure_dir(dest_dir)
        timeout_value = _STEAMMOD_DEFAULT_TIMEOUT if timeout is None else int(timeout)
        concurrency = _STEAMMOD_IMAGE_CONCURRENCY if max_concurrency is None else int(max_concurrency)
        concurrency = max(1, concurrency)

        close_session = False
        if session is None:
            timeout_cfg = aiohttp.ClientTimeout(total=timeout_value)
            session = aiohttp.ClientSession(timeout=timeout_cfg)
            close_session = True

        semaphore = asyncio.Semaphore(concurrency)

        async def fetch_one(target: ImageTarget) -> ImageDownload | None:
            res_type, url, basename = target
            if not url:
                return None
            temp_path: Path | None = None
            async with semaphore:
                try:
                    attempts = _STEAMMOD_HTTP_RETRIES + 1
                    last_exc: Exception | None = None
                    for attempt in range(1, attempts + 1):
                        chosen_proxy = proxy if proxy is not None else _next_proxy()
                        await _respect_request_delay()
                        try:
                            async with session.get(
                                url,
                                headers={"User-Agent": "Mozilla/5.0"},
                                proxy=chosen_proxy,
                                timeout=timeout_value,
                            ) as response:
                                if (
                                    response.status in _STEAMMOD_RETRY_STATUSES
                                    and attempt < attempts
                                ):
                                    retry_after = response.headers.get("retry-after")
                                    if retry_after:
                                        try:
                                            await asyncio.sleep(float(retry_after))
                                        except ValueError:
                                            pass
                                    await _sleep_backoff(
                                        attempt, RuntimeError(f"HTTP {response.status}")
                                    )
                                    continue
                                if response.status != 200:
                                    logging.warning(
                                        "Steam image fetch failed for %s: HTTP %s",
                                        url,
                                        response.status,
                                    )
                                    return None
                                ext = _extension_from_headers(response.headers) or ".bin"
                                path = dest_dir / f"{basename}{ext}"
                                temp_path = path.with_suffix(f"{path.suffix}.part")
                                digest = hashlib.sha256()
                                with temp_path.open("wb") as handle:
                                    async for chunk in response.content.iter_chunked(
                                        1024 * 1024
                                    ):
                                        if not chunk:
                                            continue
                                        handle.write(chunk)
                                        digest.update(chunk)
                                temp_path.replace(path)
                                temp_path = None
                                return (res_type, url, path, digest.hexdigest())
                        except aiohttp.ClientError as exc:
                            last_exc = exc
                            if attempt >= attempts:
                                logging.warning(
                                    "Steam image fetch failed for %s: %s", url, exc
                                )
                                return None
                            await _sleep_backoff(attempt, exc)
                            continue
                    if last_exc:
                        logging.warning("Steam image fetch failed for %s: %s", url, last_exc)
                    return None
                finally:
                    if temp_path and temp_path.exists():
                        try:
                            temp_path.unlink()
                        except FileNotFoundError:
                            pass

        try:
            tasks = [asyncio.create_task(fetch_one(target)) for target in targets]
            raw_results = await asyncio.gather(*tasks)
            results: List[ImageDownload] = []
            for entry in raw_results:
                if entry is not None:
                    results.append(entry)
            return results
        finally:
            if close_session and session is not None:
                await session.close()
