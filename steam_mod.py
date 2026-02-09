from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple
from urllib.parse import parse_qs, urlparse

import aiohttp
from selectolax.parser import HTMLParser

from bbcode import html_to_bbcode
from http_utils import ProxyPool, RetryPolicy, mask_proxy, is_dns_error
from utils import dedupe_images, ensure_dir, normalize_image_url, extension_from_headers

DEFAULT_TIMEOUT = 20
DEFAULT_IMAGE_CONCURRENCY = 6
DEFAULT_RETRY_POLICY = RetryPolicy(retries=2, backoff=1.0, request_delay=0.0)

ImageTarget = Tuple[str, str, str]
ImageDownload = Tuple[str, str, Path, str]


class AsyncThrottle:
    def __init__(self, delay: float) -> None:
        self.delay = max(0.0, float(delay))
        self._locks: dict[int, asyncio.Lock] = {}
        self._last_ts: dict[int, float] = {}

    async def wait(self) -> None:
        if self.delay <= 0:
            return
        loop = asyncio.get_running_loop()
        key = id(loop)
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        async with lock:
            now = time.monotonic()
            last_ts = self._last_ts.get(key, 0.0)
            wait_for = self.delay - (now - last_ts)
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_ts[key] = time.monotonic()

    def update_delay(self, delay: float) -> None:
        self.delay = max(0.0, float(delay))


@dataclass
class SteamMod:
    item_id: str
    title: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    logo: str = ""
    screenshots: List[str] = field(default_factory=list)
    size_text: str = ""
    created_at: str = ""
    updated_at: str = ""
    created_ts: int = 0
    updated_ts: int = 0
    page_ok: bool = False

    def __post_init__(self) -> None:
        self.item_id = str(self.item_id)

    async def load(
        self,
        *,
        timeout: int | None = None,
        proxy: str | None = None,
        session: aiohttp.ClientSession | None = None,
        language: str | None = None,
        client: SteamWorkshopClient | None = None,
    ) -> bool:
        client = client or _DEFAULT_CLIENT
        fetched = await client.fetch_mod(
            self.item_id,
            timeout=timeout,
            proxy=proxy,
            session=session,
            language=language,
        )
        if fetched is None:
            return False
        self._apply(fetched)
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
        client: SteamWorkshopClient | None = None,
    ) -> List[ImageDownload]:
        client = client or _DEFAULT_CLIENT
        return await client.download_images(
            dest_dir,
            targets,
            timeout=timeout,
            proxy=proxy,
            session=session,
            max_concurrency=max_concurrency,
        )

    @classmethod
    def from_html(cls, item_id: str, html_text: str) -> "SteamMod":
        parser = HTMLParser(html_text)
        title = _clean_text(
            parser.css_first("div.workshopItemTitle").text()
            if parser.css_first("div.workshopItemTitle")
            else ""
        )
        description_node = parser.css_first("div.workshopItemDescription")
        if description_node is None:
            description = ""
        else:
            raw_html = description_node.html or ""
            if not raw_html:
                raw_html = description_node.text() or ""
            description = _clean_description(raw_html)

        logo_node = parser.css_first(
            "div.col_right.responsive_local_menu div.workshopItemPreviewImageMain a img"
        )
        if logo_node is None:
            logo_node = parser.css_first("img#previewImage")
        logo_url = normalize_image_url(
            logo_node.attributes.get("src") if logo_node else ""
        )

        tags: List[str] = []
        size_text = ""
        created_at = ""
        updated_at = ""
        created_ts = 0
        updated_ts = 0

        right_blocks = parser.css("div.rightDetailsBlock")
        if right_blocks:
            tag_nodes = right_blocks[0].css("a")
            tag_values = [_clean_text(node.text()) for node in tag_nodes if node.text()]
            tags = _dedupe_keep_order([t for t in tag_values if t])

        if len(right_blocks) > 1:
            stat_nodes = right_blocks[1].css(
                "div.detailsStatsContainerRight div.detailsStatRight"
            )
            stats = [_clean_text(node.text()) for node in stat_nodes if node.text()]
            size_text = stats[0] if len(stats) > 0 else ""
            created_at = stats[1] if len(stats) > 1 else ""
            updated_at = stats[2] if len(stats) > 2 else ""
            created_ts = _parse_steam_date(created_at)
            updated_ts = _parse_steam_date(updated_at)

        screenshot_nodes = parser.css("div.highlight_strip_screenshot img")
        screenshot_urls: List[str] = []
        for node in screenshot_nodes:
            raw_url = node.attributes.get("src") or node.attributes.get("data-src") or ""
            url = normalize_image_url(raw_url)
            if url:
                screenshot_urls.append(url)
        screenshot_urls = dedupe_images(screenshot_urls)

        if logo_url:
            images = dedupe_images([logo_url] + screenshot_urls)
            logo_url = images[0]
            screenshots = images[1:]
        else:
            screenshots = screenshot_urls

        dependencies = _extract_dependencies(html_text)

        return cls(
            item_id=str(item_id),
            title=title,
            description=description,
            tags=tags,
            dependencies=dependencies,
            logo=logo_url,
            screenshots=screenshots,
            size_text=size_text,
            created_at=created_at,
            updated_at=updated_at,
            created_ts=created_ts,
            updated_ts=updated_ts,
            page_ok=True,
        )

    def _apply(self, other: "SteamMod") -> None:
        self.title = other.title
        self.description = other.description
        self.tags = list(other.tags)
        self.dependencies = list(other.dependencies)
        self.logo = other.logo
        self.screenshots = list(other.screenshots)
        self.size_text = other.size_text
        self.created_at = other.created_at
        self.updated_at = other.updated_at
        self.created_ts = other.created_ts
        self.updated_ts = other.updated_ts
        self.page_ok = other.page_ok


class SteamWorkshopClient:
    def __init__(
        self,
        *,
        policy: RetryPolicy | None = None,
        proxies: List[str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        image_concurrency: int = DEFAULT_IMAGE_CONCURRENCY,
        proxy_images: bool = True,
    ) -> None:
        self.policy = policy or RetryPolicy(
            retries=DEFAULT_RETRY_POLICY.retries,
            backoff=DEFAULT_RETRY_POLICY.backoff,
            request_delay=DEFAULT_RETRY_POLICY.request_delay,
            retry_statuses=set(DEFAULT_RETRY_POLICY.retry_statuses),
        )
        self.proxy_pool = ProxyPool(proxies)
        self.timeout = int(timeout)
        self.image_concurrency = max(1, int(image_concurrency))
        self.proxy_images = bool(proxy_images)
        self._throttle = AsyncThrottle(self.policy.request_delay)

    def set_policy(self, retries: int, backoff: float, request_delay: float) -> None:
        self.policy = RetryPolicy(
            retries=retries,
            backoff=backoff,
            request_delay=request_delay,
            retry_statuses=set(self.policy.retry_statuses),
        )
        self._throttle.update_delay(self.policy.request_delay)

    def set_proxy_pool(self, proxies: List[str]) -> None:
        self.proxy_pool.set(proxies)

    def set_proxy_images(self, enabled: bool) -> None:
        self.proxy_images = bool(enabled)

    async def fetch_mod(
        self,
        item_id: str,
        *,
        timeout: int | None = None,
        proxy: str | None = None,
        session: aiohttp.ClientSession | None = None,
        language: str | None = None,
    ) -> SteamMod | None:
        url = f"https://steamcommunity.com/sharedfiles/filedetails/?id={item_id}&requireditems=1"
        if language:
            url = f"{url}&l={language}"
        timeout_value = self._coerce_timeout(timeout)
        close_session = False
        if session is None:
            timeout_cfg = aiohttp.ClientTimeout(total=timeout_value)
            session = aiohttp.ClientSession(timeout=timeout_cfg)
            close_session = True

        html_text: str | None = None
        attempts = self.policy.retries + 1
        last_exc: Exception | None = None
        last_proxy: str | None = None
        try:
            for attempt in range(1, attempts + 1):
                chosen_proxy = proxy if proxy is not None else self.proxy_pool.next()
                last_proxy = chosen_proxy
                await self._throttle.wait()
                try:
                    async with session.get(
                        url,
                        headers={"User-Agent": "Mozilla/5.0"},
                        proxy=chosen_proxy,
                        timeout=timeout_value,
                    ) as response:
                        if response.status in self.policy.retry_statuses and attempt < attempts:
                            retry_after = response.headers.get("retry-after")
                            if retry_after:
                                try:
                                    await asyncio.sleep(float(retry_after))
                                except ValueError:
                                    pass
                            await self._sleep_backoff(
                                attempt,
                                RuntimeError(f"HTTP {response.status}"),
                                url=url,
                                proxy=chosen_proxy,
                            )
                            continue
                        if response.status != 200:
                            logging.warning(
                                "Steam page fetch failed for %s: HTTP %s",
                                item_id,
                                response.status,
                            )
                            return None
                        html_text = await response.text()
                        break
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    last_exc = exc
                    if chosen_proxy and is_dns_error(exc) and attempt < attempts:
                        logging.warning(
                            "Steam proxy DNS error for url=%s via %s: %s",
                            url,
                            mask_proxy(chosen_proxy),
                            exc,
                        )
                    if attempt >= attempts:
                        if chosen_proxy and is_dns_error(exc):
                            logging.warning(
                                "Steam page fetch failed for %s url=%s via %s: %s",
                                item_id,
                                url,
                                mask_proxy(chosen_proxy),
                                exc,
                            )
                        else:
                            logging.warning(
                                "Steam page fetch failed for %s: %s", item_id, exc
                            )
                        return None
                    await self._sleep_backoff(
                        attempt,
                        exc,
                        url=url,
                        proxy=chosen_proxy,
                    )
                    continue
        finally:
            if close_session and session is not None:
                await session.close()
        if html_text is None:
            if last_exc:
                if last_proxy and is_dns_error(last_exc):
                    logging.warning(
                        "Steam page fetch failed for %s url=%s via %s: %s",
                        item_id,
                        url,
                        mask_proxy(last_proxy),
                        last_exc,
                    )
                else:
                    logging.warning(
                        "Steam page fetch failed for %s: %s", item_id, last_exc
                    )
            return None
        return SteamMod.from_html(str(item_id), html_text)

    async def fetch_mods(
        self,
        item_ids: List[str],
        *,
        timeout: int | None = None,
        language: str | None = None,
    ) -> dict[str, SteamMod]:
        if not item_ids:
            return {}
        timeout_value = self._coerce_timeout(timeout)
        timeout_cfg = aiohttp.ClientTimeout(total=timeout_value)
        results: dict[str, SteamMod] = {}
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            for item_id in item_ids:
                mod = await self.fetch_mod(
                    item_id,
                    timeout=timeout_value,
                    session=session,
                    language=language,
                )
                if mod is None:
                    logging.warning("Steam page parse failed for %s", item_id)
                    continue
                results[str(item_id)] = mod
        return results

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
        timeout_value = self._coerce_timeout(timeout)
        concurrency = (
            self.image_concurrency if max_concurrency is None else int(max_concurrency)
        )
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
                    attempts = self.policy.retries + 1
                    last_exc: Exception | None = None
                    last_proxy: str | None = None
                    for attempt in range(1, attempts + 1):
                        if proxy is not None:
                            chosen_proxy = proxy
                        elif self.proxy_images:
                            chosen_proxy = self.proxy_pool.next()
                        else:
                            chosen_proxy = None
                        last_proxy = chosen_proxy
                        await self._throttle.wait()
                        try:
                            async with session.get(
                                url,
                                headers={"User-Agent": "Mozilla/5.0"},
                                proxy=chosen_proxy,
                                timeout=timeout_value,
                            ) as response:
                                if (
                                    response.status in self.policy.retry_statuses
                                    and attempt < attempts
                                ):
                                    retry_after = response.headers.get("retry-after")
                                    if retry_after:
                                        try:
                                            await asyncio.sleep(float(retry_after))
                                        except ValueError:
                                            pass
                                    await self._sleep_backoff(
                                        attempt,
                                        RuntimeError(f"HTTP {response.status}"),
                                        url=url,
                                        proxy=chosen_proxy,
                                    )
                                    continue
                                if response.status != 200:
                                    logging.warning(
                                        "Steam image fetch failed for %s: HTTP %s",
                                        url,
                                        response.status,
                                    )
                                    return None
                                ext = extension_from_headers(response.headers) or ".bin"
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
                        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                            last_exc = exc
                            if chosen_proxy and is_dns_error(exc) and attempt < attempts:
                                logging.warning(
                                    "Steam proxy DNS error for %s via %s: %s",
                                    url,
                                    mask_proxy(chosen_proxy),
                                    exc,
                                )
                            if attempt >= attempts:
                                if chosen_proxy and is_dns_error(exc):
                                    logging.warning(
                                        "Steam image fetch failed for %s via %s: %s",
                                        url,
                                        mask_proxy(chosen_proxy),
                                        exc,
                                    )
                                else:
                                    logging.warning(
                                        "Steam image fetch failed for %s: %s", url, exc
                                    )
                                return None
                            await self._sleep_backoff(
                                attempt,
                                exc,
                                url=url,
                                proxy=chosen_proxy,
                            )
                            continue
                    if last_exc:
                        if last_proxy and is_dns_error(last_exc):
                            logging.warning(
                                "Steam image fetch failed for %s via %s: %s",
                                url,
                                mask_proxy(last_proxy),
                                last_exc,
                            )
                        else:
                            logging.warning(
                                "Steam image fetch failed for %s: %s", url, last_exc
                            )
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

    def _coerce_timeout(self, timeout: int | None) -> int:
        if timeout is None:
            return int(self.timeout)
        return int(timeout)

    async def _sleep_backoff(
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
        await asyncio.sleep(delay)


_DEFAULT_CLIENT = SteamWorkshopClient()


def set_steam_mod_proxy_pool(proxies: List[str]) -> None:
    _DEFAULT_CLIENT.set_proxy_pool(proxies)


def set_steam_mod_proxy_images(enabled: bool) -> None:
    _DEFAULT_CLIENT.set_proxy_images(enabled)


def set_steam_mod_request_policy(retries: int, backoff: float, request_delay: float) -> None:
    _DEFAULT_CLIENT.set_policy(retries, backoff, request_delay)


def _clean_text(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value).strip()


def _clean_description(value: str | None) -> str:
    if not value:
        return ""
    return html_to_bbcode(value)


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
