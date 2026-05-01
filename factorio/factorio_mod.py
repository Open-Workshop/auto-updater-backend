from __future__ import annotations

import asyncio
import hashlib
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

import aiohttp
import requests

from core.log_tags import tagged_logger
from core.utils import ensure_dir, extension_from_headers
from sync.state import SourceDependency, SourceModProtocol


FACTORIO_API_BASE = "https://mods.factorio.com/api"
FACTORIO_STORAGE_BASE = "https://mods-storage.re146.dev"
FACTORIO_CATALOG_VERSION = "2.0"
FACTORIO_CATALOG_PAGE_SIZE = 50
DEFAULT_TIMEOUT = 20
DEFAULT_IMAGE_CONCURRENCY = 6
DEFAULT_RETRIES = 2
DEFAULT_RETRY_BACKOFF = 1.0
DEFAULT_REQUEST_DELAY = 0.0
_RESERVED_DEPENDENCIES = {
    "base",
    "core",
    "space-age",
    "quality",
    "elevated-rails",
}

FACTORIO_LOG = tagged_logger("parser")


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


def _absolute_asset_url(url: str | None) -> str:
    rendered = str(url or "").strip()
    if not rendered:
        return ""
    parsed = urlparse(rendered)
    if parsed.scheme and parsed.netloc:
        return rendered
    return urljoin("https://assets-mod.factorio.com/", rendered.lstrip("/"))


def _clean_text(value: Any) -> str:
    rendered = str(value or "").strip()
    if not rendered:
        return ""
    return re.sub(r"\s+", " ", rendered)


def _clean_markdown_text(value: Any) -> str:
    rendered = str(value or "")
    if not rendered:
        return ""
    return rendered.replace("\r\n", "\n").replace("\r", "\n").strip()


def _dedupe_keep_order(values: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for value in values:
        rendered = str(value or "").strip()
        if not rendered or rendered in seen:
            continue
        seen.add(rendered)
        result.append(value)
    return result


def _parse_iso_datetime(value: Any) -> tuple[str, int]:
    rendered = _clean_text(value)
    if not rendered:
        return "", 0
    normalized = rendered.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return rendered, 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return rendered, int(dt.timestamp())


def _parse_dependency_entry(value: Any) -> tuple[SourceDependency | None, str | None]:
    rendered = _clean_text(value)
    if not rendered:
        return None, None
    match = re.match(
        r"^(?P<prefix>\(\?\)|[!?~])?\s*(?P<name>[A-Za-z0-9_-]+)",
        rendered,
    )
    if not match:
        return None, None
    prefix = str(match.group("prefix") or "")
    name = str(match.group("name") or "").strip()
    if not name or name in _RESERVED_DEPENDENCIES:
        return None, None
    if prefix == "!":
        return None, name
    if prefix in {"?", "(?)", "~"}:
        return SourceDependency(name, optional=True), None
    if prefix:
        return None, None
    return SourceDependency(name, optional=False), None


def _parse_dependencies(values: Any) -> tuple[list[SourceDependency], list[str]]:
    if not isinstance(values, list):
        return [], []
    dependencies: list[SourceDependency] = []
    conflicts: list[str] = []
    for value in values:
        dep_name, conflict_name = _parse_dependency_entry(value)
        if dep_name:
            dependencies.append(dep_name)
        if conflict_name:
            conflicts.append(conflict_name)
    return _dedupe_keep_order(dependencies), _dedupe_keep_order(conflicts)


def _version_from_release(release: Dict[str, Any] | None) -> str:
    if not isinstance(release, dict):
        return ""
    return _clean_text(release.get("version"))


def _latest_release(payload: Dict[str, Any]) -> Dict[str, Any] | None:
    releases = payload.get("releases")
    if not isinstance(releases, list) or not releases:
        return None
    latest = releases[0]
    if isinstance(latest, dict):
        return latest
    return None


def list_factorio_mod_names(
    page: int,
    page_size: int = FACTORIO_CATALOG_PAGE_SIZE,
    *,
    version: str = FACTORIO_CATALOG_VERSION,
    hide_deprecated: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[str]:
    params = {
        "page_size": max(1, int(page_size)),
        "page": max(1, int(page)),
        "sort": "updated_at",
        "sort_order": "desc",
        "version": version,
        "hide_deprecated": "true" if hide_deprecated else "false",
    }
    response = requests.get(
        f"{FACTORIO_API_BASE}/mods",
        params=params,
        headers={"User-Agent": "openworkshop-mirror/2.0"},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    names: list[str] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        name = _clean_text(item.get("name"))
        if name:
            names.append(name)
    return names


def download_factorio_mod_archive(
    mod_name: str,
    version: str,
    target_path: Path,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    retry_backoff: float = DEFAULT_RETRY_BACKOFF,
) -> Path | None:
    mod_name = _clean_text(mod_name)
    version = _clean_text(version)
    if not mod_name or not version:
        FACTORIO_LOG.warning(
            "Cannot download Factorio archive: missing mod_name=%s version=%s",
            mod_name,
            version,
        )
        return None
    ensure_dir(target_path.parent)
    archive_url = (
        f"{FACTORIO_STORAGE_BASE}/"
        f"{quote(mod_name, safe='')}/"
        f"{quote(version, safe='')}.zip"
    )
    attempts = max(1, int(retries) + 1)
    for attempt in range(1, attempts + 1):
        response: requests.Response | None = None
        temp_path: Path | None = None
        try:
            response = requests.get(
                archive_url,
                headers={"User-Agent": "openworkshop-mirror/2.0"},
                stream=True,
                timeout=timeout,
            )
            if response.status_code != 200:
                if response.status_code >= 500 and attempt < attempts:
                    FACTORIO_LOG.warning(
                        "Factorio archive request failed for %s (%s): HTTP %s",
                        mod_name,
                        version,
                        response.status_code,
                    )
                    continue
                else:
                    FACTORIO_LOG.warning(
                        "Factorio archive request failed for %s (%s): HTTP %s",
                        mod_name,
                        version,
                        response.status_code,
                    )
                    return None
            else:
                temp_path = target_path.with_suffix(f"{target_path.suffix}.part")
                digest = hashlib.sha256()
                with temp_path.open("wb") as handle:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if not chunk:
                            continue
                        handle.write(chunk)
                        digest.update(chunk)
                temp_path.replace(target_path)
                temp_path = None
                return target_path
        except requests.RequestException as exc:
            if attempt >= attempts:
                FACTORIO_LOG.warning(
                    "Factorio archive download failed for %s (%s): %s",
                    mod_name,
                    version,
                    exc,
                )
                return None
            delay = retry_backoff * (2 ** (attempt - 1))
            FACTORIO_LOG.warning(
                "Retrying Factorio archive download for %s (%s) in %.1fs",
                mod_name,
                version,
                delay,
            )
            time.sleep(delay)
        finally:
            if response is not None:
                response.close()
            if temp_path is not None and temp_path.exists():
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
    return None


@dataclass
class FactorioMod:
    item_id: str
    title: str = ""
    summary: str = ""
    description: str = ""
    git_url: str = ""
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    dependency_items: List[SourceDependency] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    logo: str = ""
    screenshots: List[str] = field(default_factory=list)
    version: str = ""
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
        session: aiohttp.ClientSession | None = None,
        client: FactorioPortalClient | None = None,
    ) -> bool:
        client = client or _DEFAULT_CLIENT
        fetched = await client.fetch_mod(
            self.item_id,
            timeout=timeout,
            session=session,
        )
        if fetched is None:
            return False
        self._apply(fetched)
        return True

    async def download_images(
        self,
        dest_dir: Path,
        targets: List[tuple[str, str, str]],
        *,
        timeout: int | None = None,
        session: aiohttp.ClientSession | None = None,
        max_concurrency: int | None = None,
        client: FactorioPortalClient | None = None,
    ) -> List[tuple[str, str, Path, str]]:
        client = client or _DEFAULT_CLIENT
        return await client.download_images(
            dest_dir,
            targets,
            timeout=timeout,
            session=session,
            max_concurrency=max_concurrency,
        )

    @classmethod
    def from_api_json(cls, item_id: str, payload: Dict[str, Any]) -> "FactorioMod":
        latest = _latest_release(payload) or {}
        info_json = latest.get("info_json") if isinstance(latest, dict) else {}
        if not isinstance(info_json, dict):
            info_json = {}

        title = _clean_text(payload.get("title"))
        summary = _clean_markdown_text(payload.get("summary"))
        description = _clean_markdown_text(payload.get("description"))
        if not description:
            description = summary or title
        if not summary:
            summary = description or title
        git_url = _clean_text(payload.get("source_url")) or _clean_text(payload.get("homepage"))

        category = _clean_text(payload.get("category"))
        tags = _dedupe_keep_order(_clean_text(item) for item in payload.get("tags") or [])
        if category:
            tags = _dedupe_keep_order([category] + tags)

        thumbnail = _absolute_asset_url(payload.get("thumbnail"))
        images_payload = payload.get("images")
        screenshots: list[str] = []
        if isinstance(images_payload, list):
            for image in images_payload:
                if not isinstance(image, dict):
                    continue
                image_url = _absolute_asset_url(image.get("url"))
                if image_url:
                    screenshots.append(image_url)
        logo = thumbnail
        if not logo and screenshots:
            logo = screenshots[0]
            screenshots = screenshots[1:]
        if logo:
            screenshots = [url for url in screenshots if url != logo]
            screenshots = _dedupe_keep_order(screenshots)

        created_at, created_ts = _parse_iso_datetime(payload.get("created_at"))
        updated_at, updated_ts = _parse_iso_datetime(payload.get("updated_at"))
        dependency_items, conflicts = _parse_dependencies(info_json.get("dependencies"))
        dependencies = [item.source_id for item in dependency_items if not item.optional]
        version = _version_from_release(latest)

        return cls(
            item_id=str(item_id),
            title=title,
            summary=summary,
            description=description,
            git_url=git_url,
            tags=tags,
            dependencies=dependencies,
            dependency_items=dependency_items,
            conflicts=conflicts,
            logo=logo,
            screenshots=screenshots,
            version=version,
            created_at=created_at,
            updated_at=updated_at,
            created_ts=created_ts,
            updated_ts=updated_ts,
            page_ok=bool(version or title),
        )

    def _apply(self, other: "FactorioMod") -> None:
        self.title = other.title
        self.summary = other.summary
        self.description = other.description
        self.git_url = other.git_url
        self.tags = list(other.tags)
        self.dependencies = list(other.dependencies)
        self.dependency_items = list(other.dependency_items)
        self.conflicts = list(other.conflicts)
        self.logo = other.logo
        self.screenshots = list(other.screenshots)
        self.version = other.version
        self.created_at = other.created_at
        self.updated_at = other.updated_at
        self.created_ts = other.created_ts
        self.updated_ts = other.updated_ts
        self.page_ok = other.page_ok


class FactorioPortalClient:
    def __init__(
        self,
        *,
        api_base: str = FACTORIO_API_BASE,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        request_delay: float = DEFAULT_REQUEST_DELAY,
        image_concurrency: int = DEFAULT_IMAGE_CONCURRENCY,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.timeout = int(timeout)
        self.retries = max(0, int(retries))
        self.retry_backoff = max(0.0, float(retry_backoff))
        self.image_concurrency = max(1, int(image_concurrency))
        self._throttle = AsyncThrottle(request_delay)

    def _coerce_timeout(self, timeout: int | None) -> int:
        if timeout is None:
            return int(self.timeout)
        return int(timeout)

    @asynccontextmanager
    async def _session_for_request(
        self,
        timeout_value: int,
        session: aiohttp.ClientSession | None,
    ):
        if session is not None:
            yield session
            return
        timeout_cfg = aiohttp.ClientTimeout(total=timeout_value)
        async with aiohttp.ClientSession(timeout=timeout_cfg) as direct_session:
            yield direct_session

    def list_mod_names(
        self,
        page: int,
        page_size: int = FACTORIO_CATALOG_PAGE_SIZE,
        *,
        version: str = FACTORIO_CATALOG_VERSION,
        hide_deprecated: bool = True,
        timeout: int | None = None,
    ) -> list[str]:
        return list_factorio_mod_names(
            page,
            page_size,
            version=version,
            hide_deprecated=hide_deprecated,
            timeout=self._coerce_timeout(timeout),
        )

    async def fetch_mod(
        self,
        item_id: str,
        *,
        timeout: int | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> FactorioMod | None:
        url = f"{self.api_base}/mods/{item_id}/full"
        timeout_value = self._coerce_timeout(timeout)
        attempts = self.retries + 1
        for attempt in range(1, attempts + 1):
            await self._throttle.wait()
            try:
                async with self._session_for_request(timeout_value, session) as active_session:
                    async with active_session.get(
                        url,
                        headers={"User-Agent": "openworkshop-mirror/2.0"},
                        timeout=timeout_value,
                    ) as response:
                        if response.status == 404:
                            FACTORIO_LOG.warning("Factorio mod not found: %s", item_id)
                            return None
                        if response.status != 200:
                            if response.status >= 500 and attempt < attempts:
                                delay = self.retry_backoff * (2 ** (attempt - 1))
                                FACTORIO_LOG.warning(
                                    "Retrying Factorio mod fetch for %s in %.1fs (HTTP %s)",
                                    item_id,
                                    delay,
                                    response.status,
                                )
                                await asyncio.sleep(delay)
                                continue
                            FACTORIO_LOG.warning(
                                "Factorio mod fetch failed for %s: HTTP %s",
                                item_id,
                                response.status,
                            )
                            return None
                        payload = await response.json()
                        if not isinstance(payload, dict):
                            FACTORIO_LOG.warning(
                                "Factorio mod fetch returned non-object payload for %s",
                                item_id,
                            )
                            return None
                        return FactorioMod.from_api_json(str(item_id), payload)
            except (
                aiohttp.ClientError,
                asyncio.TimeoutError,
                asyncio.IncompleteReadError,
            ) as exc:
                if attempt >= attempts:
                    FACTORIO_LOG.warning("Factorio mod fetch failed for %s: %s", item_id, exc)
                    return None
                delay = self.retry_backoff * (2 ** (attempt - 1))
                FACTORIO_LOG.warning(
                    "Retrying Factorio mod fetch for %s in %.1fs after %s",
                    item_id,
                    delay,
                    type(exc).__name__,
                )
                await asyncio.sleep(delay)
        return None

    async def download_images(
        self,
        dest_dir: Path,
        targets: List[tuple[str, str, str]],
        *,
        timeout: int | None = None,
        session: aiohttp.ClientSession | None = None,
        max_concurrency: int | None = None,
    ) -> List[tuple[str, str, Path, str]]:
        if not targets:
            return []
        ensure_dir(dest_dir)
        timeout_value = self._coerce_timeout(timeout)
        concurrency = (
            self.image_concurrency if max_concurrency is None else int(max_concurrency)
        )
        concurrency = max(1, concurrency)
        semaphore = asyncio.Semaphore(concurrency)

        async def fetch_one(target: tuple[str, str, str]) -> tuple[str, str, Path, str] | None:
            res_type, url, basename = target
            if not url:
                return None
            async with semaphore:
                attempts = self.retries + 1
                for attempt in range(1, attempts + 1):
                    temp_path: Path | None = None
                    await self._throttle.wait()
                    try:
                        async with self._session_for_request(timeout_value, session) as active_session:
                            async with active_session.get(
                                url,
                                headers={"User-Agent": "openworkshop-mirror/2.0"},
                                timeout=timeout_value,
                            ) as response:
                                if response.status != 200:
                                    if response.status >= 500 and attempt < attempts:
                                        delay = self.retry_backoff * (2 ** (attempt - 1))
                                        FACTORIO_LOG.warning(
                                            "Retrying Factorio image fetch for %s in %.1fs (HTTP %s)",
                                            url,
                                            delay,
                                            response.status,
                                        )
                                        await asyncio.sleep(delay)
                                        continue
                                    FACTORIO_LOG.warning(
                                        "Factorio image fetch failed for %s: HTTP %s",
                                        url,
                                        response.status,
                                    )
                                    return None
                                ext = extension_from_headers(response.headers)
                                if not ext:
                                    ext = Path(urlparse(url).path).suffix or ".bin"
                                path = dest_dir / f"{basename}{ext}"
                                temp_path = path.with_suffix(f"{path.suffix}.part")
                                digest = hashlib.sha256()
                                with temp_path.open("wb") as handle:
                                    async for chunk in response.content.iter_chunked(1024 * 1024):
                                        if not chunk:
                                            continue
                                        handle.write(chunk)
                                        digest.update(chunk)
                                temp_path.replace(path)
                                temp_path = None
                                return (res_type, url, path, digest.hexdigest())
                    except (
                        aiohttp.ClientError,
                        asyncio.TimeoutError,
                        asyncio.IncompleteReadError,
                    ) as exc:
                        if attempt >= attempts:
                            FACTORIO_LOG.warning(
                                "Factorio image fetch failed for %s: %s",
                                url,
                                exc,
                            )
                            return None
                        delay = self.retry_backoff * (2 ** (attempt - 1))
                        FACTORIO_LOG.warning(
                            "Retrying Factorio image fetch for %s in %.1fs after %s",
                            url,
                            delay,
                            type(exc).__name__,
                        )
                        await asyncio.sleep(delay)
                        continue
                    finally:
                        if temp_path is not None and temp_path.exists():
                            try:
                                temp_path.unlink()
                            except FileNotFoundError:
                                pass
                return None

        tasks = [asyncio.create_task(fetch_one(target)) for target in targets]
        results = await asyncio.gather(*tasks)
        return [item for item in results if item is not None]


class FactorioModLoader:
    def __init__(self, timeout: int) -> None:
        self.timeout = int(timeout)
        self.client = FactorioPortalClient(timeout=self.timeout)

    def load_batch(self, item_ids: List[str]) -> Dict[str, SourceModProtocol]:
        if not item_ids:
            return {}
        FACTORIO_LOG.info("Factorio batch load: items=%s", len(item_ids))
        return asyncio.run(self._load_sequential(item_ids))

    async def _load_sequential(self, item_ids: List[str]) -> Dict[str, SourceModProtocol]:
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        results: Dict[str, SourceModProtocol] = {}
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            total = len(item_ids)
            for idx, item_id in enumerate(item_ids, start=1):
                start = time.monotonic()
                FACTORIO_LOG.info("Factorio load %s/%s id=%s", idx, total, item_id)
                mod = await self.client.fetch_mod(
                    str(item_id),
                    timeout=self.timeout,
                    session=session,
                )
                elapsed = time.monotonic() - start
                if mod is None:
                    FACTORIO_LOG.warning(
                        "Factorio page parse failed for %s (%.2fs)",
                        item_id,
                        elapsed,
                    )
                    continue
                FACTORIO_LOG.debug("Factorio page loaded %s (%.2fs)", item_id, elapsed)
                results[str(item_id)] = mod
        return results


_DEFAULT_CLIENT = FactorioPortalClient()
