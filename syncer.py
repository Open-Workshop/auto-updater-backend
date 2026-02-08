from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

import aiohttp
import requests

from PIL import Image, ImageOps
import imagehash

_PHASH_AVAILABLE = True

from ow_api import ApiClient
from steam_api import (
    steam_fetch_workshop_page_ids_html,
    steam_get_app_details,
    steam_stats_reset,
    steam_stats_snapshot,
)
from steam_mod import SteamMod
from steamcmd import download_steam_mod
from utils import (
    dedupe_images,
    ensure_dir,
    has_files,
    strip_bbcode,
    truncate,
    zip_directory,
)


@dataclass(frozen=True)
class SyncOptions:
    page_size: int
    timeout: int
    max_pages: int
    max_items: int
    page_delay: float
    max_screenshots: int
    public_mode: int
    without_author: bool
    sync_tags: bool
    prune_tags: bool
    sync_dependencies: bool
    prune_dependencies: bool
    sync_resources: bool
    prune_resources: bool
    upload_resource_files: bool
    scrape_preview_images: bool
    scrape_required_items: bool
    force_required_item_id: Optional[str]
    language: str


@dataclass
class ModPayload:
    mod: SteamMod
    title: str
    short_desc: str
    description: str
    tags: List[str]
    deps: List[str]
    deps_ok: bool
    images: List[str]
    images_incomplete: bool
    ow_mod_id: Optional[int]
    is_new: bool


PHASH_MAX_DISTANCE = 6


@dataclass(frozen=True)
class ImageHashes:
    sha256: str | None
    phash: str | None


def _phash_from_path(path: Path) -> str | None:
    if not _PHASH_AVAILABLE:
        return None
    try:
        with Image.open(path) as img:
            img = ImageOps.exif_transpose(img)
            img = img.convert("RGB")
            return str(imagehash.phash(img))
    except Exception as exc:
        logging.debug("Failed to compute phash for %s: %s", path, exc)
        return None


def _build_hashes(file_hash: str | None, file_path: Path) -> ImageHashes:
    sha256 = file_hash if file_hash else None
    phash = _phash_from_path(file_path)
    return ImageHashes(sha256=sha256, phash=phash)


def _phash_distance(left: str, right: str) -> Optional[int]:
    if not _PHASH_AVAILABLE:
        return None
    try:
        return imagehash.hex_to_hash(left) - imagehash.hex_to_hash(right)
    except Exception:
        return None


def _hashes_match(left: ImageHashes, right: ImageHashes) -> bool:
    if _PHASH_AVAILABLE and left.phash and right.phash:
        distance = _phash_distance(left.phash, right.phash)
        if distance is not None:
            return distance <= PHASH_MAX_DISTANCE
    if left.sha256 and right.sha256:
        return left.sha256 == right.sha256
    return False


def _hash_matches_any(target: ImageHashes, candidates: Iterable[ImageHashes]) -> bool:
    for candidate in candidates:
        if _hashes_match(target, candidate):
            return True
    return False


class WorkQueue:
    def __init__(self) -> None:
        self.meta_queue: deque[str] = deque()
        self.queued_ids: set[str] = set()
        self.download_queue: deque[str] = deque()
        self.download_queued: set[str] = set()
        self.pending_downloads: Dict[str, ModPayload] = {}

    def enqueue_metadata(self, item_id: str) -> None:
        item_id = str(item_id)
        if item_id in self.queued_ids:
            return
        self.queued_ids.add(item_id)
        self.meta_queue.append(item_id)

    def enqueue_download(self, item_id: str, payload: ModPayload) -> None:
        item_id = str(item_id)
        self.pending_downloads[item_id] = payload
        if item_id in self.download_queued:
            return
        self.download_queued.add(item_id)
        self.download_queue.append(item_id)

    def pop_meta_batch(self, max_size: int) -> List[str]:
        batch: List[str] = []
        while self.meta_queue and len(batch) < max_size:
            batch.append(self.meta_queue.popleft())
        return batch

    def pop_download(self) -> Optional[tuple[str, ModPayload]]:
        if not self.download_queue:
            return None
        item_id = self.download_queue.popleft()
        self.download_queued.discard(item_id)
        payload = self.pending_downloads.pop(item_id, None)
        if payload is None:
            return None
        return item_id, payload

    def has_work(self) -> bool:
        return bool(self.meta_queue or self.download_queue)


class TagManager:
    def __init__(
        self,
        api: ApiClient,
        game_id: int,
        page_size: int,
        *,
        enabled: bool,
        prune: bool,
    ) -> None:
        self.api = api
        self.game_id = game_id
        self.page_size = page_size
        self.enabled = enabled
        self.prune = prune
        self._name_to_id: Dict[str, int] = {}
        self._id_to_name: Dict[int, str] = {}

    def preload(self) -> None:
        if not self.enabled:
            return
        for tag in self.api.list_tags(self.game_id, self.page_size):
            name = tag.get("name") or tag.get("tag_name")
            tag_id = tag.get("id") or tag.get("tag_id")
            if name and tag_id:
                self._name_to_id[str(name).lower()] = int(tag_id)
                self._id_to_name[int(tag_id)] = str(name)

    def sync_mod_tags(self, ow_mod_id: int, tag_names: List[str]) -> None:
        if not self.enabled:
            return
        desired_tag_ids = self._resolve_tag_ids(tag_names)
        current_tag_ids = self.api.get_mod_tags(ow_mod_id)
        missing_tags = [tid for tid in desired_tag_ids if tid not in current_tag_ids]
        extra_tags = [tid for tid in current_tag_ids if tid not in desired_tag_ids]
        if missing_tags or extra_tags:
            logging.debug(
                "OW mod %s tags: current=%s desired=%s add=%s prune=%s",
                ow_mod_id,
                len(current_tag_ids),
                len(desired_tag_ids),
                [self._id_to_name.get(tid, tid) for tid in missing_tags],
                [self._id_to_name.get(tid, tid) for tid in extra_tags],
            )
        for tag_id in desired_tag_ids:
            if tag_id not in current_tag_ids:
                self.api.add_mod_tag(ow_mod_id, tag_id)
        if self.prune:
            for tag_id in current_tag_ids:
                if tag_id not in desired_tag_ids:
                    self.api.delete_mod_tag(ow_mod_id, tag_id)

    def _resolve_tag_ids(self, tag_names: List[str]) -> List[int]:
        desired_tag_ids: List[int] = []
        for tag_name in tag_names:
            key = tag_name.lower()
            tag_id = self._name_to_id.get(key)
            if not tag_id:
                try:
                    tag_id = self.api.add_tag(tag_name)
                except Exception as exc:
                    logging.warning("Failed to add tag %s: %s", tag_name, exc)
                    continue
                self.api.associate_game_tag(self.game_id, tag_id)
                self._name_to_id[key] = tag_id
                self._id_to_name[tag_id] = tag_name
            desired_tag_ids.append(tag_id)
        return desired_tag_ids


class DependencyManager:
    def __init__(
        self,
        api: ApiClient,
        ow_by_source: Dict[str, Dict[str, Any]],
        *,
        enabled: bool,
        prune: bool,
        scrape_required_items: bool,
        enqueue_metadata: Callable[[str], None],
    ) -> None:
        self.api = api
        self.ow_by_source = ow_by_source
        self.enabled = enabled
        self.prune = prune
        self.scrape_required_items = scrape_required_items
        self.enqueue_metadata = enqueue_metadata
        self.pending_dependency_links: Dict[int, Dict[str, Any]] = {}

    def queue_missing_sources(self, dep_source_ids: List[str]) -> None:
        if not self.enabled or not self.scrape_required_items:
            return
        for dep_source_id in dep_source_ids:
            self.enqueue_metadata(str(dep_source_id))

    def sync_dependencies(
        self,
        ow_mod_id: int,
        dep_source_ids: List[str],
        deps_ok: bool,
    ) -> None:
        if not self.enabled or not self.scrape_required_items:
            return
        desired_dep_ids: List[int] = []
        missing_sources: List[str] = []
        for dep_source_id in dep_source_ids:
            dep_source_id = str(dep_source_id)
            dep_mod = self.ow_by_source.get(dep_source_id)
            if dep_mod:
                desired_dep_ids.append(int(dep_mod.get("id")))
            else:
                missing_sources.append(dep_source_id)
                self.enqueue_metadata(dep_source_id)

        current_dep_ids = self.api.get_mod_dependencies(ow_mod_id)
        for dep_id in desired_dep_ids:
            if dep_id not in current_dep_ids:
                self.api.add_mod_dependency(ow_mod_id, dep_id)

        allow_prune = self.prune and deps_ok and not missing_sources
        if allow_prune:
            for dep_id in current_dep_ids:
                if dep_id not in desired_dep_ids:
                    self.api.delete_mod_dependency(ow_mod_id, dep_id)
        elif self.prune and not deps_ok:
            logging.debug(
                "Skip dependency prune for %s due to Steam scrape failure",
                ow_mod_id,
            )

        if missing_sources:
            self.pending_dependency_links[ow_mod_id] = {
                "deps": dep_source_ids,
                "deps_ok": deps_ok,
            }

    def retry_pending(self) -> None:
        if not self.pending_dependency_links:
            return
        for ow_mod_id, info in list(self.pending_dependency_links.items()):
            dep_source_ids = [str(dep) for dep in info.get("deps", [])]
            deps_ok = bool(info.get("deps_ok", True))
            desired_dep_ids: List[int] = []
            missing_sources: List[str] = []
            for dep_source_id in dep_source_ids:
                dep_mod = self.ow_by_source.get(dep_source_id)
                if dep_mod:
                    desired_dep_ids.append(int(dep_mod.get("id")))
                else:
                    missing_sources.append(dep_source_id)
            current_dep_ids = self.api.get_mod_dependencies(ow_mod_id)
            for dep_id in desired_dep_ids:
                if dep_id not in current_dep_ids:
                    self.api.add_mod_dependency(ow_mod_id, dep_id)
            if self.prune and deps_ok and not missing_sources:
                for dep_id in current_dep_ids:
                    if dep_id not in desired_dep_ids:
                        self.api.delete_mod_dependency(ow_mod_id, dep_id)
            if not missing_sources:
                self.pending_dependency_links.pop(ow_mod_id, None)


class ResourceSyncer:
    def __init__(
        self,
        api: ApiClient,
        mirror_root: Path,
        *,
        timeout: int,
        enabled: bool,
        prune: bool,
        upload_files: bool,
    ) -> None:
        self.api = api
        self.mirror_root = mirror_root
        self.timeout = int(timeout)
        self.enabled = enabled
        self.prune = prune
        self.upload_files = upload_files

    def sync_resources(
        self,
        ow_mod_id: int,
        mod: SteamMod,
        images: List[str],
        images_incomplete: bool,
    ) -> None:
        if not self.enabled or not images:
            return
        current_resources = self.api.get_mod_resources(ow_mod_id)
        if self.upload_files:
            self._sync_resource_files(
                ow_mod_id,
                mod,
                images,
                images_incomplete,
                current_resources,
            )
        else:
            self._sync_resource_urls(
                ow_mod_id,
                images,
                images_incomplete,
                current_resources,
            )

    def _sync_resource_urls(
        self,
        ow_mod_id: int,
        images: List[str],
        images_incomplete: bool,
        current_resources: List[Dict[str, Any]],
    ) -> None:
        current_urls = {
            (r.get("type"), r.get("url")): r.get("id") for r in current_resources
        }
        desired_resources = self._build_desired_resources(images)
        for res_type, url in desired_resources:
            if (res_type, url) not in current_urls:
                self.api.add_resource("mods", ow_mod_id, res_type, url)

        if self.prune and images_incomplete:
            logging.debug(
                "Skip resource prune for %s due to missing image cache",
                ow_mod_id,
            )
        elif self.prune:
            desired_set = set(desired_resources)
            for (res_type, url), res_id in current_urls.items():
                if (res_type, url) not in desired_set:
                    if res_id is not None:
                        self.api.delete_resource(int(res_id))

    def _sync_resource_files(
        self,
        ow_mod_id: int,
        mod: SteamMod,
        images: List[str],
        images_incomplete: bool,
        current_resources: List[Dict[str, Any]],
    ) -> None:
        dest_dir = self.mirror_root / "resources" / str(mod.item_id)
        hashes_by_id, hash_cache = self._build_resource_hashes(
            mod, current_resources, dest_dir
        )
        cache_path = dest_dir / "resource_hashes.json"
        cached_resources = hash_cache.get("resources", {})

        deleted_ids = self._prune_duplicate_resources(current_resources, hashes_by_id)
        if deleted_ids:
            for res_id in deleted_ids:
                hashes_by_id.pop(res_id, None)
                if isinstance(cached_resources, dict):
                    cached_resources.pop(str(res_id), None)
            self._save_hash_cache(cache_path, hash_cache)

        existing_hashes: List[ImageHashes] = []
        existing_logo_hashes: List[ImageHashes] = []
        existing_sha256: set[str] = set()
        existing_logo_sha256: set[str] = set()
        sha256_to_resources: Dict[str, List[Dict[str, Any]]] = {}
        for resource in current_resources:
            res_id = resource.get("id")
            if res_id is None or int(res_id) in deleted_ids:
                continue
            hashes = hashes_by_id.get(int(res_id))
            if not hashes:
                continue
            existing_hashes.append(hashes)
            if resource.get("type") == "logo":
                existing_logo_hashes.append(hashes)
            if hashes.sha256:
                existing_sha256.add(hashes.sha256)
                if resource.get("type") == "logo":
                    existing_logo_sha256.add(hashes.sha256)
                sha256_to_resources.setdefault(hashes.sha256, []).append(resource)

        targets = self._build_image_targets(images)

        desired_hashes: List[ImageHashes] = []
        downloaded_count = 0
        if targets:
            downloads = self._download_steam_images(mod, targets, dest_dir)
            downloaded_count = len(downloads)
            seen_sha256: set[str] = set()
            for res_type, _, file_path, file_hash in downloads:
                hashes = _build_hashes(file_hash, file_path)
                if hashes.sha256 and hashes.sha256 in seen_sha256:
                    continue
                if hashes.sha256:
                    seen_sha256.add(hashes.sha256)
                desired_hashes.append(hashes)

                if res_type == "logo":
                    if _hash_matches_any(hashes, existing_logo_hashes):
                        continue
                else:
                    if _hash_matches_any(hashes, existing_hashes):
                        continue

                if self.api.add_resource_file(
                    "mods", ow_mod_id, res_type, file_path
                ):
                    if (
                        res_type == "logo"
                        and hashes.sha256
                        and hashes.sha256 in existing_sha256
                        and hashes.sha256 not in existing_logo_sha256
                    ):
                        for resource in sha256_to_resources.get(hashes.sha256, []):
                            res_id = resource.get("id")
                            if res_id is None:
                                continue
                            self.api.delete_resource(int(res_id))
                            deleted_ids.add(int(res_id))
                            hashes_by_id.pop(int(res_id), None)
                            if isinstance(cached_resources, dict):
                                cached_resources.pop(str(res_id), None)
                        self._save_hash_cache(cache_path, hash_cache)
                    existing_hashes.append(hashes)
                    if res_type == "logo":
                        existing_logo_hashes.append(hashes)
                    if hashes.sha256:
                        existing_sha256.add(hashes.sha256)
                        if res_type == "logo":
                            existing_logo_sha256.add(hashes.sha256)

        if self.prune and images_incomplete:
            logging.debug(
                "Skip resource prune for %s due to missing image cache",
                mod.item_id,
            )
        elif self.prune and desired_hashes and downloaded_count == len(targets):
            for resource in current_resources:
                res_id = resource.get("id")
                if res_id is None or int(res_id) in deleted_ids:
                    continue
                hashes = hashes_by_id.get(int(res_id))
                if not hashes or _hash_matches_any(hashes, desired_hashes):
                    continue
                self.api.delete_resource(int(res_id))
                if isinstance(cached_resources, dict):
                    cached_resources.pop(str(res_id), None)
            self._save_hash_cache(cache_path, hash_cache)

    def _download_steam_images(
        self,
        mod: SteamMod,
        targets: List[tuple[str, str, str]],
        dest_dir: Path,
    ) -> List[tuple[str, str, Path, str]]:
        if not targets:
            return []
        return asyncio.run(
            mod.download_images(
                dest_dir,
                targets,
                timeout=self.timeout,
            )
        )

    def _build_resource_hashes(
        self,
        mod: SteamMod,
        resources: List[Dict[str, Any]],
        dest_dir: Path,
    ) -> tuple[Dict[int, ImageHashes], Dict[str, Any]]:
        cache_path = dest_dir / "resource_hashes.json"
        cache = self._load_hash_cache(cache_path)
        cached_resources = cache.get("resources")
        if not isinstance(cached_resources, dict):
            cached_resources = {}
            cache["resources"] = cached_resources

        valid_ids = {
            str(res_id)
            for res_id in (r.get("id") for r in resources)
            if res_id is not None
        }
        for cached_id in list(cached_resources.keys()):
            if cached_id not in valid_ids:
                cached_resources.pop(cached_id, None)

        hashes_by_id: Dict[int, ImageHashes] = {}
        url_to_ids: Dict[str, List[int]] = {}
        for resource in resources:
            res_id = resource.get("id")
            url = resource.get("url") or ""
            if res_id is None or not url:
                continue
            cached_entry = cached_resources.get(str(res_id))
            if isinstance(cached_entry, dict) and cached_entry.get("url") == url:
                cached_sha256 = cached_entry.get("sha256") or cached_entry.get("hash")
                cached_phash = cached_entry.get("phash")
                if cached_sha256 or cached_phash:
                    if _PHASH_AVAILABLE and not cached_phash:
                        url_to_ids.setdefault(url, []).append(int(res_id))
                    else:
                        hashes_by_id[int(res_id)] = ImageHashes(
                            sha256=str(cached_sha256) if cached_sha256 else None,
                            phash=str(cached_phash) if cached_phash else None,
                        )
                    continue
            url_to_ids.setdefault(url, []).append(int(res_id))

        if url_to_ids:
            self._prune_missing_resource_urls(url_to_ids, cached_resources)

        if url_to_ids:
            targets: List[tuple[str, str, str]] = []
            for idx, url in enumerate(url_to_ids.keys()):
                targets.append(("existing", url, f"existing_{idx}"))
            downloads = self._download_steam_images(mod, targets, dest_dir)
            for _, url, file_path, file_hash in downloads:
                if not file_hash and not _PHASH_AVAILABLE:
                    continue
                hashes = _build_hashes(file_hash, file_path)
                for res_id in url_to_ids.get(url, []):
                    hashes_by_id[res_id] = hashes
                    cached_resources[str(res_id)] = {
                        "url": url,
                        "sha256": hashes.sha256,
                        "phash": hashes.phash,
                    }
                try:
                    file_path.unlink()
                except FileNotFoundError:
                    pass
                except Exception:
                    logging.debug("Failed to remove hash temp %s", file_path)

        self._save_hash_cache(cache_path, cache)
        return hashes_by_id, cache

    def _prune_missing_resource_urls(
        self,
        url_to_ids: Dict[str, List[int]],
        cached_resources: Dict[str, Any],
    ) -> None:
        if not url_to_ids:
            return
        for url, res_ids in list(url_to_ids.items()):
            status = self._head_status(url)
            if status != 404:
                continue
            logging.warning("Deleting OW resource(s) with missing URL: %s", url)
            for res_id in res_ids:
                self.api.delete_resource(int(res_id))
                if isinstance(cached_resources, dict):
                    cached_resources.pop(str(res_id), None)
            url_to_ids.pop(url, None)

    def _head_status(self, url: str) -> int | None:
        try:
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            logging.debug("Failed to probe resource %s: %s", url, exc)
            return None
        try:
            return int(response.status_code)
        finally:
            response.close()

    def _prune_duplicate_resources(
        self,
        resources: List[Dict[str, Any]],
        hashes_by_id: Dict[int, ImageHashes],
    ) -> set[int]:
        by_hash: Dict[str, List[Dict[str, Any]]] = {}
        for resource in resources:
            res_id = resource.get("id")
            if res_id is None:
                continue
            hashes = hashes_by_id.get(int(res_id))
            if not hashes:
                continue
            key = hashes.sha256 or hashes.phash
            if not key:
                continue
            by_hash.setdefault(key, []).append(resource)

        deleted_ids: set[int] = set()
        for _, group in by_hash.items():
            if len(group) <= 1:
                continue
            keep = None
            for resource in group:
                if resource.get("type") == "logo":
                    keep = resource
                    break
            if keep is None:
                keep = group[0]
            for resource in group:
                if resource is keep:
                    continue
                res_id = resource.get("id")
                if res_id is None:
                    continue
                self.api.delete_resource(int(res_id))
                deleted_ids.add(int(res_id))
        return deleted_ids

    @staticmethod
    def _load_hash_cache(path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {"version": 1, "resources": {}}
        try:
            payload = json.loads(path.read_text("utf-8"))
        except Exception:
            return {"version": 1, "resources": {}}
        if not isinstance(payload, dict):
            return {"version": 1, "resources": {}}
        resources = payload.get("resources")
        if not isinstance(resources, dict):
            payload["resources"] = {}
        if "version" not in payload:
            payload["version"] = 1
        return payload

    @staticmethod
    def _save_hash_cache(path: Path, cache: Dict[str, Any]) -> None:
        ensure_dir(path.parent)
        try:
            path.write_text(json.dumps(cache, ensure_ascii=True, indent=2), "utf-8")
        except Exception as exc:
            logging.warning("Failed to write hash cache %s: %s", path, exc)

    @staticmethod
    def _build_desired_resources(images: List[str]) -> List[tuple[str, str]]:
        desired: List[tuple[str, str]] = []
        for idx_img, url in enumerate(images):
            res_type = "logo" if idx_img == 0 else "screenshot"
            desired.append((res_type, url))
        return desired

    @staticmethod
    def _build_image_targets(images: List[str]) -> List[tuple[str, str, str]]:
        targets: List[tuple[str, str, str]] = []
        for idx_img, url in enumerate(images):
            res_type = "logo" if idx_img == 0 else "screenshot"
            basename = "logo" if idx_img == 0 else f"{idx_img}"
            targets.append((res_type, url, basename))
        return targets


class SteamModLoader:
    def __init__(self, timeout: int, language: str) -> None:
        self.timeout = int(timeout)
        self.language = language

    def load_batch(self, item_ids: List[str]) -> Dict[str, SteamMod]:
        if not item_ids:
            return {}
        logging.info("Steam batch load: items=%s", len(item_ids))
        return asyncio.run(self._load_sequential(item_ids))

    async def _load_sequential(self, item_ids: List[str]) -> Dict[str, SteamMod]:
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        results: Dict[str, SteamMod] = {}
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            total = len(item_ids)
            for idx, item_id in enumerate(item_ids, start=1):
                start = time.monotonic()
                logging.info("Steam load %s/%s id=%s", idx, total, item_id)
                mod = SteamMod(item_id)
                ok = await mod.load(
                    timeout=self.timeout,
                    session=session,
                    language=self.language,
                )
                elapsed = time.monotonic() - start
                if not ok:
                    logging.warning(
                        "Steam page parse failed for %s (%.2fs)", item_id, elapsed
                    )
                    continue
                logging.debug("Steam page loaded %s (%.2fs)", item_id, elapsed)
                results[str(item_id)] = mod
        return results


class ModSyncer:
    def __init__(
        self,
        api: ApiClient,
        steam_app_id: int,
        game_id: int,
        mirror_root: Path,
        steam_root: Path,
        steamcmd_path: Path,
        options: SyncOptions,
    ) -> None:
        self.api = api
        self.steam_app_id = steam_app_id
        self.game_id = game_id
        self.mirror_root = mirror_root
        self.steam_root = steam_root
        self.steamcmd_path = steamcmd_path
        self.options = options

        self.queue = WorkQueue()
        self.page = 1
        self.listed_count = 0
        self.ow_by_source: Dict[str, Dict[str, Any]] = {}
        self.steam_mod_cache: Dict[str, SteamMod] = {}
        self.tag_manager = TagManager(
            api,
            game_id,
            options.page_size,
            enabled=options.sync_tags,
            prune=options.prune_tags,
        )
        self.dependency_manager = DependencyManager(
            api,
            self.ow_by_source,
            enabled=options.sync_dependencies,
            prune=options.prune_dependencies,
            scrape_required_items=options.scrape_required_items,
            enqueue_metadata=self.queue.enqueue_metadata,
        )
        self.resource_syncer = ResourceSyncer(
            api,
            mirror_root,
            timeout=options.timeout,
            enabled=options.sync_resources,
            prune=options.prune_resources,
            upload_files=options.upload_resource_files,
        )
        self.mod_loader = SteamModLoader(options.timeout, options.language)

    def run(self) -> None:
        steam_stats_reset()
        self._load_existing_mods()
        self.tag_manager.preload()

        if self.options.force_required_item_id:
            self.queue.enqueue_metadata(str(self.options.force_required_item_id))
            logging.info("Steam workshop items: 1 (forced)")
        else:
            logging.info(
                "Steam workshop listing: max_items=%s max_pages=%s",
                self.options.max_items or "unlimited",
                self.options.max_pages or "unlimited",
            )

        while True:
            if not self.queue.has_work():
                if self.options.force_required_item_id:
                    break
                if self.options.max_items > 0 and self.listed_count >= self.options.max_items:
                    break
                if not self._fetch_next_page():
                    break
                if not self.queue.meta_queue:
                    continue

            if self.queue.meta_queue:
                self._process_metadata_batch()
                continue

            download_item = self.queue.pop_download()
            if download_item:
                item_id, payload = download_item
                self._process_download_item(item_id, payload)
                continue

        stats = steam_stats_snapshot()
        if stats.get("total"):
            logging.info(
                "Steam requests: total=%s ok=%s failed=%s endpoints=%s",
                stats.get("total"),
                stats.get("success"),
                stats.get("failed"),
                stats.get("by_endpoint"),
            )

    def _load_existing_mods(self) -> None:
        ow_mods = self.api.list_mods(self.game_id, self.options.page_size)
        for mod in ow_mods:
            source_id = mod.get("source_id")
            if source_id is not None:
                self.ow_by_source[str(source_id)] = mod

    def _fetch_next_page(self) -> bool:
        if self.options.max_pages > 0 and self.page > self.options.max_pages:
            return False
        logging.info(
            "Steam workshop page fetch: page=%s max_pages=%s",
            self.page,
            self.options.max_pages or "unlimited",
        )
        page_ids = steam_fetch_workshop_page_ids_html(
            self.steam_app_id,
            self.page,
            self.options.language,
            self.options.timeout,
        )
        if not page_ids:
            return False
        for item_id in page_ids:
            if self.options.max_items > 0 and self.listed_count >= self.options.max_items:
                break
            self.queue.enqueue_metadata(str(item_id))
            self.listed_count += 1
        self.page += 1
        if self.options.page_delay > 0:
            time.sleep(self.options.page_delay)
        return True

    def _process_metadata_batch(self) -> None:
        batch_ids = self.queue.pop_meta_batch(30)
        if not batch_ids:
            return
        logging.info("Process metadata batch: size=%s", len(batch_ids))
        mod_map = self.mod_loader.load_batch(batch_ids)
        self.steam_mod_cache.update(mod_map)

        for workshop_id in batch_ids:
            mod = self.steam_mod_cache.get(str(workshop_id))
            if not mod:
                logging.warning("Steam page missing for %s", workshop_id)
                continue
            payload = self._build_payload(mod, workshop_id)
            if payload is None:
                continue
            if self._needs_file_update(mod, payload.ow_mod_id):
                logging.info(
                    "Queue download for %s (new=%s)",
                    workshop_id,
                    payload.ow_mod_id is None,
                )
                self.queue.enqueue_download(str(workshop_id), payload)
                continue

            if payload.ow_mod_id is None:
                continue

            logging.info("Updating OW mod %s metadata", payload.ow_mod_id)
            self.api.edit_mod(
                payload.ow_mod_id,
                payload.title,
                payload.short_desc,
                payload.description,
                "steam",
                int(workshop_id),
                self.game_id,
                self.options.public_mode,
                set_source=False,
            )
            self.tag_manager.sync_mod_tags(payload.ow_mod_id, payload.tags)
            self.dependency_manager.sync_dependencies(
                payload.ow_mod_id,
                payload.deps,
                payload.deps_ok,
            )
            self.resource_syncer.sync_resources(
                payload.ow_mod_id,
                mod,
                payload.images,
                payload.images_incomplete,
            )

    def _process_download_item(self, item_id: str, payload: ModPayload) -> None:
        logging.info(
            "Downloading Steam mod %s (new=%s)",
            item_id,
            payload.is_new,
        )
        archive_path = self._download_mod_archive(item_id)
        if not archive_path:
            logging.warning("Steam download failed for %s", item_id)
            return

        ow_mod_id = payload.ow_mod_id
        if payload.is_new:
            logging.info("Creating OW mod for %s", item_id)
            mod_id = self.api.add_mod(
                payload.title,
                payload.short_desc,
                payload.description,
                "steam",
                int(item_id),
                self.game_id,
                self.options.public_mode,
                self.options.without_author,
                archive_path,
            )
            self.ow_by_source[str(item_id)] = {
                "id": mod_id,
                "source_id": int(item_id),
                "date_update_file": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
            }
            ow_mod_id = mod_id
        else:
            logging.info("Updating OW mod %s file", ow_mod_id)
            self.api.edit_mod(
                int(ow_mod_id),
                payload.title,
                payload.short_desc,
                payload.description,
                "steam",
                int(item_id),
                self.game_id,
                self.options.public_mode,
                archive_path,
                set_source=False,
            )

        if ow_mod_id is None:
            return

        self.tag_manager.sync_mod_tags(int(ow_mod_id), payload.tags)
        self.dependency_manager.sync_dependencies(
            int(ow_mod_id),
            payload.deps,
            payload.deps_ok,
        )
        self.resource_syncer.sync_resources(
            int(ow_mod_id),
            payload.mod,
            payload.images,
            payload.images_incomplete,
        )
        self.dependency_manager.retry_pending()

    def _build_payload(self, mod: SteamMod, workshop_id: str) -> Optional[ModPayload]:
        title = mod.title
        raw_description = mod.description
        tags = mod.tags
        logging.debug("Steam %s tags: %s", workshop_id, tags)

        short_desc = strip_bbcode(raw_description)
        if not short_desc:
            short_desc = title
        short_desc = truncate(short_desc, 256)
        description = truncate(raw_description, 10000)
        title, short_desc, description = self.api.limit_mod_fields(
            title, short_desc, description
        )

        ow_mod = self.ow_by_source.get(str(workshop_id))
        ow_mod_id = int(ow_mod.get("id")) if ow_mod else None
        is_existing_mod = ow_mod_id is not None

        allow_image_scrape = (not is_existing_mod) or self.options.scrape_preview_images
        images_incomplete = is_existing_mod and not allow_image_scrape

        page_deps = [str(dep) for dep in mod.dependencies if dep]
        page_deps = [dep for dep in page_deps if dep != str(workshop_id)]
        page_ok = mod.page_ok
        self.dependency_manager.queue_missing_sources(page_deps)

        images = self._collect_images(mod, allow_image_scrape)
        if not allow_image_scrape and mod.logo:
            images = [mod.logo]
        images = dedupe_images(images)
        if self.options.max_screenshots > 0 and images:
            logo = images[0]
            screenshots = images[1:]
            if len(screenshots) > self.options.max_screenshots:
                screenshots = screenshots[: self.options.max_screenshots]
            images = [logo] + screenshots
        logging.debug(
            "Steam %s images: %s (logo=%s extra=%s)",
            workshop_id,
            len(images),
            bool(mod.logo),
            "on" if allow_image_scrape else "off",
        )

        return ModPayload(
            mod=mod,
            title=title,
            short_desc=short_desc,
            description=description,
            tags=tags,
            deps=page_deps,
            deps_ok=page_ok,
            images=images,
            images_incomplete=images_incomplete,
            ow_mod_id=ow_mod_id,
            is_new=ow_mod_id is None,
        )

    def _collect_images(self, mod: SteamMod, allow_image_scrape: bool) -> List[str]:
        images: List[str] = []
        if mod.logo:
            images.append(mod.logo)
        if allow_image_scrape:
            images.extend(mod.screenshots)
        return [url for url in images if url]

    def _needs_file_update(self, mod: SteamMod, ow_mod_id: Optional[int]) -> bool:
        if ow_mod_id is None:
            return True
        ow_mod = self.ow_by_source.get(str(mod.item_id))
        if not ow_mod:
            return True
        steam_latest_ts = max(mod.updated_ts, mod.created_ts)
        ow_updated_file_ts = _parse_ow_datetime(
            (ow_mod.get("date_update_file") or ow_mod.get("date_creation"))
            if ow_mod
            else None
        )
        ow_created_ts = _parse_ow_datetime(ow_mod.get("date_creation") if ow_mod else None)
        ow_latest_ts = max(ow_updated_file_ts, ow_created_ts)
        return steam_latest_ts > ow_latest_ts

    def _download_mod_archive(self, item_id: str) -> Optional[Path]:
        if not download_steam_mod(
            self.steamcmd_path,
            self.steam_root,
            self.steam_app_id,
            int(item_id),
        ):
            return None
        workshop_path = (
            self.steam_root
            / "steamapps"
            / "workshop"
            / "content"
            / str(self.steam_app_id)
            / str(item_id)
        )
        if not has_files(workshop_path):
            return None
        return zip_directory(
            workshop_path,
            self.mirror_root / "steam_archives" / f"{item_id}.zip",
        )


def ensure_game(
    api: ApiClient,
    game_id: Optional[int],
    steam_app_id: int,
    language: str,
    timeout: int,
) -> int:
    if game_id:
        try:
            game = api.get_game(game_id)
        except Exception as exc:
            logging.warning("Game %s not found: %s", game_id, exc)
        else:
            source_id = game.get("source_id")
            if source_id and int(source_id) != steam_app_id:
                logging.warning(
                    "OW game source_id %s does not match steam app id %s",
                    source_id,
                    steam_app_id,
                )
            return game_id

    games = api.list_games_by_source(steam_app_id, 50)
    if games:
        return int(games[0]["id"])

    app_details = steam_get_app_details(steam_app_id, language, timeout)
    game_id = api.add_game(
        app_details["name"],
        app_details["short"],
        app_details["description"],
    )
    api.edit_game_source(game_id, "steam", steam_app_id)
    return game_id


def _parse_ow_datetime(value: str | None) -> int:
    if not value:
        return 0
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def sync_mods(
    api: ApiClient,
    steam_app_id: int,
    game_id: int,
    mirror_root: Path,
    steam_root: Path,
    page_size: int,
    timeout: int,
    max_pages: int,
    max_items: int,
    page_delay: float,
    max_screenshots: int,
    public_mode: int,
    without_author: bool,
    sync_tags: bool,
    prune_tags: bool,
    sync_dependencies: bool,
    prune_dependencies: bool,
    sync_resources: bool,
    prune_resources: bool,
    upload_resource_files: bool,
    scrape_preview_images: bool,
    scrape_required_items: bool,
    force_required_item_id: Optional[str],
    language: str,
    steamcmd_path: Path,
) -> None:
    options = SyncOptions(
        page_size=page_size,
        timeout=timeout,
        max_pages=max_pages,
        max_items=max_items,
        page_delay=page_delay,
        max_screenshots=max_screenshots,
        public_mode=public_mode,
        without_author=without_author,
        sync_tags=sync_tags,
        prune_tags=prune_tags,
        sync_dependencies=sync_dependencies,
        prune_dependencies=prune_dependencies,
        sync_resources=sync_resources,
        prune_resources=prune_resources,
        upload_resource_files=upload_resource_files,
        scrape_preview_images=scrape_preview_images,
        scrape_required_items=scrape_required_items,
        force_required_item_id=force_required_item_id,
        language=language,
    )
    ModSyncer(
        api,
        steam_app_id,
        game_id,
        mirror_root,
        steam_root,
        steamcmd_path,
        options,
    ).run()
