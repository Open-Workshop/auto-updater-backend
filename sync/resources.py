from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

import imagehash
import requests
from PIL import Image, ImageOps

from core.telemetry import start_span
from core.utils import ensure_dir
from ow.ow_api import ApiClient
from steam.steam_mod import SteamMod
from sync.metadata import OW_LOG


_PHASH_AVAILABLE = True
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
        OW_LOG.debug("Failed to compute phash for %s: %s", path, exc)
        return None


def build_hashes(file_hash: str | None, file_path: Path) -> ImageHashes:
    return ImageHashes(
        sha256=file_hash if file_hash else None,
        phash=_phash_from_path(file_path),
    )


def _phash_distance(left: str, right: str) -> int | None:
    if not _PHASH_AVAILABLE:
        return None
    try:
        return imagehash.hex_to_hash(left) - imagehash.hex_to_hash(right)
    except Exception:
        return None


def hashes_match(left: ImageHashes, right: ImageHashes) -> bool:
    if _PHASH_AVAILABLE and left.phash and right.phash:
        distance = _phash_distance(left.phash, right.phash)
        if distance is not None:
            return distance <= PHASH_MAX_DISTANCE
    if left.sha256 and right.sha256:
        return left.sha256 == right.sha256
    return False


def hash_matches_any(target: ImageHashes, candidates: Iterable[ImageHashes]) -> bool:
    for candidate in candidates:
        if hashes_match(target, candidate):
            return True
    return False


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
        with start_span(
            "images.sync_resources",
            {
                "ow.mod_id": ow_mod_id,
                "images.count": len(images),
                "images.incomplete": images_incomplete,
                "images.upload_files": self.upload_files,
            },
        ):
            if not self.upload_files:
                OW_LOG.warning(
                    "Resource URL sync mode is deprecated; forcing file upload mode for mod %s",
                    ow_mod_id,
                )
            current_resources = self.api.get_mod_resources(ow_mod_id)
            self._sync_resource_files(
                ow_mod_id,
                mod,
                images,
                images_incomplete,
                current_resources,
            )

    def _sync_resource_files(
        self,
        ow_mod_id: int,
        mod: SteamMod,
        images: List[str],
        images_incomplete: bool,
        current_resources: List[Dict[str, Any]],
    ) -> None:
        dest_dir = self.mirror_root / "resources" / str(mod.item_id)
        with start_span(
            "images.hashes.load_current",
            {
                "ow.mod_id": ow_mod_id,
                "images.current_resources": len(current_resources),
            },
        ):
            hashes_by_id, hash_cache = self._build_resource_hashes(
                mod,
                current_resources,
                dest_dir,
            )
        cache_path = dest_dir / "resource_hashes.json"
        cached_resources = hash_cache.get("resources", {})

        with start_span(
            "images.compare_duplicates",
            {
                "ow.mod_id": ow_mod_id,
                "images.current_resources": len(current_resources),
            },
        ):
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
            with start_span(
                "images.download_targets",
                {
                    "ow.mod_id": ow_mod_id,
                    "images.targets": len(targets),
                },
            ):
                downloads = self._download_steam_images(mod, targets, dest_dir)
            downloaded_count = len(downloads)
            with start_span(
                "images.process_and_compare",
                {
                    "ow.mod_id": ow_mod_id,
                    "images.downloaded": downloaded_count,
                    "images.existing_hashes": len(existing_hashes),
                },
            ):
                seen_sha256: set[str] = set()
                for res_type, _, file_path, file_hash in downloads:
                    hashes = build_hashes(file_hash, file_path)
                    if hashes.sha256 and hashes.sha256 in seen_sha256:
                        continue
                    if hashes.sha256:
                        seen_sha256.add(hashes.sha256)
                    desired_hashes.append(hashes)

                    if res_type == "logo":
                        if hash_matches_any(hashes, existing_logo_hashes):
                            continue
                    elif hash_matches_any(hashes, existing_hashes):
                        continue

                    if self.api.add_resource_file("mods", ow_mod_id, res_type, file_path):
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
            OW_LOG.debug(
                "Skip resource prune for %s due to missing image cache",
                mod.item_id,
            )
        elif self.prune and desired_hashes and downloaded_count == len(targets):
            with start_span(
                "images.compare_and_prune",
                {
                    "ow.mod_id": ow_mod_id,
                    "images.current_resources": len(current_resources),
                    "images.desired_hashes": len(desired_hashes),
                },
            ):
                for resource in current_resources:
                    res_id = resource.get("id")
                    if res_id is None or int(res_id) in deleted_ids:
                        continue
                    hashes = hashes_by_id.get(int(res_id))
                    if not hashes or hash_matches_any(hashes, desired_hashes):
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
            with start_span(
                "images.check_existing_urls",
                {"images.urls_to_probe": len(url_to_ids)},
            ):
                self._prune_missing_resource_urls(url_to_ids, cached_resources)

        if url_to_ids:
            targets: List[tuple[str, str, str]] = []
            for idx, url in enumerate(url_to_ids.keys()):
                targets.append(("existing", url, f"existing_{idx}"))
            with start_span(
                "images.download_existing_for_hashes",
                {"images.targets": len(targets)},
            ):
                downloads = self._download_steam_images(mod, targets, dest_dir)
            with start_span(
                "images.process_existing_hashes",
                {"images.downloaded": len(downloads)},
            ):
                for _, url, file_path, file_hash in downloads:
                    if not file_hash and not _PHASH_AVAILABLE:
                        continue
                    hashes = build_hashes(file_hash, file_path)
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
                        OW_LOG.debug("Failed to remove hash temp %s", file_path)

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
            OW_LOG.warning("Deleting OW resource(s) with missing URL: %s", url)
            for res_id in res_ids:
                self.api.delete_resource(int(res_id))
                if isinstance(cached_resources, dict):
                    cached_resources.pop(str(res_id), None)
            url_to_ids.pop(url, None)

    def _head_status(self, url: str) -> int | None:
        if not url:
            return None
        parsed = urlparse(url)
        use_get = False
        if "openworkshop" in (parsed.netloc or ""):
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) >= 3 and parts[0] == "download" and parts[1] == "resource":
                owner_type = parts[2]
                if owner_type not in {"mods", "games"}:
                    OW_LOG.warning(
                        "Skip resource probe for %s (unknown owner_type=%s)",
                        url,
                        owner_type,
                    )
                    return None
                use_get = True
        if use_get:
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    stream=True,
                    headers={"Range": "bytes=0-0"},
                )
            except requests.RequestException as exc:
                OW_LOG.debug("Failed to probe resource %s: %s", url, exc)
                return None
            try:
                return int(response.status_code)
            finally:
                response.close()
        try:
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            OW_LOG.debug("Failed to probe resource %s: %s", url, exc)
            return None
        try:
            status = int(response.status_code)
        finally:
            response.close()
        if status != 405:
            return status
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
                headers={"Range": "bytes=0-0"},
            )
        except requests.RequestException as exc:
            OW_LOG.debug("Failed to probe resource %s: %s", url, exc)
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
            return {"resources": {}, "version": 1}
        try:
            payload = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            return {"resources": {}, "version": 1}
        if not isinstance(payload, dict):
            return {"resources": {}, "version": 1}
        if "resources" not in payload or not isinstance(payload["resources"], dict):
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
            OW_LOG.warning("Failed to write hash cache %s: %s", path, exc)

    @staticmethod
    def _build_image_targets(images: List[str]) -> List[tuple[str, str, str]]:
        targets: List[tuple[str, str, str]] = []
        for idx_img, url in enumerate(images):
            res_type = "logo" if idx_img == 0 else "screenshot"
            basename = "logo" if idx_img == 0 else f"{idx_img}"
            targets.append((res_type, url, basename))
        return targets
