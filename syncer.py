import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from ow_api import (
    ApiClient,
    ow_add_game,
    ow_add_mod,
    ow_add_mod_dependency,
    ow_add_mod_tag,
    ow_add_resource,
    ow_add_resource_file,
    ow_add_tag,
    ow_associate_game_tag,
    ow_delete_mod_dependency,
    ow_delete_mod_tag,
    ow_delete_resource,
    ow_edit_game_source,
    ow_edit_mod,
    ow_get_game,
    ow_get_mod_dependencies,
    ow_get_mod_resources,
    ow_get_mod_tags,
    ow_list_games_by_source,
    ow_list_mods,
    ow_list_tags,
)
from steam_api import (
    steam_get_app_details,
    steam_fetch_workshop_page_ids_html,
    steam_stats_reset,
    steam_stats_snapshot,
)
from steam_mod import SteamMod
from steamcmd import download_steam_mod
from utils import (
    ensure_dir,
    has_files,
    strip_bbcode,
    truncate,
    zip_directory,
    dedupe_images,
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
            game = ow_get_game(api, game_id)
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

    games = ow_list_games_by_source(api, steam_app_id, 50)
    if games:
        return int(games[0]["id"])

    app_details = steam_get_app_details(steam_app_id, language, timeout)
    game_id = ow_add_game(
        api,
        app_details["name"],
        app_details["short"],
        app_details["description"],
    )
    ow_edit_game_source(api, game_id, "steam", steam_app_id)
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


async def _load_steam_mods_sequential(
    item_ids: List[str],
    timeout: int,
    language: str,
) -> Dict[str, SteamMod]:
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    results: Dict[str, SteamMod] = {}
    async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
        for item_id in item_ids:
            mod = SteamMod(item_id)
            ok = await mod.load(timeout=timeout, session=session, language=language)
            if not ok:
                logging.warning("Steam page parse failed for %s", item_id)
                continue
            results[str(item_id)] = mod
    return results


def _load_steam_mods(
    item_ids: List[str],
    timeout: int,
    language: str,
) -> Dict[str, SteamMod]:
    if not item_ids:
        return {}
    return asyncio.run(_load_steam_mods_sequential(item_ids, timeout, language))


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


def _save_hash_cache(path: Path, cache: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    try:
        path.write_text(json.dumps(cache, ensure_ascii=True, indent=2), "utf-8")
    except Exception as exc:
        logging.warning("Failed to write hash cache %s: %s", path, exc)


def _build_resource_hashes(
    mod: SteamMod,
    resources: List[Dict[str, Any]],
    dest_dir: Path,
    timeout: int,
) -> tuple[Dict[int, str], Dict[str, Any]]:
    cache_path = dest_dir / "resource_hashes.json"
    cache = _load_hash_cache(cache_path)
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

    hashes_by_id: Dict[int, str] = {}
    url_to_ids: Dict[str, List[int]] = {}
    for resource in resources:
        res_id = resource.get("id")
        url = resource.get("url") or ""
        if res_id is None or not url:
            continue
        cached_entry = cached_resources.get(str(res_id))
        if (
            isinstance(cached_entry, dict)
            and cached_entry.get("url") == url
            and cached_entry.get("hash")
        ):
            hashes_by_id[int(res_id)] = str(cached_entry["hash"])
            continue
        url_to_ids.setdefault(url, []).append(int(res_id))

    if url_to_ids:
        targets: List[tuple[str, str, str]] = []
        for idx, url in enumerate(url_to_ids.keys()):
            targets.append(("existing", url, f"existing_{idx}"))
        downloads = _download_steam_images(mod, targets, dest_dir, timeout)
        for _, url, file_path, file_hash in downloads:
            if not file_hash:
                continue
            for res_id in url_to_ids.get(url, []):
                hashes_by_id[res_id] = file_hash
                cached_resources[str(res_id)] = {"url": url, "hash": file_hash}
            try:
                file_path.unlink()
            except FileNotFoundError:
                pass
            except Exception:
                logging.debug("Failed to remove hash temp %s", file_path)

    _save_hash_cache(cache_path, cache)
    return hashes_by_id, cache


def _prune_duplicate_resources(
    api: ApiClient,
    resources: List[Dict[str, Any]],
    hashes_by_id: Dict[int, str],
) -> set[int]:
    by_hash: Dict[str, List[Dict[str, Any]]] = {}
    for resource in resources:
        res_id = resource.get("id")
        if res_id is None:
            continue
        file_hash = hashes_by_id.get(int(res_id))
        if not file_hash:
            continue
        by_hash.setdefault(file_hash, []).append(resource)

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
            ow_delete_resource(api, int(res_id))
            deleted_ids.add(int(res_id))
    return deleted_ids


async def _download_steam_images_sequential(
    mod: SteamMod,
    targets: List[tuple[str, str, str]],
    dest_dir: Path,
    timeout: int,
) -> List[tuple[str, str, Path, str]]:
    return await mod.download_images(
        dest_dir,
        targets,
        timeout=timeout,
    )


def _download_steam_images(
    mod: SteamMod,
    targets: List[tuple[str, str, str]],
    dest_dir: Path,
    timeout: int,
) -> List[tuple[str, str, Path, str]]:
    if not targets:
        return []
    return asyncio.run(
        _download_steam_images_sequential(mod, targets, dest_dir, timeout)
    )


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
    steam_stats_reset()

    ow_mods = ow_list_mods(api, game_id, page_size)
    ow_by_source: Dict[str, Dict[str, Any]] = {}
    for mod in ow_mods:
        source_id = mod.get("source_id")
        if source_id is not None:
            ow_by_source[str(source_id)] = mod

    queue: deque[str] = deque()
    queued_ids: set[str] = set()
    listed_count = 0
    page = 1

    def enqueue(item_id: str) -> None:
        if item_id in queued_ids:
            return
        queued_ids.add(item_id)
        queue.append(item_id)

    def fetch_next_page() -> bool:
        nonlocal page, listed_count
        if max_pages > 0 and page > max_pages:
            return False
        page_ids = steam_fetch_workshop_page_ids_html(
            steam_app_id,
            page,
            language,
            timeout,
        )
        if not page_ids:
            return False
        for item_id in page_ids:
            if max_items > 0 and listed_count >= max_items:
                break
            enqueue(str(item_id))
            listed_count += 1
        page += 1
        if page_delay > 0:
            time.sleep(page_delay)
        return True

    if force_required_item_id:
        enqueue(str(force_required_item_id))
        logging.info("Steam workshop items: 1 (forced)")
    else:
        logging.info(
            "Steam workshop listing: max_items=%s max_pages=%s",
            max_items or "unlimited",
            max_pages or "unlimited",
        )

    tag_cache: Dict[str, int] = {}
    tag_id_to_name: Dict[int, str] = {}
    if sync_tags:
        for tag in ow_list_tags(api, game_id, page_size):
            name = tag.get("name") or tag.get("tag_name")
            tag_id = tag.get("id") or tag.get("tag_id")
            if name and tag_id:
                tag_cache[str(name).lower()] = int(tag_id)
                tag_id_to_name[int(tag_id)] = str(name)

    steam_mod_cache: Dict[str, SteamMod] = {}
    # resource hash cache handles dedupe/prune when uploading files

    def get_mod(item_id: str) -> Optional[SteamMod]:
        if item_id in steam_mod_cache:
            return steam_mod_cache[item_id]
        mods = _load_steam_mods([item_id], timeout, language)
        mod = mods.get(str(item_id))
        if mod:
            steam_mod_cache[str(item_id)] = mod
            return mod
        return None

    def ensure_mod_exists(item_id: str, mod: Optional[SteamMod] = None) -> Optional[int]:
        existing = ow_by_source.get(str(item_id))
        if existing:
            return int(existing.get("id"))
        if mod is None:
            mod = get_mod(str(item_id))
        if not mod:
            return None
        title = mod.title
        description = mod.description
        short_desc = strip_bbcode(description) or title
        short_desc = truncate(short_desc, 256)
        description = truncate(description, 10000)
        if not download_steam_mod(
            steamcmd_path,
            steam_root,
            steam_app_id,
            int(item_id),
        ):
            return None
        workshop_path = (
            steam_root
            / "steamapps"
            / "workshop"
            / "content"
            / str(steam_app_id)
            / str(item_id)
        )
        if not has_files(workshop_path):
            return None
        archive_path = zip_directory(
            workshop_path,
            mirror_root / "steam_archives" / f"{item_id}.zip",
        )
        mod_id = ow_add_mod(
            api,
            title,
            short_desc,
            description,
            "steam",
            int(item_id),
            game_id,
            public_mode,
            without_author,
            archive_path,
        )
        ow_by_source[str(item_id)] = {
            "id": mod_id,
            "source_id": int(item_id),
            "date_update_file": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        if sync_resources and mod.logo:
            if upload_resource_files:
                dest_dir = mirror_root / "resources" / str(item_id)
                downloads = _download_steam_images(
                    mod,
                    [("logo", mod.logo, "logo")],
                    dest_dir,
                    timeout,
                )
                for _, _, file_path, _ in downloads:
                    ow_add_resource_file(api, "mods", mod_id, "logo", file_path)
                    break
            else:
                ow_add_resource(api, "mods", mod_id, "logo", mod.logo)
        return mod_id

    while True:
        if not queue:
            if force_required_item_id:
                break
            if max_items > 0 and listed_count >= max_items:
                break
            if not fetch_next_page():
                break
            if not queue:
                continue

        batch_ids: List[str] = []
        while queue and len(batch_ids) < 30:
            batch_ids.append(queue.popleft())
        mod_map = _load_steam_mods(batch_ids, timeout, language)
        steam_mod_cache.update(mod_map)
        for workshop_id in batch_ids:
            mod = steam_mod_cache.get(str(workshop_id))
            if not mod:
                logging.warning("Steam page missing for %s", workshop_id)
                continue

            title = mod.title
            raw_description = mod.description
            updated = mod.updated_ts
            created = mod.created_ts
            steam_latest_ts = max(updated, created)
            tags = mod.tags
            logging.debug("Steam %s tags: %s", workshop_id, tags)

            short_desc = strip_bbcode(raw_description)
            if not short_desc:
                short_desc = title
            short_desc = truncate(short_desc, 256)
            description = truncate(raw_description, 10000)

            ow_mod = ow_by_source.get(str(workshop_id))
            ow_mod_id = int(ow_mod.get("id")) if ow_mod else None
            is_existing_mod = ow_mod_id is not None

            allow_image_scrape = (not is_existing_mod) or scrape_preview_images
            images_incomplete = is_existing_mod and not allow_image_scrape

            page_deps = mod.dependencies
            page_ok = mod.page_ok
            images: List[str] = []
            if mod.logo:
                images.append(mod.logo)
            if allow_image_scrape:
                images.extend(mod.screenshots)
            images = [url for url in images if url]
            images = dedupe_images(images)
            if not allow_image_scrape and mod.logo:
                images = [mod.logo]
            if max_screenshots > 0 and images:
                logo = images[0]
                screenshots = images[1:]
                if len(screenshots) > max_screenshots:
                    screenshots = screenshots[:max_screenshots]
                images = [logo] + screenshots
            logging.debug(
                "Steam %s images: %s (logo=%s extra=%s)",
                workshop_id,
                len(images),
                bool(mod.logo),
                "on" if allow_image_scrape else "off",
            )

            if ow_mod_id is None:
                ow_mod_id = ensure_mod_exists(str(workshop_id), mod)
            else:
                ow_updated_file_ts = _parse_ow_datetime(
                    (ow_mod.get("date_update_file") or ow_mod.get("date_creation"))
                    if ow_mod
                    else None
                )
                ow_created_ts = _parse_ow_datetime(ow_mod.get("date_creation") if ow_mod else None)
                ow_latest_ts = max(ow_updated_file_ts, ow_created_ts)
                need_file = steam_latest_ts > ow_latest_ts
                if need_file:
                    logging.info("Updating OW mod %s file", ow_mod_id)
                    if download_steam_mod(
                        steamcmd_path,
                        steam_root,
                        steam_app_id,
                        int(workshop_id),
                    ):
                        workshop_path = (
                            steam_root
                            / "steamapps"
                            / "workshop"
                            / "content"
                            / str(steam_app_id)
                            / str(workshop_id)
                        )
                        archive_path = zip_directory(
                            workshop_path,
                            mirror_root / "steam_archives" / f"{workshop_id}.zip",
                        )
                        ow_edit_mod(
                            api,
                            ow_mod_id,
                            title,
                            short_desc,
                            description,
                            "steam",
                            int(workshop_id),
                            game_id,
                            public_mode,
                            archive_path,
                            set_source=False,
                        )
                    else:
                        logging.warning("Steam download failed for %s", workshop_id)
                        ow_edit_mod(
                            api,
                            ow_mod_id,
                            title,
                            short_desc,
                            description,
                            "steam",
                            int(workshop_id),
                            game_id,
                            public_mode,
                            set_source=False,
                        )
                else:
                    logging.info("Updating OW mod %s metadata", ow_mod_id)
                    ow_edit_mod(
                        api,
                        ow_mod_id,
                        title,
                        short_desc,
                        description,
                        "steam",
                        int(workshop_id),
                        game_id,
                        public_mode,
                        set_source=False,
                    )

            if ow_mod_id is None:
                continue

            if sync_tags:
                desired_tag_ids: List[int] = []
                for tag_name in tags:
                    key = tag_name.lower()
                    tag_id = tag_cache.get(key)
                    if not tag_id:
                        try:
                            tag_id = ow_add_tag(api, tag_name)
                        except Exception as exc:
                            logging.warning("Failed to add tag %s: %s", tag_name, exc)
                            continue
                        ow_associate_game_tag(api, game_id, tag_id)
                        tag_cache[key] = tag_id
                        tag_id_to_name[tag_id] = tag_name
                    desired_tag_ids.append(tag_id)

                current_tag_ids = ow_get_mod_tags(api, ow_mod_id)
                missing_tags = [tid for tid in desired_tag_ids if tid not in current_tag_ids]
                extra_tags = [tid for tid in current_tag_ids if tid not in desired_tag_ids]
                if missing_tags or extra_tags:
                    logging.debug(
                        "OW mod %s tags: current=%s desired=%s add=%s prune=%s",
                        ow_mod_id,
                        len(current_tag_ids),
                        len(desired_tag_ids),
                        [tag_id_to_name.get(tid, tid) for tid in missing_tags],
                        [tag_id_to_name.get(tid, tid) for tid in extra_tags],
                    )
                for tag_id in desired_tag_ids:
                    if tag_id not in current_tag_ids:
                        ow_add_mod_tag(api, ow_mod_id, tag_id)
                if prune_tags:
                    for tag_id in current_tag_ids:
                        if tag_id not in desired_tag_ids:
                            ow_delete_mod_tag(api, ow_mod_id, tag_id)

            if sync_dependencies:
                deps_ok = True
                if scrape_required_items:
                    steam_deps = page_deps
                    deps_ok = page_ok
                else:
                    steam_deps = []
                logging.debug("Steam %s deps: %s", workshop_id, len(steam_deps))

                if steam_deps:
                    for dep_workshop_id in steam_deps:
                        dep_workshop_id = str(dep_workshop_id)
                        if dep_workshop_id == str(workshop_id):
                            continue
                        enqueue(dep_workshop_id)

                desired_dep_ids: List[int] = []
                for dep_workshop_id in steam_deps:
                    dep_workshop_id = str(dep_workshop_id)
                    if dep_workshop_id == str(workshop_id):
                        continue
                    dep_mod_id = ensure_mod_exists(dep_workshop_id)
                    if dep_mod_id is None:
                        continue
                    desired_dep_ids.append(dep_mod_id)
                current_dep_ids = ow_get_mod_dependencies(api, ow_mod_id)
                for dep_id in desired_dep_ids:
                    if dep_id not in current_dep_ids:
                        ow_add_mod_dependency(api, ow_mod_id, dep_id)
                if prune_dependencies and deps_ok:
                    for dep_id in current_dep_ids:
                        if dep_id not in desired_dep_ids:
                            ow_delete_mod_dependency(api, ow_mod_id, dep_id)
                elif prune_dependencies and not deps_ok:
                    logging.debug(
                        "Skip dependency prune for %s due to Steam scrape failure",
                        workshop_id,
                    )

            if sync_resources and images:
                current_resources = ow_get_mod_resources(api, ow_mod_id)
                current_urls = {
                    (r.get("type"), r.get("url")): r.get("id") for r in current_resources
                }
                desired_resources: List[Tuple[str, str]] = []
                for idx_img, url in enumerate(images):
                    res_type = "logo" if idx_img == 0 else "screenshot"
                    desired_resources.append((res_type, url))

                if upload_resource_files:
                    dest_dir = mirror_root / "resources" / str(workshop_id)
                    hashes_by_id, hash_cache = _build_resource_hashes(
                        mod, current_resources, dest_dir, timeout
                    )
                    cache_path = dest_dir / "resource_hashes.json"
                    cached_resources = hash_cache.get("resources", {})

                    deleted_ids = _prune_duplicate_resources(
                        api, current_resources, hashes_by_id
                    )
                    if deleted_ids:
                        for res_id in deleted_ids:
                            hashes_by_id.pop(res_id, None)
                            if isinstance(cached_resources, dict):
                                cached_resources.pop(str(res_id), None)
                        _save_hash_cache(cache_path, hash_cache)

                    existing_hashes: set[str] = set()
                    existing_logo_hashes: set[str] = set()
                    hash_to_resources: Dict[str, List[Dict[str, Any]]] = {}
                    for resource in current_resources:
                        res_id = resource.get("id")
                        if res_id is None or int(res_id) in deleted_ids:
                            continue
                        file_hash = hashes_by_id.get(int(res_id))
                        if not file_hash:
                            continue
                        existing_hashes.add(file_hash)
                        if resource.get("type") == "logo":
                            existing_logo_hashes.add(file_hash)
                        hash_to_resources.setdefault(file_hash, []).append(resource)

                    targets: List[tuple[str, str, str]] = []
                    for idx_img, url in enumerate(images):
                        res_type = "logo" if idx_img == 0 else "screenshot"
                        basename = "logo" if idx_img == 0 else f"{idx_img}"
                        targets.append((res_type, url, basename))

                    desired_hashes: set[str] = set()
                    downloaded_count = 0
                    if targets:
                        downloads = _download_steam_images(mod, targets, dest_dir, timeout)
                        downloaded_count = len(downloads)
                        seen_hashes: set[str] = set()
                        for res_type, _, file_path, file_hash in downloads:
                            if not file_hash or file_hash in seen_hashes:
                                continue
                            seen_hashes.add(file_hash)
                            desired_hashes.add(file_hash)

                            if res_type == "logo":
                                if file_hash in existing_logo_hashes:
                                    continue
                            else:
                                if file_hash in existing_hashes:
                                    continue

                            if ow_add_resource_file(
                                api, "mods", ow_mod_id, res_type, file_path
                            ):
                                if (
                                    res_type == "logo"
                                    and file_hash in existing_hashes
                                    and file_hash not in existing_logo_hashes
                                ):
                                    for resource in hash_to_resources.get(file_hash, []):
                                        res_id = resource.get("id")
                                        if res_id is None:
                                            continue
                                        ow_delete_resource(api, int(res_id))
                                        deleted_ids.add(int(res_id))
                                        hashes_by_id.pop(int(res_id), None)
                                        if isinstance(cached_resources, dict):
                                            cached_resources.pop(str(res_id), None)
                                    _save_hash_cache(cache_path, hash_cache)
                                existing_hashes.add(file_hash)
                                if res_type == "logo":
                                    existing_logo_hashes.add(file_hash)

                    if prune_resources and images_incomplete:
                        logging.debug(
                            "Skip resource prune for %s due to missing image cache",
                            workshop_id,
                        )
                    elif (
                        prune_resources
                        and desired_hashes
                        and downloaded_count == len(targets)
                    ):
                        for resource in current_resources:
                            res_id = resource.get("id")
                            if res_id is None or int(res_id) in deleted_ids:
                                continue
                            file_hash = hashes_by_id.get(int(res_id))
                            if not file_hash or file_hash in desired_hashes:
                                continue
                            ow_delete_resource(api, int(res_id))
                            if isinstance(cached_resources, dict):
                                cached_resources.pop(str(res_id), None)
                        _save_hash_cache(cache_path, hash_cache)
                else:
                    for res_type, url in desired_resources:
                        if (res_type, url) not in current_urls:
                            ow_add_resource(api, "mods", ow_mod_id, res_type, url)

                    if prune_resources and images_incomplete:
                        logging.debug(
                            "Skip resource prune for %s due to missing image cache",
                            workshop_id,
                        )
                    elif prune_resources:
                        desired_set = set(desired_resources)
                        for (res_type, url), res_id in current_urls.items():
                            if (res_type, url) not in desired_set:
                                if res_id is not None:
                                    ow_delete_resource(api, int(res_id))

    stats = steam_stats_snapshot()
    if stats.get("total"):
        logging.info(
            "Steam requests: total=%s ok=%s failed=%s endpoints=%s",
            stats.get("total"),
            stats.get("success"),
            stats.get("failed"),
            stats.get("by_endpoint"),
        )
