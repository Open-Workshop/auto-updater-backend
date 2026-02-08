import logging
import time
from datetime import datetime, timezone
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    ow_get_mod_details,
    ow_get_mod_resources,
    ow_get_mod_tags,
    ow_list_games_by_source,
    ow_list_mods,
    ow_list_tags,
)
from steam_api import (
    steam_get_app_details,
    steam_get_published_file_details,
    steam_fetch_workshop_page_ids_html,
    steam_scrape_workshop_page,
    steam_stats_reset,
    steam_stats_snapshot,
)
from steamcmd import download_steam_mod
from utils import (
    download_url_to_file_with_hash,
    has_files,
    parse_images,
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

    steam_details_cache: Dict[str, Dict[str, Any]] = {}
    warned_resource_prune = False

    def get_details(item_id: str) -> Optional[Dict[str, Any]]:
        if item_id in steam_details_cache:
            return steam_details_cache[item_id]
        details = steam_get_published_file_details([item_id], timeout)
        if item_id in details:
            steam_details_cache[item_id] = details[item_id]
            return details[item_id]
        return None

    def ensure_mod_exists(item_id: str, details: Optional[Dict[str, Any]] = None) -> Optional[int]:
        existing = ow_by_source.get(str(item_id))
        if existing:
            return int(existing.get("id"))
        if details is None:
            details = get_details(str(item_id))
        if not details or int(details.get("result", 1)) != 1:
            return None
        title = details.get("title", "")
        description = details.get("description", "")
        preview_url = details.get("preview_url") or ""
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
        if sync_resources and preview_url:
            if upload_resource_files:
                dest_dir = mirror_root / "resources" / str(item_id)
                file_path, _ = download_url_to_file_with_hash(
                    preview_url,
                    dest_dir,
                    "logo",
                    timeout,
                )
                if file_path:
                    ow_add_resource_file(api, "mods", mod_id, "logo", file_path)
            else:
                ow_add_resource(api, "mods", mod_id, "logo", preview_url)
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
        details_map = steam_get_published_file_details(batch_ids, timeout)
        steam_details_cache.update(details_map)
        for workshop_id in batch_ids:
            details = steam_details_cache.get(str(workshop_id))
            if not details:
                logging.warning("Steam details missing for %s", workshop_id)
                continue
            if int(details.get("result", 1)) != 1:
                logging.warning("Steam details error for %s", workshop_id)
                continue

            title = details.get("title", "")
            raw_description = details.get("description", "")
            updated = int(details.get("time_updated") or 0)
            created = int(details.get("time_created") or 0)
            steam_latest_ts = max(updated, created)
            tags = [t.get("tag") for t in details.get("tags", []) if t.get("tag")]
            tags = [t.strip() for t in tags if t and t.strip()]
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

            images = parse_images(
                raw_description, details.get("preview_url"), max_screenshots
            )
            page_images: List[str] = []
            page_deps: List[str] = []
            page_ok = True
            if scrape_required_items or allow_image_scrape:
                page_images, page_deps, page_ok = steam_scrape_workshop_page(
                    str(workshop_id),
                    timeout,
                    include_required=scrape_required_items,
                    include_images=allow_image_scrape,
                )
                if not page_ok and ow_mod_id is None:
                    logging.warning(
                        "Skipping new workshop %s due to Steam scrape failure",
                        workshop_id,
                    )
                    continue
            if allow_image_scrape and page_images:
                for url in page_images:
                    if url not in images:
                        images.append(url)

            images = dedupe_images(images)
            logging.debug(
                "Steam %s images: %s (preview=%s extra=%s)",
                workshop_id,
                len(images),
                bool(details.get("preview_url")),
                "on" if scrape_preview_images else "off",
            )

            if ow_mod_id is None:
                ow_mod_id = ensure_mod_exists(str(workshop_id), details)
            else:
                ow_updated_file_ts = _parse_ow_datetime(
                    (ow_mod.get("date_update_file") or ow_mod.get("date_creation"))
                    if ow_mod
                    else None
                )
                ow_created_ts = _parse_ow_datetime(ow_mod.get("date_creation") if ow_mod else None)
                ow_latest_ts = max(ow_updated_file_ts, ow_created_ts)
                need_file = steam_latest_ts > ow_latest_ts
                try:
                    ow_details = ow_get_mod_details(api, ow_mod_id)
                except Exception as exc:
                    logging.warning("Failed to fetch OW mod %s: %s", ow_mod_id, exc)
                    ow_details = {}

                needs_update = False
                result_info = ow_details.get("result") if isinstance(ow_details, dict) else {}
                if isinstance(result_info, dict) and result_info:
                    if result_info.get("name") != title:
                        needs_update = True
                    if result_info.get("short_description") != short_desc:
                        needs_update = True
                    if result_info.get("description") != description:
                        needs_update = True
                elif isinstance(ow_details, dict):
                    if ow_details.get("name") and ow_details.get("name") != title:
                        needs_update = True

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
                elif needs_update:
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
                    if prune_resources:
                        if not warned_resource_prune:
                            logging.warning(
                                "Resource pruning is disabled when OW_RESOURCE_UPLOAD_FILES=true"
                            )
                            warned_resource_prune = True
                    current_logo = any(r.get("type") == "logo" for r in current_resources)
                    current_screens = sum(
                        1 for r in current_resources if r.get("type") == "screenshot"
                    )
                    desired_screens = max(0, len(images) - 1)
                    logging.debug(
                        "OW mod %s resources: current_logo=%s current_screens=%s desired_screens=%s",
                        ow_mod_id,
                        current_logo,
                        current_screens,
                        desired_screens,
                    )
                    needs_fill = (not current_logo and len(images) > 0) or (
                        current_screens < desired_screens
                    )
                    if needs_fill:
                        seen_hashes: set[str] = set()
                        for idx_img, url in enumerate(images):
                            if current_logo and current_screens >= desired_screens:
                                break
                            res_type = "logo" if idx_img == 0 else "screenshot"
                            if res_type == "logo" and current_logo:
                                continue
                            if res_type == "screenshot" and current_screens >= desired_screens:
                                continue
                            dest_dir = mirror_root / "resources" / str(workshop_id)
                            file_path, file_hash = download_url_to_file_with_hash(
                                url,
                                dest_dir,
                                f"{idx_img}",
                                timeout,
                            )
                            if not file_path or not file_hash:
                                continue
                            if file_hash in seen_hashes:
                                continue
                            if ow_add_resource_file(
                                api, "mods", ow_mod_id, res_type, file_path
                            ):
                                seen_hashes.add(file_hash)
                                if res_type == "logo":
                                    current_logo = True
                                else:
                                    current_screens += 1
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
