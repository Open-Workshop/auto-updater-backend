import logging
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
    steam_list_workshop_ids_html,
    steam_scrape_workshop_page,
    steam_stats_reset,
    steam_stats_snapshot,
)
from steamcmd import download_steam_mod
from utils import (
    download_url_to_file,
    has_files,
    load_state,
    normalize_image_url,
    parse_images,
    save_state,
    strip_bbcode,
    truncate,
    utc_now,
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


def sync_mods(
    api: ApiClient,
    steam_app_id: int,
    game_id: int,
    mirror_root: Path,
    steam_root: Path,
    state_file: Path,
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
    state = load_state(state_file)
    mods_state: Dict[str, Any] = state.setdefault("mods", {})
    steam_stats_reset()

    ow_mods = ow_list_mods(api, game_id, page_size)
    ow_by_source: Dict[str, Dict[str, Any]] = {}
    for mod in ow_mods:
        source_id = mod.get("source_id")
        if source_id is not None:
            ow_by_source[str(source_id)] = mod

    if force_required_item_id:
        workshop_ids = [force_required_item_id]
    else:
        workshop_ids = steam_list_workshop_ids_html(
            steam_app_id,
            max_pages,
            max_items,
            page_delay,
            language,
            timeout,
        )

    logging.info("Steam workshop items: %s", len(workshop_ids))

    tag_cache: Dict[str, int] = {}
    tag_id_to_name: Dict[int, str] = {}
    if sync_tags:
        for tag in ow_list_tags(api, game_id, page_size):
            name = tag.get("name") or tag.get("tag_name")
            tag_id = tag.get("id") or tag.get("tag_id")
            if name and tag_id:
                tag_cache[str(name).lower()] = int(tag_id)
                tag_id_to_name[int(tag_id)] = str(name)

    workshop_ids = list(dict.fromkeys(workshop_ids))
    queued_ids = set(workshop_ids)

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
        ow_by_source[str(item_id)] = {"id": mod_id, "source_id": int(item_id)}
        mods_state[str(item_id)] = {
            "ow_mod_id": mod_id,
            "steam_updated": int(details.get("time_updated") or 0),
            "last_sync": utc_now(),
        }
        save_state(state_file, state)
        return mod_id

    idx = 0
    while idx < len(workshop_ids):
        batch_ids = workshop_ids[idx : idx + 30]
        idx += 30
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
            tags = [t.get("tag") for t in details.get("tags", []) if t.get("tag")]
            tags = [t.strip() for t in tags if t and t.strip()]
            logging.debug("Steam %s tags: %s", workshop_id, tags)

            short_desc = strip_bbcode(raw_description)
            if not short_desc:
                short_desc = title
            short_desc = truncate(short_desc, 256)
            description = truncate(raw_description, 10000)

            images = parse_images(raw_description, details.get("preview_url"), max_screenshots)
            page_images: List[str] = []
            page_deps: List[str] = []
            page_ok = True
            if scrape_preview_images or scrape_required_items:
                page_images, page_deps, page_ok = steam_scrape_workshop_page(
                    str(workshop_id),
                    timeout,
                    include_required=scrape_required_items,
                )
                if not page_ok:
                    logging.warning(
                        "Skipping workshop %s due to Steam scrape failure",
                        workshop_id,
                    )
                    continue
            if scrape_preview_images and page_images:
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

            mod_state = mods_state.get(str(workshop_id), {})
            previous_updated = int(mod_state.get("steam_updated") or 0)
            need_file = updated != previous_updated or str(workshop_id) not in mods_state

            ow_mod = ow_by_source.get(str(workshop_id))
            ow_mod_id = int(ow_mod.get("id")) if ow_mod else None

            if ow_mod_id is None:
                ow_mod_id = ensure_mod_exists(str(workshop_id), details)
            else:
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
                        if dep_workshop_id not in queued_ids:
                            queued_ids.add(dep_workshop_id)
                            workshop_ids.append(dep_workshop_id)

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
                    resource_state = mod_state.get("resource_urls", [])
                    if not isinstance(resource_state, list):
                        resource_state = []
                    resource_state = [
                        normalize_image_url(u)
                        for u in resource_state
                        if isinstance(u, str)
                    ]
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
                        resource_state = []
                    for idx_img, url in enumerate(images):
                        if url in resource_state:
                            continue
                        res_type = "logo" if idx_img == 0 else "screenshot"
                        if res_type == "logo" and current_logo:
                            continue
                        if res_type == "screenshot" and not needs_fill and current_screens >= desired_screens:
                            continue
                        dest_dir = mirror_root / "resources" / str(workshop_id)
                        file_path = download_url_to_file(
                            url,
                            dest_dir,
                            f"{idx_img}",
                            timeout,
                        )
                        if not file_path:
                            continue
                        if ow_add_resource_file(
                            api, "mods", ow_mod_id, res_type, file_path
                        ):
                            resource_state.append(url)
                            if res_type == "logo":
                                current_logo = True
                            else:
                                current_screens += 1
                    mod_state["resource_urls"] = resource_state
                else:
                    for res_type, url in desired_resources:
                        if (res_type, url) not in current_urls:
                            ow_add_resource(api, "mods", ow_mod_id, res_type, url)

                    if prune_resources:
                        desired_set = set(desired_resources)
                        for (res_type, url), res_id in current_urls.items():
                            if (res_type, url) not in desired_set:
                                if res_id is not None:
                                    ow_delete_resource(api, int(res_id))

            mods_state[str(workshop_id)] = {
                "ow_mod_id": ow_mod_id,
                "steam_updated": updated,
                "last_sync": utc_now(),
                "resource_urls": mod_state.get("resource_urls", []),
            }
            save_state(state_file, state)

    stats = steam_stats_snapshot()
    if stats.get("total"):
        logging.info(
            "Steam requests: total=%s ok=%s failed=%s endpoints=%s",
            stats.get("total"),
            stats.get("success"),
            stats.get("failed"),
            stats.get("by_endpoint"),
        )
