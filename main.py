import logging
import sys
import time
from pathlib import Path

from config import load_config
from ow_api import ApiClient, load_api_limits, ow_get_game
from syncer import ensure_game, sync_mods
from steam_api import (
    set_steam_request_logging,
    set_steam_request_policy,
    set_steam_proxy_pool,
)
from utils import ensure_dir


def main() -> int:
    cfg = load_config()
    log_level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    set_steam_request_logging(cfg.log_steam_requests)
    set_steam_request_policy(
        cfg.steam_http_retries, cfg.steam_http_backoff, cfg.steam_request_delay
    )
    set_steam_proxy_pool(cfg.steam_proxy_pool)
    if not cfg.login_name or not cfg.password:
        logging.error("OW_LOGIN and OW_PASSWORD are required")
        return 2
    if cfg.steam_app_id <= 0 and cfg.game_id <= 0:
        logging.error("OW_STEAM_APP_ID or OW_GAME_ID is required")
        return 2

    api = ApiClient(
        cfg.api_base,
        cfg.login_name,
        cfg.password,
        cfg.timeout,
        retries=cfg.http_retries,
        retry_backoff=cfg.http_retry_backoff,
    )
    try:
        api.login()
    except Exception as exc:
        logging.error("Failed to authenticate: %s", exc)
        return 2
    load_api_limits(api)

    steam_app_id = cfg.steam_app_id
    if steam_app_id <= 0:
        try:
            game = ow_get_game(api, cfg.game_id)
        except Exception as exc:
            logging.error("Failed to load game %s: %s", cfg.game_id, exc)
            return 2
        steam_app_id = int(game.get("source_id") or 0)
        if steam_app_id <= 0:
            logging.error("OW game has no steam source_id, set OW_STEAM_APP_ID")
            return 2

    try:
        game_id = ensure_game(api, cfg.game_id if cfg.game_id > 0 else None, steam_app_id, cfg.language, cfg.timeout)
    except Exception as exc:
        logging.error("Failed to ensure game: %s", exc)
        return 2

    mirror_root = Path(cfg.mirror_root)
    steam_root = Path(cfg.steam_root)
    state_file = Path(cfg.state_file)

    logging.info("Using OW game %s for steam app %s", game_id, steam_app_id)
    ensure_dir(mirror_root)
    ensure_dir(steam_root)

    while True:
        try:
            sync_mods(
                api,
                steam_app_id,
                game_id,
                mirror_root,
                steam_root,
                state_file,
                cfg.page_size,
                cfg.timeout,
                cfg.steam_max_pages,
                cfg.steam_max_items,
                cfg.steam_delay,
                cfg.max_screenshots,
                cfg.public_mode,
                cfg.without_author,
                cfg.sync_tags,
                cfg.prune_tags,
                cfg.sync_dependencies,
                cfg.prune_dependencies,
                cfg.sync_resources,
                cfg.prune_resources,
                cfg.upload_resource_files,
                cfg.scrape_preview_images,
                cfg.scrape_required_items,
                cfg.force_required_item_id,
                cfg.language,
                Path(cfg.steamcmd_path),
            )
        except Exception:
            logging.exception("Sync failed")

        if cfg.run_once:
            break
        logging.info("Sleeping %s seconds", cfg.poll_interval)
        time.sleep(cfg.poll_interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
