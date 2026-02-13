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
from steam_mod import (
    set_steam_mod_proxy_images,
    set_steam_mod_proxy_pool,
    set_steam_mod_request_policy,
)
from telemetry import init_telemetry, shutdown_telemetry, start_span
from utils import ensure_dir, set_download_request_policy


def main() -> int:
    cfg = load_config()
    log_level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    init_telemetry()
    try:
        set_steam_request_logging(cfg.log_steam_requests)
        set_steam_request_policy(
            cfg.steam_http_retries, cfg.steam_http_backoff, cfg.steam_request_delay
        )
        set_download_request_policy(cfg.steam_http_retries, cfg.steam_http_backoff)
        if cfg.steam_proxy_scope == "mod_pages":
            set_steam_proxy_pool([])
            set_steam_mod_proxy_pool(cfg.steam_proxy_pool)
            set_steam_mod_proxy_images(False)
        elif cfg.steam_proxy_scope == "none":
            set_steam_proxy_pool([])
            set_steam_mod_proxy_pool([])
            set_steam_mod_proxy_images(False)
        else:
            set_steam_proxy_pool(cfg.steam_proxy_pool)
            set_steam_mod_proxy_pool(cfg.steam_proxy_pool)
            set_steam_mod_proxy_images(True)
        set_steam_mod_request_policy(
            cfg.steam_http_retries, cfg.steam_http_backoff, cfg.steam_request_delay
        )
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
            with start_span("ow.login"):
                api.login()
        except Exception as exc:
            logging.error("Failed to authenticate: %s", exc)
            return 2
        with start_span("ow.load_api_limits"):
            load_api_limits(api)

        steam_app_id = cfg.steam_app_id
        if steam_app_id <= 0:
            try:
                with start_span("ow.get_game", {"ow.game_id": cfg.game_id}):
                    game = ow_get_game(api, cfg.game_id)
            except Exception as exc:
                logging.error("Failed to load game %s: %s", cfg.game_id, exc)
                return 2
            steam_app_id = int(game.get("source_id") or 0)
            if steam_app_id <= 0:
                logging.error("OW game has no steam source_id, set OW_STEAM_APP_ID")
                return 2

        try:
            with start_span(
                "ow.ensure_game",
                {"steam.app_id": steam_app_id, "ow.game_id": cfg.game_id or 0},
            ):
                game_id = ensure_game(
                    api,
                    cfg.game_id if cfg.game_id > 0 else None,
                    steam_app_id,
                    cfg.language,
                    cfg.timeout,
                )
        except Exception as exc:
            logging.error("Failed to ensure game: %s", exc)
            return 2

        mirror_root = Path(cfg.mirror_root)
        steam_root = Path(cfg.steam_root)

        logging.info("Using OW game %s for steam app %s", game_id, steam_app_id)
        ensure_dir(mirror_root)
        ensure_dir(steam_root)

        sync_iteration = 0
        while True:
            sync_iteration += 1
            try:
                with start_span(
                    "sync.cycle",
                    {
                        "sync.iteration": sync_iteration,
                        "steam.app_id": steam_app_id,
                        "ow.game_id": game_id,
                        "sync.run_once": cfg.run_once,
                    },
                ):
                    sync_mods(
                        api,
                        steam_app_id,
                        game_id,
                        mirror_root,
                        steam_root,
                        cfg.page_size,
                        cfg.timeout,
                        cfg.steam_max_pages,
                        cfg.steam_start_page,
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
    finally:
        shutdown_telemetry()


if __name__ == "__main__":
    sys.exit(main())
