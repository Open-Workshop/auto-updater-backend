from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from aiohttp import web

from core.config import Config, load_config
from kube.kube_client import merge_instance_status
from ow.ow_api import ApiClient, load_api_limits, ow_get_game
from steam.steam_api import (
    set_steam_proxy_pool,
    set_steam_request_logging,
    set_steam_request_policy,
)
from steam.steam_mod import (
    set_steam_mod_proxy_images,
    set_steam_mod_proxy_pool,
    set_steam_mod_request_policy,
)
from sync.syncer import ensure_game, sync_mods
from core.telemetry import init_telemetry, shutdown_telemetry, start_span
from core.utils import ensure_dir, set_download_request_policy


class ParserRuntime:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.api: ApiClient | None = None
        self.game_id = 0
        self.steam_app_id = 0
        self.sync_requested = asyncio.Event()
        self.stop_requested = asyncio.Event()
        self.background_task: asyncio.Task[None] | None = None
        self.last_sync_started_at = ""
        self.last_sync_finished_at = ""
        self.last_sync_result = "never"
        self.last_error = ""
        self.syncing = False

    def bootstrap(self) -> int:
        set_steam_request_logging(self.cfg.log_steam_requests)
        set_steam_request_policy(
            self.cfg.steam_http_retries,
            self.cfg.steam_http_backoff,
            self.cfg.steam_request_delay,
        )
        set_download_request_policy(self.cfg.steam_http_retries, self.cfg.steam_http_backoff)
        if self.cfg.steam_proxy_scope == "mod_pages":
            set_steam_proxy_pool([])
            set_steam_mod_proxy_pool(self.cfg.steam_proxy_pool)
            set_steam_mod_proxy_images(False)
        elif self.cfg.steam_proxy_scope == "none":
            set_steam_proxy_pool([])
            set_steam_mod_proxy_pool([])
            set_steam_mod_proxy_images(False)
        else:
            set_steam_proxy_pool(self.cfg.steam_proxy_pool)
            set_steam_mod_proxy_pool(self.cfg.steam_proxy_pool)
            set_steam_mod_proxy_images(True)
        set_steam_mod_request_policy(
            self.cfg.steam_http_retries,
            self.cfg.steam_http_backoff,
            self.cfg.steam_request_delay,
        )

        if not self.cfg.login_name or not self.cfg.password:
            logging.error("OW_LOGIN and OW_PASSWORD are required")
            return 2
        if self.cfg.steam_app_id <= 0 and self.cfg.game_id <= 0:
            logging.error("OW_STEAM_APP_ID or OW_GAME_ID is required")
            return 2

        api = ApiClient(
            self.cfg.api_base,
            self.cfg.login_name,
            self.cfg.password,
            self.cfg.timeout,
            retries=self.cfg.http_retries,
            retry_backoff=self.cfg.http_retry_backoff,
        )
        try:
            with start_span("ow.login"):
                api.login()
        except Exception as exc:
            logging.error("Failed to authenticate: %s", exc)
            return 2
        with start_span("ow.load_api_limits"):
            load_api_limits(api)

        steam_app_id = self.cfg.steam_app_id
        if steam_app_id <= 0:
            try:
                with start_span("ow.get_game", {"ow.game_id": self.cfg.game_id}):
                    game = ow_get_game(api, self.cfg.game_id)
            except Exception as exc:
                logging.error("Failed to load game %s: %s", self.cfg.game_id, exc)
                return 2
            steam_app_id = int(game.get("source_id") or 0)
            if steam_app_id <= 0:
                logging.error("OW game has no steam source_id, set OW_STEAM_APP_ID")
                return 2

        try:
            with start_span(
                "ow.ensure_game",
                {"steam.app_id": steam_app_id, "ow.game_id": self.cfg.game_id or 0},
            ):
                game_id = ensure_game(
                    api,
                    self.cfg.game_id if self.cfg.game_id > 0 else None,
                    steam_app_id,
                    self.cfg.language,
                    self.cfg.timeout,
                )
        except Exception as exc:
            logging.error("Failed to ensure game: %s", exc)
            return 2

        ensure_dir(Path(self.cfg.mirror_root))
        ensure_dir(Path(self.cfg.steam_root))
        self.api = api
        self.game_id = game_id
        self.steam_app_id = steam_app_id
        logging.info("Using OW game %s for steam app %s", game_id, steam_app_id)
        return 0

    async def run_forever(self) -> None:
        while not self.stop_requested.is_set():
            await self.run_sync_once()
            if self.cfg.run_once:
                self.stop_requested.set()
                break
            try:
                await asyncio.wait_for(
                    self.sync_requested.wait(),
                    timeout=float(self.cfg.poll_interval),
                )
                self.sync_requested.clear()
            except TimeoutError:
                continue

    async def run_sync_once(self) -> None:
        if self.api is None:
            raise RuntimeError("parser runtime is not bootstrapped")
        self.syncing = True
        self.last_error = ""
        self.last_sync_started_at = _utcnow_iso()
        self._report_status(
            {
                "lastSyncStartedAt": self.last_sync_started_at,
                "lastSyncResult": "running",
                "lastError": "",
            }
        )
        try:
            await asyncio.to_thread(
                sync_mods,
                self.api,
                self.steam_app_id,
                self.game_id,
                Path(self.cfg.mirror_root),
                Path(self.cfg.steam_root),
                self.cfg.page_size,
                self.cfg.timeout,
                self.cfg.steam_max_pages,
                self.cfg.steam_start_page,
                self.cfg.steam_max_items,
                self.cfg.steam_delay,
                self.cfg.max_screenshots,
                self.cfg.public_mode,
                self.cfg.without_author,
                self.cfg.sync_tags,
                self.cfg.prune_tags,
                self.cfg.sync_dependencies,
                self.cfg.prune_dependencies,
                self.cfg.sync_resources,
                self.cfg.prune_resources,
                self.cfg.upload_resource_files,
                self.cfg.scrape_preview_images,
                self.cfg.scrape_required_items,
                self.cfg.force_required_item_id,
                self.cfg.language,
                Path(self.cfg.steamcmd_path),
                self.cfg.steamcmd_runner_url or None,
            )
            self.last_sync_result = "success"
        except Exception as exc:
            logging.exception("Sync failed")
            self.last_sync_result = "failed"
            self.last_error = str(exc)
        finally:
            self.syncing = False
            self.last_sync_finished_at = _utcnow_iso()
            self._report_status(
                {
                    "lastSyncFinishedAt": self.last_sync_finished_at,
                    "lastSyncResult": self.last_sync_result,
                    "lastError": self.last_error,
                }
            )

    def request_sync(self) -> None:
        self.sync_requested.set()

    def _report_status(self, fields: dict[str, Any]) -> None:
        if not self.cfg.instance_name or not self.cfg.instance_namespace:
            return
        try:
            merge_instance_status(
                self.cfg.instance_namespace,
                self.cfg.instance_name,
                fields,
            )
        except Exception:
            logging.exception("Failed to report parser status")

    def snapshot(self) -> dict[str, Any]:
        return {
            "steamAppId": self.steam_app_id,
            "gameId": self.game_id,
            "syncing": self.syncing,
            "lastSyncStartedAt": self.last_sync_started_at,
            "lastSyncFinishedAt": self.last_sync_finished_at,
            "lastSyncResult": self.last_sync_result,
            "lastError": self.last_error,
        }


def _utcnow_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).replace(microsecond=0).isoformat()


async def _healthz(request: web.Request) -> web.Response:
    runtime: ParserRuntime = request.app["runtime"]
    return web.json_response({"status": "ok", **runtime.snapshot()})


async def _status(request: web.Request) -> web.Response:
    runtime: ParserRuntime = request.app["runtime"]
    return web.json_response(runtime.snapshot())


async def _sync(request: web.Request) -> web.Response:
    runtime: ParserRuntime = request.app["runtime"]
    runtime.request_sync()
    return web.json_response({"accepted": True})


async def _on_startup(app: web.Application) -> None:
    runtime: ParserRuntime = app["runtime"]
    runtime.background_task = asyncio.create_task(runtime.run_forever())


async def _on_cleanup(app: web.Application) -> None:
    runtime: ParserRuntime = app["runtime"]
    runtime.stop_requested.set()
    runtime.request_sync()
    if runtime.background_task is not None:
        await runtime.background_task
    shutdown_telemetry()


def _create_app(runtime: ParserRuntime) -> web.Application:
    app = web.Application()
    app["runtime"] = runtime
    app.router.add_get("/healthz", _healthz)
    app.router.add_get("/api/v1/status", _status)
    app.router.add_post("/api/v1/sync", _sync)
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    return app


def run_parser() -> int:
    cfg = load_config()
    log_level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    init_telemetry()
    runtime = ParserRuntime(cfg)
    code = runtime.bootstrap()
    if code != 0:
        shutdown_telemetry()
        return code
    if cfg.run_once:
        asyncio.run(runtime.run_sync_once())
        shutdown_telemetry()
        return 0 if runtime.last_sync_result == "success" else 1
    app = _create_app(runtime)
    web.run_app(app, host=cfg.admin_host, port=cfg.admin_port)
    return 0
