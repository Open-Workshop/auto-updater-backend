from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from aiohttp import web

from core.config import Config, load_config, parse_list
from core.instance_schema import default_parser_type, iter_sync_env_items, load_sync_config_from_env
from kube.kube_client import get_instance, merge_instance_status, read_secret_value
from kube.mirror_instance import normalize_instance, runner_service_url
from core.log_tags import parser_log_handler
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
from core.proxy_stats import snapshot_proxy_stats
from core.utils import ensure_dir, set_download_request_policy

_CLIENT_REINIT_FIELDS = {
    "api_base",
    "login_name",
    "password",
    "steam_app_id",
    "game_id",
    "timeout",
    "http_retries",
    "http_retry_backoff",
    "language",
}


def _parser_type_from_env() -> str:
    return os.environ.get("OW_PARSER_TYPE", "").strip() or default_parser_type()


def _workload_id_from_env() -> str:
    return os.environ.get("OW_WORKLOAD_ID", "").strip() or "parser"


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

    def _apply_runtime_settings(self) -> None:
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

    def _reinitialize_client_state(self) -> bool:
        if not self.cfg.login_name or not self.cfg.password:
            logging.error("OW_LOGIN and OW_PASSWORD are required")
            return False
        if self.cfg.steam_app_id <= 0 and self.cfg.game_id <= 0:
            logging.error("OW_STEAM_APP_ID or OW_GAME_ID is required")
            return False

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
            return False
        with start_span("ow.load_api_limits"):
            load_api_limits(api)

        steam_app_id = self.cfg.steam_app_id
        if steam_app_id <= 0:
            try:
                with start_span("ow.get_game", {"ow.game_id": self.cfg.game_id}):
                    game = ow_get_game(api, self.cfg.game_id)
            except Exception as exc:
                logging.error("Failed to load game %s: %s", self.cfg.game_id, exc)
                return False
            steam_app_id = int(game.get("source_id") or 0)
            if steam_app_id <= 0:
                logging.error("OW game has no steam source_id, set OW_STEAM_APP_ID")
                return False

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
            return False

        ensure_dir(Path(self.cfg.mirror_root))
        ensure_dir(Path(self.cfg.steam_root))
        self.api = api
        self.game_id = game_id
        self.steam_app_id = steam_app_id
        logging.info("Using OW game %s for steam app %s", game_id, steam_app_id)
        return True

    def _refresh_config_from_cluster(self) -> None:
        if not self.cfg.instance_name or not self.cfg.instance_namespace:
            return
        instance = normalize_instance(
            get_instance(self.cfg.instance_namespace, self.cfg.instance_name)
        )
        spec = dict(instance.get("spec") or {})
        source = dict(spec.get("source") or {})
        sync = dict(spec.get("sync") or {})
        credentials = dict(spec.get("credentials") or {})
        parser = dict(spec.get("parser") or {})
        sync_cfg = load_sync_config_from_env(dict(iter_sync_env_items(sync)))
        credentials_secret = str(credentials.get("secretRef") or "").strip()
        parser_proxy_secret = str(parser.get("proxyPoolSecretRef") or "").strip()
        proxy_pool_value = ""
        if parser_proxy_secret:
            proxy_pool_value = read_secret_value(
                self.cfg.instance_namespace,
                parser_proxy_secret,
                "proxyPool",
            )
        candidate_cfg = replace(
            self.cfg,
            api_base=str(sync_cfg["api_base"]),
            login_name=read_secret_value(
                self.cfg.instance_namespace,
                credentials_secret,
                "login",
            ),
            password=read_secret_value(
                self.cfg.instance_namespace,
                credentials_secret,
                "password",
            ),
            steam_app_id=int(source.get("steamAppId") or 0),
            game_id=int(source.get("owGameId") or 0),
            page_size=int(sync_cfg["page_size"]),
            poll_interval=int(sync_cfg["poll_interval"]),
            timeout=int(sync_cfg["timeout"]),
            http_retries=int(sync_cfg["http_retries"]),
            http_retry_backoff=float(sync_cfg["http_retry_backoff"]),
            run_once=bool(sync_cfg["run_once"]),
            log_level=str(sync_cfg["log_level"]),
            log_steam_requests=bool(sync_cfg["log_steam_requests"]),
            steam_http_retries=int(sync_cfg["steam_http_retries"]),
            steam_http_backoff=float(sync_cfg["steam_http_backoff"]),
            steam_request_delay=float(sync_cfg["steam_request_delay"]),
            steam_proxy_pool=parse_list(proxy_pool_value),
            steam_proxy_scope="mod_pages" if parser_proxy_secret else "none",
            steam_max_pages=int(sync_cfg["steam_max_pages"]),
            steam_start_page=int(sync_cfg["steam_start_page"]),
            steam_max_items=int(sync_cfg["steam_max_items"]),
            steam_delay=float(sync_cfg["steam_delay"]),
            max_screenshots=int(sync_cfg["max_screenshots"]),
            upload_resource_files=bool(sync_cfg["upload_resource_files"]),
            scrape_preview_images=bool(sync_cfg["scrape_preview_images"]),
            scrape_required_items=bool(sync_cfg["scrape_required_items"]),
            force_required_item_id=str(sync_cfg["force_required_item_id"]) or None,
            public_mode=int(sync_cfg["public_mode"]),
            without_author=bool(sync_cfg["without_author"]),
            sync_tags=bool(sync_cfg["sync_tags"]),
            prune_tags=bool(sync_cfg["prune_tags"]),
            sync_dependencies=bool(sync_cfg["sync_dependencies"]),
            prune_dependencies=bool(sync_cfg["prune_dependencies"]),
            sync_resources=bool(sync_cfg["sync_resources"]),
            prune_resources=bool(sync_cfg["prune_resources"]),
            language=str(source.get("language") or "english").strip() or "english",
            steamcmd_runner_url=runner_service_url(
                self.cfg.instance_name,
                self.cfg.instance_namespace,
            ),
        )
        changed_fields = sorted(
            field_name
            for field_name in self.cfg.__dataclass_fields__
            if getattr(candidate_cfg, field_name) != getattr(self.cfg, field_name)
        )
        if not changed_fields:
            return
        previous_cfg = self.cfg
        self.cfg = candidate_cfg
        try:
            self._apply_runtime_settings()
            if any(field_name in _CLIENT_REINIT_FIELDS for field_name in changed_fields):
                if not self._reinitialize_client_state():
                    raise RuntimeError(
                        "Failed to reinitialize parser runtime from latest MirrorInstance config"
                    )
        except Exception:
            self.cfg = previous_cfg
            self._apply_runtime_settings()
            raise
        logging.info(
            "Reloaded parser config from MirrorInstance: %s",
            ", ".join(changed_fields),
        )

    def bootstrap(self) -> int:
        self._apply_runtime_settings()
        if not self._reinitialize_client_state():
            return 2
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
            await asyncio.to_thread(self._refresh_config_from_cluster)
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
                Path(self.cfg.depotdownloader_path),
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
            "proxyStats": self.proxy_snapshot(),
        }

    def proxy_snapshot(self) -> dict[str, Any]:
        return {
            "generatedAt": _utcnow_iso(),
            "instanceName": self.cfg.instance_name,
            "workloadId": _workload_id_from_env(),
            "podName": os.environ.get("HOSTNAME", "").strip(),
            "proxyConfigured": bool(self.cfg.steam_proxy_pool),
            "proxyPoolSize": len(self.cfg.steam_proxy_pool),
            "proxyScope": self.cfg.steam_proxy_scope,
            "stats": snapshot_proxy_stats(),
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


async def _proxy_stats(request: web.Request) -> web.Response:
    runtime: ParserRuntime = request.app["runtime"]
    return web.json_response(runtime.proxy_snapshot())


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
    app.router.add_get("/api/v1/proxy-stats", _proxy_stats)
    app.router.add_post("/api/v1/sync", _sync)
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    return app


def run_parser() -> int:
    parser_type = _parser_type_from_env()
    workload_id = _workload_id_from_env()
    if parser_type != default_parser_type():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=[logging.StreamHandler()],
        )
        logging.error("Unsupported parser type %s", parser_type)
        return 2
    if workload_id != "parser":
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=[logging.StreamHandler()],
        )
        logging.error("Parser host cannot run workload %s", workload_id)
        return 2
    cfg = load_config()
    log_level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        handlers=[parser_log_handler()],
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
