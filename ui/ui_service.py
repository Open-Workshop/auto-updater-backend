"""UI service for auto-updater."""
from __future__ import annotations

import logging
from typing import Any

from aiohttp import web

from kube.kube_client import get_kube_clients
from ui.ui_assets import STATIC_DIR
from ui.ui_common import UISettings, load_ui_settings
from ui.ui_handlers import (
    _basic_auth,
    dashboard,
    delete_instance_route,
    edit_instance_page,
    healthz,
    instance_detail_page,
    instance_summary_api,
    instances_api,
    new_instance_page,
    pod_logs_api,
    pod_logs_page,
    proxy_stats_api,
    proxy_stats_page,
    resource_page,
    save_instance,
    sync_now,
    toggle_instance,
)


async def favicon(request: web.Request) -> web.FileResponse:
    del request
    return web.FileResponse(STATIC_DIR / "favicon.ico")


def _create_app(settings: UISettings) -> web.Application:
    """Create and configure the aiohttp application."""
    app = web.Application(middlewares=[_basic_auth])
    app["settings"] = settings

    def register(method: str, path: str, handler: Any) -> None:
        """Register a route with optional base path support."""
        app.router.add_route(method, path, handler)
        if settings.base_path:
            if path == "/":
                app.router.add_route(method, settings.base_path, handler)
                app.router.add_route(method, settings.base_path + "/", handler)
            else:
                app.router.add_route(method, f"{settings.base_path}{path}", handler)

    register("GET", "/healthz", healthz)
    register("GET", "/favicon.ico", favicon)
    register("GET", "/", dashboard)
    register("GET", "/proxy-stats", proxy_stats_page)
    register("GET", "/api/instances", instances_api)
    register("GET", "/api/proxy-stats", proxy_stats_api)
    register("GET", "/api/instances/{name}", instance_summary_api)
    register("GET", "/instances/new", new_instance_page)
    register("GET", "/instances/{name}", instance_detail_page)
    register("GET", "/instances/{name}/edit", edit_instance_page)
    register("GET", "/instances/{name}/resources", resource_page)
    register("GET", "/api/instances/{name}/logs/{target}", pod_logs_api)
    register("GET", "/instances/{name}/logs/{target}", pod_logs_page)
    register("POST", "/instances/save", save_instance)
    register("POST", "/instances/{name}/sync", sync_now)
    register("POST", "/instances/{name}/toggle", toggle_instance)
    register("POST", "/instances/{name}/delete", delete_instance_route)
    app.router.add_static("/assets", str(STATIC_DIR), show_index=False)
    if settings.base_path:
        app.router.add_static(f"{settings.base_path}/assets", str(STATIC_DIR), show_index=False)
    return app


def run_ui() -> int:
    """Run the UI service."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    settings = load_ui_settings()
    get_kube_clients()
    app = _create_app(settings)
    web.run_app(app, host=settings.host, port=settings.port)
    return 0
