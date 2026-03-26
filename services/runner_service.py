from __future__ import annotations

import logging
import os
from pathlib import Path

from aiohttp import web

from steam.steamcmd import download_mod_archive


def _runner_host() -> str:
    return os.environ.get("RUNNER_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"


def _runner_port() -> int:
    try:
        return int(os.environ.get("RUNNER_BIND_PORT", "8080"))
    except ValueError:
        return 8080


def _steam_root() -> Path:
    return Path(os.environ.get("STEAM_ROOT", "/data/runner/steam"))


def _steamcmd_path() -> Path:
    return Path(os.environ.get("STEAMCMD_PATH", "/opt/steamcmd/steamcmd.sh"))


async def _healthz(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def _archive(request: web.Request) -> web.StreamResponse:
    payload = await request.json()
    app_id = int(payload.get("appId") or 0)
    workshop_id = int(payload.get("workshopId") or 0)
    if app_id <= 0 or workshop_id <= 0:
        return web.json_response(
            {"reason": "appId and workshopId are required", "retryable": False},
            status=400,
        )
    archive_path = _steam_root() / "archives" / f"{app_id}-{workshop_id}.zip"
    result = await request.app["loop"].run_in_executor(
        None,
        lambda: download_mod_archive(
            _steamcmd_path(),
            _steam_root(),
            app_id,
            workshop_id,
            archive_path,
            None,
        ),
    )
    if not result.ok or result.archive_path is None:
        return web.json_response(
            {
                "reason": result.reason or "archive build failed",
                "retryable": result.retryable,
                "diagnostics": result.diagnostics,
            },
            status=502,
        )
    return web.FileResponse(
        path=result.archive_path,
        headers={
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="{workshop_id}.zip"',
        },
    )


def _create_app() -> web.Application:
    app = web.Application()
    app["loop"] = None
    app.router.add_get("/healthz", _healthz)
    app.router.add_post("/api/v1/archive", _archive)

    async def on_startup(application: web.Application) -> None:
        import asyncio

        application["loop"] = asyncio.get_running_loop()

    app.on_startup.append(on_startup)
    return app


def run_runner() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    app = _create_app()
    web.run_app(app, host=_runner_host(), port=_runner_port())
    return 0
