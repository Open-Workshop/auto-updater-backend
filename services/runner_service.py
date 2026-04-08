from __future__ import annotations

import logging
import os
from pathlib import Path

from aiohttp import web

from steam.depot_downloader import download_mod_archive


def _runner_host() -> str:
    return os.environ.get("RUNNER_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"


def _runner_port() -> int:
    try:
        return int(os.environ.get("RUNNER_BIND_PORT", "8080"))
    except ValueError:
        return 8080


def _steam_root() -> Path:
    return Path(os.environ.get("STEAM_ROOT", "/data/runner/steam"))


def _depotdownloader_path() -> Path:
    return Path(os.environ.get("DEPOTDOWNLOADER_PATH", "/opt/depotdownloader/DepotDownloader"))


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
            _depotdownloader_path(),
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


async def _archive_done(request: web.Request) -> web.Response:
    payload = await request.json()
    app_id = int(payload.get("appId") or 0)
    workshop_id = int(payload.get("workshopId") or 0)
    if app_id <= 0 or workshop_id <= 0:
        return web.json_response(
            {"reason": "appId and workshopId are required"},
            status=400,
        )
    
    import shutil
    archive_path = _steam_root() / "archives" / f"{app_id}-{workshop_id}.zip"
    workshop_path = (
        _steam_root()
        / "steamapps"
        / "workshop"
        / "content"
        / str(app_id)
        / str(workshop_id)
    )
    
    cleaned = []
    if archive_path.exists():
        archive_path.unlink(missing_ok=True)
        cleaned.append(str(archive_path))
    if workshop_path.exists():
        shutil.rmtree(workshop_path, ignore_errors=True)
        cleaned.append(str(workshop_path))
    
    if cleaned:
        logging.info("Cleaned after archive done: %s", cleaned)
    
    return web.json_response({"cleaned": cleaned})


def _create_app() -> web.Application:
    app = web.Application()
    app["loop"] = None
    app.router.add_get("/healthz", _healthz)
    app.router.add_post("/api/v1/archive", _archive)
    app.router.add_post("/api/v1/archive/done", _archive_done)

    async def on_startup(application: web.Application) -> None:
        import asyncio

        application["loop"] = asyncio.get_running_loop()

    app.on_startup.append(on_startup)
    return app


def _cleanup_old_archives(max_age_seconds: int = 3600) -> None:
    import time
    archives_dir = _steam_root() / "archives"
    if not archives_dir.exists():
        return
    now = time.time()
    cleaned = 0
    for f in archives_dir.iterdir():
        if f.is_file() and f.suffix == ".zip":
            age = now - f.stat().st_mtime
            if age > max_age_seconds:
                f.unlink(missing_ok=True)
                cleaned += 1
    if cleaned:
        logging.info("Cleaned %d old archive(s)", cleaned)


def run_runner() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    _cleanup_old_archives()
    app = _create_app()
    web.run_app(app, host=_runner_host(), port=_runner_port())
    return 0
