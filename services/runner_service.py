from __future__ import annotations

import logging
import os
import shutil
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


def _archive_paths(app_id: int, workshop_id: int) -> tuple[Path, Path]:
    archive_path = _steam_root() / "archives" / f"{app_id}-{workshop_id}.zip"
    workshop_path = (
        _steam_root()
        / "steamapps"
        / "workshop"
        / "content"
        / str(app_id)
        / str(workshop_id)
    )
    return archive_path, workshop_path


def _cleanup_archive_artifacts(app_id: int, workshop_id: int) -> list[str]:
    archive_path, workshop_path = _archive_paths(app_id, workshop_id)
    cleaned: list[str] = []
    if archive_path.exists():
        try:
            archive_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            logging.warning("Failed to remove archive %s: %s", archive_path, exc)
        else:
            cleaned.append(str(archive_path))
    if workshop_path.exists():
        try:
            shutil.rmtree(workshop_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logging.warning("Failed to remove workshop path %s: %s", workshop_path, exc)
        else:
            cleaned.append(str(workshop_path))
    return cleaned


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
    cleaned = _cleanup_archive_artifacts(app_id, workshop_id)

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
    now = time.time()
    cleaned_archives = 0
    if archives_dir.exists():
        for archive_file in archives_dir.iterdir():
            if not archive_file.is_file() or archive_file.suffix != ".zip":
                continue
            try:
                age = now - archive_file.stat().st_mtime
            except FileNotFoundError:
                continue
            if age <= max_age_seconds:
                continue
            try:
                archive_file.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                logging.warning("Failed to remove stale archive %s: %s", archive_file, exc)
            else:
                cleaned_archives += 1

    content_dir = _steam_root() / "steamapps" / "workshop" / "content"
    cleaned_workshops = 0
    if content_dir.exists():
        for app_dir in content_dir.iterdir():
            if not app_dir.is_dir() or app_dir.is_symlink():
                continue
            for workshop_dir in app_dir.iterdir():
                if not workshop_dir.is_dir() or workshop_dir.is_symlink():
                    continue
                try:
                    age = now - workshop_dir.stat().st_mtime
                except FileNotFoundError:
                    continue
                if age <= max_age_seconds:
                    continue
                try:
                    shutil.rmtree(workshop_dir)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    logging.warning(
                        "Failed to remove stale workshop path %s: %s",
                        workshop_dir,
                        exc,
                    )
                else:
                    cleaned_workshops += 1

    if cleaned_archives or cleaned_workshops:
        logging.info(
            "Cleaned %d old archive(s) and %d old workshop path(s)",
            cleaned_archives,
            cleaned_workshops,
        )


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
