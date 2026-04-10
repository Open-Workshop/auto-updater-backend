from __future__ import annotations

import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from core.telemetry import start_span
from core.utils import (
    dedupe_images,
    has_files,
    strip_bbcode,
    truncate,
    zip_directory,
)
from ow.ow_api import ApiClient
from steam.depot_downloader import download_mod_archive
from steam.steam_api import (
    steam_fetch_workshop_page_ids_html,
    steam_stats_reset,
    steam_stats_snapshot,
)
from steam.steam_mod import SteamMod
from sync.state import DownloadTask, ModIndex, ModPayload, ReadyTask, SyncOptions, WorkQueue
from sync.support import (
    DEPOTDOWNLOADER_MAX_DOWNLOAD_ATTEMPTS,
    DEPOTDOWNLOADER_RETRY_BACKOFF_SECONDS,
    OW_LOG,
    PARSER_LOG,
    STEAM_LOG,
    DependencyManager,
    ResourceSyncer,
    SteamModLoader,
    TagManager,
    ensure_game,
    ow_recent_edit as _ow_recent_edit,
    parse_ow_datetime as _parse_ow_datetime,
    recent_edit_window_label as _recent_edit_window_label,
)
CATALOG_BACKPRESSURE_HIGH_WATERMARK = 10
CATALOG_BACKPRESSURE_LOW_WATERMARK = 5
CATALOG_BACKPRESSURE_POLL_SECONDS = 0.2
OW_WORKER_COUNT = 3


class ModSyncer:
    def __init__(
        self,
        api: ApiClient,
        steam_app_id: int,
        game_id: int,
        mirror_root: Path,
        steam_root: Path,
        depotdownloader_path: Path,
        steamcmd_runner_url: str | None,
        options: SyncOptions,
    ) -> None:
        self.api = api
        self.steam_app_id = steam_app_id
        self.game_id = game_id
        self.mirror_root = mirror_root
        self.steam_root = steam_root
        self.depotdownloader_path = depotdownloader_path
        self.steamcmd_runner_url = steamcmd_runner_url
        self.options = options

        self.queue = WorkQueue()
        self.stop_requested = threading.Event()
        self._worker_error: Exception | None = None
        self._worker_error_lock = threading.Lock()
        self.lookup_api: ApiClient | None = None
        self.start_page = max(1, int(options.start_page))
        self.page = self.start_page
        self.listed_count = 0
        self.mod_index = ModIndex()
        self.steam_mod_cache: Dict[str, SteamMod] = {}
        self.catalog_backpressure_high_watermark = CATALOG_BACKPRESSURE_HIGH_WATERMARK
        self.catalog_backpressure_low_watermark = CATALOG_BACKPRESSURE_LOW_WATERMARK
        self.ow_worker_count = OW_WORKER_COUNT
        self._catalog_backpressure_active = False
        self._ow_worker_state = threading.local()
        self.tag_manager = TagManager(
            api,
            game_id,
            options.page_size,
            enabled=options.sync_tags,
            prune=options.prune_tags,
        )
        self.dependency_manager = DependencyManager(
            api,
            enabled=options.sync_dependencies,
            prune=options.prune_dependencies,
            scrape_required_items=options.scrape_required_items,
            enqueue_metadata=self.queue.enqueue_metadata,
            lookup_mod=self.mod_index.get,
        )
        self.resource_syncer = ResourceSyncer(
            api,
            mirror_root,
            timeout=options.timeout,
            enabled=options.sync_resources,
            prune=options.prune_resources,
            upload_files=options.upload_resource_files,
        )
        self.mod_loader = SteamModLoader(options.timeout, options.language)

    def run(self) -> None:
        with start_span(
            "sync.run",
            {
                "steam.app_id": self.steam_app_id,
                "ow.game_id": self.game_id,
                "sync.max_items": self.options.max_items,
                "sync.max_pages": self.options.max_pages,
                "sync.forced_item": bool(self.options.force_required_item_id),
            },
        ):
            self._clear_local_caches("startup")
            steam_stats_reset()
            self.tag_manager.preload()
            self.lookup_api = self._create_lookup_api()
            producer = threading.Thread(
                target=self._run_producer,
                name="steam-producer",
            )
            downloader = threading.Thread(
                target=self._run_downloader,
                name="steam-downloader",
            )
            ow_worker = threading.Thread(
                target=self._run_ow_worker,
                name="ow-worker-1",
            )
            ow_workers = [ow_worker]
            for index in range(1, self.ow_worker_count):
                ow_workers.append(
                    threading.Thread(
                        target=self._run_ow_worker,
                        name=f"ow-worker-{index + 1}",
                    )
                )
            try:
                producer.start()
                downloader.start()
                for worker in ow_workers:
                    worker.start()
                producer.join()
                downloader.join()
                for worker in ow_workers:
                    worker.join()
            finally:
                if self.lookup_api is not None:
                    self.lookup_api.session.close()
                    self.lookup_api = None
            if self._worker_error is not None:
                raise self._worker_error
            self.dependency_manager.retry_pending()

            stats = steam_stats_snapshot()
            if stats.get("total"):
                STEAM_LOG.info(
                    "Steam requests: total=%s ok=%s failed=%s endpoints=%s",
                    stats.get("total"),
                    stats.get("success"),
                    stats.get("failed"),
                    stats.get("by_endpoint"),
                )

    def _create_lookup_api(self) -> ApiClient:
        lookup_api = ApiClient(
            self.api.base_url,
            self.api.login_name,
            self.api.password,
            self.api.timeout,
            retries=self.api.retries,
            retry_backoff=self.api.retry_backoff,
            limits=self.api.limits,
        )
        lookup_api.login()
        return lookup_api

    def _record_worker_error(self, exc: Exception) -> None:
        with self._worker_error_lock:
            if self._worker_error is None:
                self._worker_error = exc
        self.stop_requested.set()

    def _wait_for_catalog_capacity(self) -> None:
        high_watermark = max(1, int(self.catalog_backpressure_high_watermark))
        low_watermark = min(
            max(0, int(self.catalog_backpressure_low_watermark)),
            high_watermark - 1,
        )
        while not self.stop_requested.is_set():
            backlog = self.queue.downstream_backlog()
            if self._catalog_backpressure_active:
                if backlog <= low_watermark:
                    STEAM_LOG.info(
                        "Catalog producer resumed: downstream_backlog=%s low_watermark=%s",
                        backlog,
                        low_watermark,
                    )
                    self._catalog_backpressure_active = False
                    return
                time.sleep(CATALOG_BACKPRESSURE_POLL_SECONDS)
                continue
            if backlog >= high_watermark:
                self._catalog_backpressure_active = True
                STEAM_LOG.info(
                    "Catalog producer paused: downstream_backlog=%s high_watermark=%s",
                    backlog,
                    high_watermark,
                )
                time.sleep(CATALOG_BACKPRESSURE_POLL_SECONDS)
                continue
            return

    def _run_producer(self) -> None:
        try:
            if self.options.force_required_item_id:
                self.queue.enqueue_metadata(str(self.options.force_required_item_id))
                STEAM_LOG.info("Steam workshop items: 1 (forced)")
            else:
                STEAM_LOG.info(
                    "Steam workshop listing: start_page=%s max_items=%s max_pages=%s",
                    self.start_page,
                    self.options.max_items or "unlimited",
                    self.options.max_pages or "unlimited",
                )

            while not self.stop_requested.is_set():
                self._wait_for_catalog_capacity()
                if self.stop_requested.is_set():
                    break
                batch_ids = self.queue.pop_meta_batch(30)
                if batch_ids:
                    self._process_metadata_batch(batch_ids)
                    continue
                if self.options.force_required_item_id:
                    break
                if (
                    self.options.max_items > 0
                    and self.listed_count >= self.options.max_items
                ):
                    break
                if not self._fetch_next_page():
                    break
        except Exception as exc:
            STEAM_LOG.exception("Steam producer failed")
            self._record_worker_error(exc)
        finally:
            self.queue.finish_producer()

    def _run_downloader(self) -> None:
        try:
            while not self.stop_requested.is_set():
                task = self.queue.pop_download()
                if task is not None:
                    self._process_download_task(task)
                    continue
                if self.queue.producer_finished():
                    break
        except Exception as exc:
            STEAM_LOG.exception("Steam downloader failed")
            self._record_worker_error(exc)
        finally:
            self.queue.finish_downloader()

    def _run_ow_worker(self) -> None:
        worker_api: ApiClient | None = None
        try:
            worker_api = self._create_lookup_api()
            self._ow_worker_state.api = worker_api
            self._ow_worker_state.tag_manager = self.tag_manager.clone(worker_api)
            self._ow_worker_state.dependency_manager = self.dependency_manager.clone(
                worker_api
            )
            self._ow_worker_state.resource_syncer = self.resource_syncer.clone(
                worker_api
            )
            while not self.stop_requested.is_set():
                task = self.queue.pop_ready()
                if task is not None:
                    self._process_ready_task(task)
                    continue
                if self.queue.downloader_finished():
                    break
        except Exception as exc:
            OW_LOG.exception("OW worker failed")
            self._record_worker_error(exc)
        finally:
            if worker_api is not None:
                worker_api.session.close()
            self._ow_worker_state.__dict__.clear()

    def _worker_api(self) -> ApiClient:
        api = getattr(self._ow_worker_state, "api", None)
        return api if api is not None else self.api

    def _worker_tag_manager(self) -> TagManager:
        manager = getattr(self._ow_worker_state, "tag_manager", None)
        return manager if manager is not None else self.tag_manager

    def _worker_dependency_manager(self) -> DependencyManager:
        manager = getattr(self._ow_worker_state, "dependency_manager", None)
        return manager if manager is not None else self.dependency_manager

    def _worker_resource_syncer(self) -> ResourceSyncer:
        syncer = getattr(self._ow_worker_state, "resource_syncer", None)
        return syncer if syncer is not None else self.resource_syncer

    def _fetch_next_page(self) -> bool:
        with start_span(
            "steam.list_page",
            {
                "steam.app_id": self.steam_app_id,
                "steam.page": self.page,
                "sync.max_pages": self.options.max_pages,
                "sync.max_items": self.options.max_items,
            },
        ):
            if self.options.max_pages > 0:
                last_page = self.start_page + self.options.max_pages - 1
                if self.page > last_page:
                    return False
            STEAM_LOG.info(
                "Steam workshop page fetch: page=%s max_pages=%s",
                self.page,
                self.options.max_pages or "unlimited",
            )
            page_ids = steam_fetch_workshop_page_ids_html(
                self.steam_app_id,
                self.page,
                self.options.language,
                self.options.timeout,
            )
            if not page_ids:
                return False
            for item_id in page_ids:
                if (
                    self.options.max_items > 0
                    and self.listed_count >= self.options.max_items
                ):
                    break
                self.queue.enqueue_metadata(str(item_id))
                self.listed_count += 1
            self.page += 1
            if self.options.page_delay > 0:
                time.sleep(self.options.page_delay)
            return True

    def _fetch_existing_ow_mods(
        self,
        source_ids: List[str],
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        requested = [str(item) for item in source_ids]
        if not requested:
            return {}
        if self.lookup_api is None:
            return {item: self.mod_index.get(item) for item in requested}
        missing: List[int] = []
        for source_id in requested:
            if self.mod_index.has(source_id):
                continue
            try:
                missing.append(int(source_id))
            except (TypeError, ValueError):
                continue
        found: Dict[str, Dict[str, Any]] = {}
        if missing:
            results = self.lookup_api.get_mods_by_source_ids(
                "steam",
                missing,
                page_size=len(missing),
            )
            for mod in results:
                source_id = mod.get("source_id")
                if source_id is None:
                    continue
                found[str(source_id)] = mod
        return self.mod_index.remember_many(requested, found)

    def _process_metadata_batch(self, batch_ids: List[str]) -> None:
        if not batch_ids:
            return
        with start_span(
            "metadata.batch",
            {"metadata.batch_size": len(batch_ids)},
        ):
            STEAM_LOG.info("Process metadata batch: size=%s", len(batch_ids))
            now_ts = int(time.time())
            window_label = _recent_edit_window_label()
            ow_mod_map = self._fetch_existing_ow_mods(batch_ids)
            fetch_ids: List[str] = []
            skipped_recent = 0
            for workshop_id in batch_ids:
                ow_mod = ow_mod_map.get(str(workshop_id))
                if ow_mod and _ow_recent_edit(ow_mod, now_ts):
                    skipped_recent += 1
                    STEAM_LOG.info(
                        "Skipping Steam fetch for %s (recent OW edit within %s)",
                        ow_mod.get("id") or workshop_id,
                        window_label,
                    )
                    continue
                fetch_ids.append(str(workshop_id))
            if not fetch_ids:
                STEAM_LOG.info(
                    "Skipped %s mods from Steam fetch due to recent edits",
                    skipped_recent,
                )
                return
            if skipped_recent:
                STEAM_LOG.info(
                    "Skipped %s mods from Steam fetch due to recent edits",
                    skipped_recent,
                )
            mod_map = self.mod_loader.load_batch(fetch_ids)
            self.steam_mod_cache.update(mod_map)

            for workshop_id in fetch_ids:
                mod = self.steam_mod_cache.get(str(workshop_id))
                if not mod:
                    STEAM_LOG.warning("Steam page missing for %s", workshop_id)
                    continue
                with start_span(
                    "mod.payload_build",
                    {"steam.item_id": str(workshop_id)},
                ):
                    payload = self._build_payload(mod, workshop_id)
                if payload is None:
                    continue
                if payload.ow_mod_id is not None and _ow_recent_edit(payload.ow_mod):
                    OW_LOG.info(
                        "Skipping OW mod %s (recent edit within %s)",
                        payload.ow_mod_id,
                        _recent_edit_window_label(),
                    )
                    continue
                if self._needs_file_update(mod, payload.ow_mod):
                    STEAM_LOG.info(
                        "Queue download for %s (new=%s)",
                        workshop_id,
                        payload.ow_mod_id is None,
                    )
                    self.queue.enqueue_download(str(workshop_id), payload)
                    continue

                if payload.ow_mod_id is None:
                    continue

                OW_LOG.info("Queue OW metadata update for %s", payload.ow_mod_id)
                self.queue.enqueue_ready(str(workshop_id), payload)

    def _process_download_task(self, task: DownloadTask) -> None:
        item_id = task.item_id
        payload = task.payload
        STEAM_LOG.info(
            "Downloading Steam mod %s (payload_new=%s)",
            item_id,
            payload.is_new,
        )
        archive_path = self._download_mod_archive(item_id)
        if not archive_path:
            STEAM_LOG.error("Steam download failed for %s", item_id)
            return
        self.queue.enqueue_ready(item_id, payload, archive_path=archive_path)

    def _process_ready_task(self, task: ReadyTask) -> None:
        if task.archive_path is None:
            self._process_metadata_update(task.item_id, task.payload)
        else:
            self._process_file_update(task.item_id, task.payload, task.archive_path)
        self._worker_dependency_manager().retry_pending()

    def _process_metadata_update(self, item_id: str, payload: ModPayload) -> None:
        if payload.ow_mod_id is None:
            return
        api = self._worker_api()
        tag_manager = self._worker_tag_manager()
        dependency_manager = self._worker_dependency_manager()
        resource_syncer = self._worker_resource_syncer()
        OW_LOG.info("Updating OW mod %s metadata", payload.ow_mod_id)
        with start_span(
            "ow.mod_upsert",
            {
                "ow.mod_id": payload.ow_mod_id,
                "steam.item_id": str(item_id),
                "ow.mode": "metadata_update",
            },
        ):
            api.edit_mod(
                payload.ow_mod_id,
                payload.title,
                payload.short_desc,
                payload.description,
                "steam",
                int(item_id),
                self.game_id,
                self.options.public_mode,
                set_source=False,
            )
        tag_manager.sync_mod_tags(payload.ow_mod_id, payload.tags)
        dependency_manager.sync_dependencies(
            payload.ow_mod_id,
            payload.deps,
            payload.deps_ok,
        )
        resource_syncer.sync_resources(
            payload.ow_mod_id,
            payload.mod,
            payload.images,
            payload.images_incomplete,
        )

    def _process_file_update(
        self,
        item_id: str,
        payload: ModPayload,
        archive_path: Path,
    ) -> None:
        api = self._worker_api()
        tag_manager = self._worker_tag_manager()
        dependency_manager = self._worker_dependency_manager()
        resource_syncer = self._worker_resource_syncer()
        ow_mod = payload.ow_mod
        ow_mod_id = payload.ow_mod_id
        if ow_mod is None:
            ow_mod = api.get_mod_by_source("steam", int(item_id))
            if ow_mod is not None:
                mod_id = ow_mod.get("id")
                try:
                    ow_mod_id = int(mod_id) if mod_id is not None else None
                except (TypeError, ValueError):
                    ow_mod_id = None
                if ow_mod_id is not None:
                    self.mod_index.set(
                        str(item_id),
                        {
                            "id": int(ow_mod_id),
                            "source_id": int(item_id),
                        },
                    )
        if ow_mod is not None and _ow_recent_edit(ow_mod):
            OW_LOG.info(
                "Skipping OW mod %s download (recent edit within %s)",
                ow_mod_id,
                _recent_edit_window_label(),
            )
            self._notify_archive_done(item_id)
            self._safe_unlink(archive_path)
            return

        try:
            with start_span(
                "ow.mod_upsert",
                {
                    "ow.mod_id": int(payload.ow_mod_id) if payload.ow_mod_id else None,
                    "steam.item_id": str(item_id),
                    "ow.mode": "upsert_with_file",
                },
            ):
                ow_mod_id, created_now = api.upsert_mod_with_file(
                    payload.title,
                    payload.short_desc,
                    payload.description,
                    "steam",
                    int(item_id),
                    self.game_id,
                    self.options.public_mode,
                    self.options.without_author,
                    archive_path,
                )
            self.mod_index.set(
                str(item_id),
                {
                    "id": int(ow_mod_id),
                    "source_id": int(item_id),
                    "date_update_file": datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                },
            )
            if created_now:
                OW_LOG.info("Created OW mod %s for %s", int(ow_mod_id), item_id)
            else:
                OW_LOG.info("Updated OW mod %s file", int(ow_mod_id))

            if ow_mod_id is None:
                return

            tag_manager.sync_mod_tags(int(ow_mod_id), payload.tags)
            dependency_manager.sync_dependencies(
                int(ow_mod_id),
                payload.deps,
                payload.deps_ok,
            )
            resource_syncer.sync_resources(
                int(ow_mod_id),
                payload.mod,
                payload.images,
                payload.images_incomplete,
            )
        finally:
            self._notify_archive_done(item_id)
            self._safe_unlink(archive_path)

    def _clear_local_caches(self, reason: str) -> None:
        self.mod_index.clear()
        self.steam_mod_cache.clear()
        appworkshop_acf = (
            self.steam_root
            / "steamapps"
            / "workshop"
            / f"appworkshop_{self.steam_app_id}.acf"
        )
        self._safe_unlink(appworkshop_acf)
        cache_dirs = (
            self.mirror_root / "steam_archives",
            self.mirror_root / "resources",
            self.steam_root / "steamapps" / "workshop" / "downloads",
            self.steam_root / "steamapps" / "workshop" / "content",
        )
        for cache_dir in cache_dirs:
            self._clear_directory_contents(cache_dir, reason)

    def _clear_directory_contents(self, path: Path, reason: str) -> None:
        if not path.exists():
            return
        if not path.is_dir():
            PARSER_LOG.warning(
                "Skip cache cleanup for %s (%s): path is not a directory",
                path,
                reason,
            )
            return
        removed = 0
        for child in path.iterdir():
            try:
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
                removed += 1
            except FileNotFoundError:
                continue
            except Exception as exc:
                PARSER_LOG.warning(
                    "Failed to delete cache entry %s (%s): %s",
                    child,
                    reason,
                    exc,
                )
        if removed:
            PARSER_LOG.info("Cache cleanup %s (%s): removed=%s", path, reason, removed)

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except Exception as exc:
            PARSER_LOG.warning("Failed to remove archive %s: %s", path, exc)

    def _build_payload(self, mod: SteamMod, workshop_id: str) -> Optional[ModPayload]:
        title = mod.title
        if not title:
            title = f"Steam Mod {workshop_id}"
            STEAM_LOG.warning("Steam %s missing title, using fallback", workshop_id)
        raw_description = mod.description
        tags = mod.tags
        STEAM_LOG.debug("Steam %s tags: %s", workshop_id, tags)

        short_desc = strip_bbcode(raw_description)
        if not short_desc:
            short_desc = title
        short_desc = truncate(short_desc, 256)
        description = truncate(raw_description, 10000)
        title, short_desc, description = self.api.limit_mod_fields(
            title, short_desc, description
        )

        ow_mod = self.mod_index.get(str(workshop_id))
        ow_mod_id = int(ow_mod.get("id")) if ow_mod else None
        is_existing_mod = ow_mod_id is not None

        allow_image_scrape = (not is_existing_mod) or self.options.scrape_preview_images
        images_incomplete = is_existing_mod and not allow_image_scrape

        page_deps = [str(dep) for dep in mod.dependencies if dep]
        page_deps = [dep for dep in page_deps if dep != str(workshop_id)]
        page_ok = mod.page_ok
        self.dependency_manager.queue_missing_sources(page_deps)

        with start_span(
            "images.prepare_payload",
            {
                "steam.item_id": str(workshop_id),
                "images.scrape_enabled": allow_image_scrape,
                "images.max_screenshots": self.options.max_screenshots,
            },
        ):
            images = self._collect_images(mod, allow_image_scrape)
            if not allow_image_scrape and mod.logo:
                images = [mod.logo]
            images = dedupe_images(images)
            if self.options.max_screenshots > 0 and images:
                logo = images[0]
                screenshots = images[1:]
                if len(screenshots) > self.options.max_screenshots:
                    screenshots = screenshots[: self.options.max_screenshots]
                images = [logo] + screenshots
        STEAM_LOG.debug(
            "Steam %s images: %s (logo=%s extra=%s)",
            workshop_id,
            len(images),
            bool(mod.logo),
            "on" if allow_image_scrape else "off",
        )

        return ModPayload(
            mod=mod,
            title=title,
            short_desc=short_desc,
            description=description,
            tags=tags,
            deps=page_deps,
            deps_ok=page_ok,
            images=images,
            images_incomplete=images_incomplete,
            ow_mod=ow_mod,
            ow_mod_id=ow_mod_id,
            is_new=ow_mod_id is None,
        )

    def _collect_images(self, mod: SteamMod, allow_image_scrape: bool) -> List[str]:
        images: List[str] = []
        if mod.logo:
            images.append(mod.logo)
        if allow_image_scrape:
            images.extend(mod.screenshots)
        return [url for url in images if url]

    def _needs_file_update(
        self,
        mod: SteamMod,
        ow_mod: Optional[Dict[str, Any]],
    ) -> bool:
        with start_span("mod.file_update_decision"):
            if ow_mod is None:
                return True
            steam_latest_ts = max(mod.updated_ts, mod.created_ts)
            ow_updated_file_ts = _parse_ow_datetime(
                (ow_mod.get("date_update_file") or ow_mod.get("date_creation"))
                if ow_mod
                else None
            )
            ow_created_ts = _parse_ow_datetime(
                ow_mod.get("date_creation") if ow_mod else None
            )
            ow_latest_ts = max(ow_updated_file_ts, ow_created_ts)
            return steam_latest_ts > ow_latest_ts

    def _download_mod_archive(self, item_id: str) -> Optional[Path]:
        with start_span(
            "mod.download_archive",
            {
                "steam.item_id": str(item_id),
                "steam.app_id": self.steam_app_id,
            },
        ):
            for attempt in range(1, DEPOTDOWNLOADER_MAX_DOWNLOAD_ATTEMPTS + 1):
                download_result = download_mod_archive(
                    self.depotdownloader_path,
                    self.steam_root,
                    self.steam_app_id,
                    int(item_id),
                    self.mirror_root / "steam_archives" / f"{item_id}.zip",
                    self.steamcmd_runner_url,
                )
                if download_result.ok:
                    return download_result.archive_path
                reason = download_result.reason or "unknown reason"
                STEAM_LOG.error(
                    "SteamCMD download attempt %s/%s failed for %s: %s",
                    attempt,
                    DEPOTDOWNLOADER_MAX_DOWNLOAD_ATTEMPTS,
                    item_id,
                    reason,
                )
                if attempt >= DEPOTDOWNLOADER_MAX_DOWNLOAD_ATTEMPTS or not download_result.retryable:
                    return None
                delay = DEPOTDOWNLOADER_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1))
                STEAM_LOG.warning(
                    "Retrying SteamCMD download for %s in %.1fs",
                    item_id,
                    delay,
                )
                time.sleep(delay)
        return None
    
    def _notify_archive_done(self, item_id: str) -> None:
        if not self.steamcmd_runner_url:
            return
        response: requests.Response | None = None
        try:
            endpoint = self.steamcmd_runner_url.rstrip("/") + "/api/v1/archive/done"
            response = requests.post(
                endpoint,
                json={"appId": self.steam_app_id, "workshopId": int(item_id)},
                timeout=10,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            details = ""
            if response is not None:
                details = f" status={response.status_code} body={(response.text or '')[:200]!r}"
            PARSER_LOG.warning("Failed to notify archive done: %s%s", exc, details)
        finally:
            if response is not None:
                response.close()

def sync_mods(
    api: ApiClient,
    steam_app_id: int,
    game_id: int,
    mirror_root: Path,
    steam_root: Path,
    page_size: int,
    timeout: int,
    max_pages: int,
    start_page: int,
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
    depotdownloader_path: Path,
    steamcmd_runner_url: Optional[str] = None,
) -> None:
    options = SyncOptions(
        page_size=page_size,
        timeout=timeout,
        max_pages=max_pages,
        start_page=start_page,
        max_items=max_items,
        page_delay=page_delay,
        max_screenshots=max_screenshots,
        public_mode=public_mode,
        without_author=without_author,
        sync_tags=sync_tags,
        prune_tags=prune_tags,
        sync_dependencies=sync_dependencies,
        prune_dependencies=prune_dependencies,
        sync_resources=sync_resources,
        prune_resources=prune_resources,
        upload_resource_files=upload_resource_files,
        scrape_preview_images=scrape_preview_images,
        scrape_required_items=scrape_required_items,
        force_required_item_id=force_required_item_id,
        language=language,
    )
    ModSyncer(
        api,
        steam_app_id,
        game_id,
        mirror_root,
        steam_root,
        depotdownloader_path,
        steamcmd_runner_url,
        options,
    ).run()
