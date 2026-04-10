from __future__ import annotations

import queue
import threading
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from steam.steam_mod import SteamMod


@dataclass(frozen=True)
class SyncOptions:
    page_size: int
    timeout: int
    max_pages: int
    start_page: int
    max_items: int
    page_delay: float
    max_screenshots: int
    public_mode: int
    without_author: bool
    sync_tags: bool
    prune_tags: bool
    sync_dependencies: bool
    prune_dependencies: bool
    sync_resources: bool
    prune_resources: bool
    upload_resource_files: bool
    scrape_preview_images: bool
    scrape_required_items: bool
    force_required_item_id: Optional[str]
    language: str


@dataclass
class ModPayload:
    mod: SteamMod
    title: str
    short_desc: str
    description: str
    tags: List[str]
    deps: List[str]
    deps_ok: bool
    images: List[str]
    images_incomplete: bool
    ow_mod: Optional[Dict[str, Any]]
    ow_mod_id: Optional[int]
    is_new: bool


@dataclass(frozen=True)
class DownloadTask:
    item_id: str
    payload: ModPayload


@dataclass(frozen=True)
class ReadyTask:
    item_id: str
    payload: ModPayload
    archive_path: Path | None = None


class WorkQueue:
    def __init__(self) -> None:
        self.meta_queue: queue.Queue[str] = queue.Queue()
        self.queued_ids: set[str] = set()
        self.download_queue: queue.Queue[DownloadTask] = queue.Queue()
        self.ready_queue: queue.Queue[ReadyTask] = queue.Queue()
        self._lock = threading.Lock()
        self._producer_done = threading.Event()
        self._downloader_done = threading.Event()
        self._downloader_workers_total = 1
        self._downloader_workers_done = 0

    def enqueue_metadata(self, item_id: str) -> None:
        item_id = str(item_id)
        with self._lock:
            if item_id in self.queued_ids:
                return
            self.queued_ids.add(item_id)
        self.meta_queue.put(item_id)

    def enqueue_download(self, item_id: str, payload: ModPayload) -> None:
        self.download_queue.put(DownloadTask(item_id=str(item_id), payload=payload))

    def enqueue_ready(
        self,
        item_id: str,
        payload: ModPayload,
        *,
        archive_path: Path | None = None,
    ) -> None:
        self.ready_queue.put(
            ReadyTask(
                item_id=str(item_id),
                payload=payload,
                archive_path=archive_path,
            )
        )

    def pop_meta_batch(self, max_size: int, timeout: float = 0.2) -> List[str]:
        batch: List[str] = []
        try:
            batch.append(self.meta_queue.get(timeout=timeout))
        except queue.Empty:
            return batch
        while len(batch) < max_size:
            try:
                batch.append(self.meta_queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def pop_download(self, timeout: float = 0.2) -> Optional[DownloadTask]:
        try:
            return self.download_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def pop_ready(self, timeout: float = 0.2) -> Optional[ReadyTask]:
        try:
            return self.ready_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def has_metadata(self) -> bool:
        return not self.meta_queue.empty()

    def downstream_backlog(self) -> int:
        return max(0, self.download_queue.qsize()) + max(0, self.ready_queue.qsize())

    def finish_producer(self) -> None:
        self._producer_done.set()

    def producer_finished(self) -> bool:
        return self._producer_done.is_set()

    def configure_downloaders(self, worker_count: int) -> None:
        with self._lock:
            self._downloader_workers_total = max(1, int(worker_count))
            self._downloader_workers_done = 0
            self._downloader_done.clear()

    def finish_downloader(self) -> None:
        with self._lock:
            self._downloader_workers_done += 1
            if self._downloader_workers_done >= self._downloader_workers_total:
                self._downloader_done.set()

    def downloader_finished(self) -> bool:
        return self._downloader_done.is_set()


class ModIndex:
    def __init__(self) -> None:
        self._cache: Dict[str, Optional[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def get(self, source_id: str) -> Optional[Dict[str, Any]]:
        key = str(source_id)
        with self._lock:
            value = self._cache.get(key)
            return deepcopy(value) if value is not None else None

    def has(self, source_id: str) -> bool:
        with self._lock:
            return str(source_id) in self._cache

    def set(self, source_id: str, mod: Dict[str, Any]) -> None:
        with self._lock:
            self._cache[str(source_id)] = deepcopy(mod)

    def remember_many(
        self,
        source_ids: List[str],
        mods_by_source_id: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        rendered_ids = [str(item) for item in source_ids]
        with self._lock:
            for source_id in rendered_ids:
                if source_id in self._cache:
                    continue
                mod = mods_by_source_id.get(source_id)
                self._cache[source_id] = deepcopy(mod) if mod is not None else None
            return {
                source_id: (
                    deepcopy(self._cache[source_id])
                    if self._cache.get(source_id) is not None
                    else None
                )
                for source_id in rendered_ids
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
