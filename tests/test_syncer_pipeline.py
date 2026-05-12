import importlib
import sys
import threading
import types
import unittest
from contextlib import nullcontext
from pathlib import Path

from sync.state import SourceTagGroup


def _install_syncer_stubs() -> None:
    aiohttp = types.ModuleType("aiohttp")
    aiohttp.ClientTimeout = object
    aiohttp.ClientSession = object
    sys.modules["aiohttp"] = aiohttp

    pil = types.ModuleType("PIL")
    pil.Image = types.SimpleNamespace(open=lambda *_args, **_kwargs: None)
    pil.ImageOps = types.SimpleNamespace(exif_transpose=lambda image: image)
    sys.modules["PIL"] = pil

    imagehash = types.ModuleType("imagehash")
    imagehash.hex_to_hash = lambda _value: 0
    imagehash.phash = lambda _image: 0
    sys.modules["imagehash"] = imagehash

    ow_api = types.ModuleType("ow.ow_api")
    ow_api.ApiClient = object
    sys.modules["ow.ow_api"] = ow_api

    steam_api = types.ModuleType("steam.steam_api")
    steam_api.steam_fetch_workshop_page_ids_html = lambda *_args, **_kwargs: []
    steam_api.steam_get_app_details = lambda *_args, **_kwargs: {}
    steam_api.steam_stats_reset = lambda: None
    steam_api.steam_stats_snapshot = lambda: {}
    sys.modules["steam.steam_api"] = steam_api

    steam_mod = types.ModuleType("steam.steam_mod")
    steam_mod.SteamMod = object
    sys.modules["steam.steam_mod"] = steam_mod

    telemetry = types.ModuleType("core.telemetry")
    telemetry.start_span = lambda *_args, **_kwargs: nullcontext()
    sys.modules["core.telemetry"] = telemetry

    depot_downloader = types.ModuleType("steam.depot_downloader")
    depot_downloader.download_mod_archive = lambda *_args, **_kwargs: None
    sys.modules["steam.depot_downloader"] = depot_downloader

    utils = types.ModuleType("core.utils")
    utils.dedupe_images = lambda items: list(dict.fromkeys(items))
    utils.ensure_dir = lambda _path: None
    utils.has_files = lambda _path: False
    utils.extension_from_headers = lambda *_args, **_kwargs: "zip"
    utils.truncate = lambda value, _limit: value
    utils.zip_directory = lambda *_args, **_kwargs: None
    sys.modules["core.utils"] = utils


def _load_syncer_module():
    _install_syncer_stubs()
    sys.modules.pop("sync.syncer", None)
    return importlib.import_module("sync.syncer")


class _FakeApi:
    @staticmethod
    def limit_mod_fields(title: str, short_desc: str, description: str):
        return title, short_desc, description


class _TagApiStub:
    def __init__(
        self,
        *,
        tags: list[dict] | None = None,
        tag_groups: list[dict] | None = None,
        current_tag_ids: list[int] | None = None,
        next_tag_id: int = 101,
        next_group_id: int = 201,
    ) -> None:
        self.tags = list(tags or [])
        self.tag_groups = list(tag_groups or [])
        self.current_tag_ids = list(current_tag_ids or [])
        self.next_tag_id = next_tag_id
        self.next_group_id = next_group_id
        self.add_tag_calls: list[str] = []
        self.add_tag_requests: list[tuple[str, int | None]] = []
        self.add_tag_group_calls: list[str] = []
        self.patch_tag_calls: list[tuple[int, int | None]] = []
        self.associate_calls: list[tuple[int, int]] = []
        self.add_mod_tag_calls: list[tuple[int, int]] = []
        self.delete_mod_tag_calls: list[tuple[int, int]] = []

    def list_tags(self, game_id: int, page_size: int, *, include: list[str] | None = None) -> list[dict]:
        del game_id, page_size, include
        return list(self.tags)

    def list_tag_groups(self, game_id: int, page_size: int) -> list[dict]:
        del game_id, page_size
        return list(self.tag_groups)

    def get_mod_tags(self, ow_mod_id: int) -> list[int]:
        del ow_mod_id
        return list(self.current_tag_ids)

    def add_tag(self, name: str, *, group_id: int | None = None) -> int:
        self.add_tag_calls.append(name)
        self.add_tag_requests.append((name, group_id))
        tag_id = self.next_tag_id
        self.next_tag_id += 1
        tag_entry: dict[str, object] = {"id": tag_id, "name": name}
        if group_id is not None:
            group_name = next(
                (
                    group.get("name")
                    for group in self.tag_groups
                    if int(group.get("id") or 0) == int(group_id)
                ),
                None,
            )
            tag_entry["group"] = {"id": int(group_id), "name": group_name or f"Group {group_id}"}
        self.tags.append(tag_entry)
        return tag_id

    def add_tag_group(self, name: str) -> int:
        self.add_tag_group_calls.append(name)
        group_id = self.next_group_id
        self.next_group_id += 1
        self.tag_groups.append({"id": group_id, "name": name})
        return group_id

    def patch_tag(self, tag_id: int, *, name: str | None = None, group_id: int | None = None) -> None:
        self.patch_tag_calls.append((tag_id, group_id))
        for tag in self.tags:
            if int(tag.get("id", 0)) != int(tag_id):
                continue
            if name is not None:
                tag["name"] = name
            if group_id is None:
                tag.pop("group", None)
            else:
                group_name = next(
                    (
                        group.get("name")
                        for group in self.tag_groups
                        if int(group.get("id") or 0) == int(group_id)
                    ),
                    None,
                )
                tag["group"] = {"id": int(group_id), "name": group_name or f"Group {group_id}"}
            break

    def associate_game_tag(self, game_id: int, tag_id: int) -> None:
        self.associate_calls.append((game_id, tag_id))

    def add_mod_tag(self, ow_mod_id: int, tag_id: int) -> None:
        self.add_mod_tag_calls.append((ow_mod_id, tag_id))
        if tag_id not in self.current_tag_ids:
            self.current_tag_ids.append(tag_id)

    def delete_mod_tag(self, ow_mod_id: int, tag_id: int) -> None:
        self.delete_mod_tag_calls.append((ow_mod_id, tag_id))
        try:
            self.current_tag_ids.remove(tag_id)
        except ValueError:
            pass


class SyncerPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.syncer = _load_syncer_module()

    def _make_syncer(self, parser_type: str | None = None):
        options = self.syncer.SyncOptions(
            page_size=50,
            timeout=60,
            max_pages=0,
            start_page=1,
            max_items=0,
            page_delay=0.0,
            max_screenshots=0,
            public_mode=0,
            without_author=False,
            sync_tags=False,
            prune_tags=False,
            sync_dependencies=False,
            prune_dependencies=False,
            sync_resources=False,
            prune_resources=False,
            upload_resource_files=False,
            scrape_preview_images=False,
            scrape_required_items=False,
            force_required_item_id=None,
            language="english",
        )
        syncer = self.syncer.ModSyncer(
            _FakeApi(),
            480,
            12,
            Path("/tmp/mirror"),
            Path("/tmp/steam"),
            Path("/tmp/depotdownloader"),
            None,
            options,
            parser_type=parser_type,
        )
        syncer._clear_local_caches = lambda _reason: None
        syncer.tag_manager.preload = lambda: None
        syncer._create_lookup_api = lambda: types.SimpleNamespace(
            session=types.SimpleNamespace(close=lambda: None)
        )
        return syncer

    def test_default_catalog_backpressure_watermarks_are_reduced(self) -> None:
        syncer = self._make_syncer()
        self.assertEqual(syncer.catalog_backpressure_high_watermark, 10)
        self.assertEqual(syncer.catalog_backpressure_low_watermark, 5)
        self.assertEqual(syncer.download_worker_count, 1)
        self.assertEqual(syncer.ow_worker_count, 3)

    def test_tag_manager_uses_grouped_tags_by_name_without_recreating_them(self) -> None:
        api = _TagApiStub(
            tags=[{"id": 42, "name": "Gameplay", "group": {"id": 1, "name": "Version"}}],
            current_tag_ids=[42],
        )
        manager = self.syncer.TagManager(
            api,
            game_id=3,
            page_size=50,
            enabled=True,
            prune=True,
        )

        manager.preload()
        manager.sync_mod_tags(100, ["Gameplay"])

        self.assertEqual(api.add_tag_calls, [])
        self.assertEqual(api.associate_calls, [])
        self.assertEqual(api.add_mod_tag_calls, [])
        self.assertEqual(api.delete_mod_tag_calls, [])

    def test_tag_manager_dedupes_duplicate_tag_names_before_sync(self) -> None:
        api = _TagApiStub(tags=[], current_tag_ids=[], next_tag_id=101)
        manager = self.syncer.TagManager(
            api,
            game_id=3,
            page_size=50,
            enabled=True,
            prune=True,
        )

        manager.sync_mod_tags(100, ["Gameplay", "Gameplay", "Gameplay"])

        self.assertEqual(api.add_tag_calls, ["Gameplay"])
        self.assertEqual(api.associate_calls, [(3, 101)])
        self.assertEqual(api.add_mod_tag_calls, [(100, 101)])
        self.assertEqual(api.delete_mod_tag_calls, [])

    def test_tag_manager_keeps_grouped_tags_out_of_flat_sync(self) -> None:
        api = _TagApiStub(tags=[], current_tag_ids=[], next_tag_id=101, next_group_id=301)
        manager = self.syncer.TagManager(
            api,
            game_id=3,
            page_size=50,
            enabled=True,
            prune=True,
        )

        manager.sync_mod_tags(
            100,
            ["Approved", "Customizable", "Scene", "Sci-Fi", "Wallpaper", "Loose"],
            [
                SourceTagGroup("Miscellaneous", ["Approved", "Customizable"]),
                SourceTagGroup("Type", ["Scene"]),
                SourceTagGroup("Genre", ["Sci-Fi"]),
                SourceTagGroup("Category", ["Wallpaper"]),
            ],
        )

        self.assertEqual(api.add_tag_group_calls, ["Miscellaneous", "Type", "Genre", "Category"])
        self.assertEqual(
            api.add_tag_requests,
            [
                ("Approved", 301),
                ("Customizable", 301),
                ("Scene", 302),
                ("Sci-Fi", 303),
                ("Wallpaper", 304),
                ("Loose", None),
            ],
        )
        self.assertEqual(api.patch_tag_calls, [])
        self.assertEqual(
            api.add_mod_tag_calls,
            [(100, 101), (100, 102), (100, 103), (100, 104), (100, 105), (100, 106)],
        )

    def _payload(self, item_id: str):
        mod = types.SimpleNamespace(item_id=item_id)
        return self.syncer.ModPayload(
            mod=mod,
            title=f"title-{item_id}",
            short_desc="short",
            description="desc",
            tags=[],
            deps=[],
            deps_ok=True,
            images=[],
            images_incomplete=False,
            ow_mod={"id": int(item_id), "source_id": int(item_id)},
            ow_mod_id=int(item_id),
            is_new=False,
        )

    def test_producer_continues_while_ow_worker_is_busy(self) -> None:
        syncer = self._make_syncer()
        first_task_started = threading.Event()
        allow_first_finish = threading.Event()
        second_task_enqueued = threading.Event()
        processed: list[str] = []
        fetch_calls = {"count": 0}

        def fetch_next_page() -> bool:
            fetch_calls["count"] += 1
            if fetch_calls["count"] == 1:
                syncer.queue.enqueue_metadata("1")
                return True
            if fetch_calls["count"] == 2:
                if not first_task_started.wait(timeout=1):
                    raise AssertionError("first task did not start in time")
                syncer.queue.enqueue_metadata("2")
                return True
            return False

        original_enqueue_ready = syncer.queue.enqueue_ready

        def enqueue_ready(item_id, payload, *, archive_path=None):
            original_enqueue_ready(item_id, payload, archive_path=archive_path)
            if str(item_id) == "2":
                second_task_enqueued.set()

        syncer.queue.enqueue_ready = enqueue_ready
        syncer._fetch_next_page = fetch_next_page
        syncer._fetch_existing_ow_mods = lambda ids: {
            str(item_id): {"id": int(item_id), "source_id": int(item_id)}
            for item_id in ids
        }
        syncer.mod_loader.load_batch = lambda ids: {
            str(item_id): types.SimpleNamespace(item_id=str(item_id))
            for item_id in ids
        }
        syncer._build_payload = lambda mod, workshop_id: self._payload(str(workshop_id))
        syncer._needs_file_update = lambda _mod, _ow_mod: False

        def process_ready_task(task) -> None:
            if task.item_id == "1":
                first_task_started.set()
                if not allow_first_finish.wait(timeout=2):
                    raise AssertionError("test did not release first task")
            processed.append(task.item_id)

        syncer._process_ready_task = process_ready_task

        runner = threading.Thread(target=syncer.run, name="test-syncer-run")
        runner.start()
        self.assertTrue(first_task_started.wait(timeout=1))
        self.assertTrue(
            second_task_enqueued.wait(timeout=1),
            "producer should enqueue next OW task while worker is still busy",
        )
        allow_first_finish.set()
        runner.join(timeout=2)
        self.assertFalse(runner.is_alive(), "syncer.run should complete")
        self.assertCountEqual(processed, ["1", "2"])

    def test_ow_worker_handles_metadata_while_download_worker_is_busy(self) -> None:
        syncer = self._make_syncer()
        download_started = threading.Event()
        allow_download_finish = threading.Event()
        metadata_processed = threading.Event()
        file_processed = threading.Event()
        fetch_calls = {"count": 0}

        def fetch_next_page() -> bool:
            fetch_calls["count"] += 1
            if fetch_calls["count"] == 1:
                syncer.queue.enqueue_metadata("1")
                syncer.queue.enqueue_metadata("2")
                return True
            return False

        syncer._fetch_next_page = fetch_next_page
        syncer._fetch_existing_ow_mods = lambda ids: {
            str(item_id): {"id": int(item_id), "source_id": int(item_id)}
            for item_id in ids
        }
        syncer.mod_loader.load_batch = lambda ids: {
            str(item_id): types.SimpleNamespace(item_id=str(item_id))
            for item_id in ids
        }
        syncer._build_payload = lambda mod, workshop_id: self._payload(str(workshop_id))
        syncer._needs_file_update = lambda mod, _ow_mod: str(mod.item_id) == "1"

        def process_download_task(task) -> None:
            download_started.set()
            if not allow_download_finish.wait(timeout=2):
                raise AssertionError("test did not release download task")
            syncer.queue.enqueue_ready(task.item_id, task.payload, archive_path=Path("/tmp/1.zip"))

        def process_ready_task(task) -> None:
            if task.archive_path is None:
                metadata_processed.set()
                return
            file_processed.set()

        syncer._process_download_task = process_download_task
        syncer._process_ready_task = process_ready_task

        runner = threading.Thread(target=syncer.run, name="test-syncer-run")
        runner.start()
        self.assertTrue(download_started.wait(timeout=1))
        self.assertTrue(
            metadata_processed.wait(timeout=1),
            "OW metadata task should complete while download worker is still blocked",
        )
        allow_download_finish.set()
        self.assertTrue(file_processed.wait(timeout=1))
        runner.join(timeout=2)
        self.assertFalse(runner.is_alive(), "syncer.run should complete")

    def test_ow_workers_can_process_multiple_mods_in_parallel(self) -> None:
        syncer = self._make_syncer()
        syncer.ow_worker_count = 2
        first_started = threading.Event()
        second_started = threading.Event()
        overlap_detected = threading.Event()
        allow_finish = threading.Event()
        active: set[str] = set()
        active_lock = threading.Lock()
        fetch_calls = {"count": 0}

        def fetch_next_page() -> bool:
            fetch_calls["count"] += 1
            if fetch_calls["count"] == 1:
                syncer.queue.enqueue_metadata("1")
                syncer.queue.enqueue_metadata("2")
                return True
            return False

        syncer._fetch_next_page = fetch_next_page
        syncer._fetch_existing_ow_mods = lambda ids: {
            str(item_id): {"id": int(item_id), "source_id": int(item_id)}
            for item_id in ids
        }
        syncer.mod_loader.load_batch = lambda ids: {
            str(item_id): types.SimpleNamespace(item_id=str(item_id))
            for item_id in ids
        }
        syncer._build_payload = lambda mod, workshop_id: self._payload(str(workshop_id))
        syncer._needs_file_update = lambda _mod, _ow_mod: False

        def process_ready_task(task) -> None:
            with active_lock:
                active.add(task.item_id)
                if task.item_id == "1":
                    first_started.set()
                if task.item_id == "2":
                    second_started.set()
                if len(active) >= 2:
                    overlap_detected.set()
            if not allow_finish.wait(timeout=2):
                raise AssertionError("test did not release parallel tasks")
            with active_lock:
                active.discard(task.item_id)

        syncer._process_ready_task = process_ready_task

        runner = threading.Thread(target=syncer.run, name="test-syncer-run")
        runner.start()
        self.assertTrue(first_started.wait(timeout=1))
        self.assertTrue(second_started.wait(timeout=1))
        self.assertTrue(
            overlap_detected.wait(timeout=1),
            "ready tasks should overlap when multiple OW workers are enabled",
        )
        allow_finish.set()
        runner.join(timeout=2)
        self.assertFalse(runner.is_alive(), "syncer.run should complete")

    def test_download_workers_can_overlap_archive_tasks(self) -> None:
        syncer = self._make_syncer()
        syncer.steamcmd_runner_url = "http://runner"
        syncer.download_worker_count = 2
        first_started = threading.Event()
        second_started = threading.Event()
        overlap_detected = threading.Event()
        second_ready_processed = threading.Event()
        allow_first_finish = threading.Event()
        processed: list[str] = []
        active: set[str] = set()
        active_lock = threading.Lock()
        fetch_calls = {"count": 0}

        def fetch_next_page() -> bool:
            fetch_calls["count"] += 1
            if fetch_calls["count"] == 1:
                syncer.queue.enqueue_metadata("1")
                syncer.queue.enqueue_metadata("2")
                return True
            return False

        syncer._fetch_next_page = fetch_next_page
        syncer._fetch_existing_ow_mods = lambda ids: {
            str(item_id): {"id": int(item_id), "source_id": int(item_id)}
            for item_id in ids
        }
        syncer.mod_loader.load_batch = lambda ids: {
            str(item_id): types.SimpleNamespace(item_id=str(item_id))
            for item_id in ids
        }
        syncer._build_payload = lambda mod, workshop_id: self._payload(str(workshop_id))
        syncer._needs_file_update = lambda _mod, _ow_mod: True

        def process_download_task(task) -> None:
            with active_lock:
                active.add(task.item_id)
                if task.item_id == "1":
                    first_started.set()
                if task.item_id == "2":
                    second_started.set()
                if len(active) >= 2:
                    overlap_detected.set()
            try:
                if task.item_id == "1":
                    if not allow_first_finish.wait(timeout=2):
                        raise AssertionError("test did not release first archive task")
                syncer.queue.enqueue_ready(
                    task.item_id,
                    task.payload,
                    archive_path=Path(f"/tmp/{task.item_id}.zip"),
                )
            finally:
                with active_lock:
                    active.discard(task.item_id)

        def process_ready_task(task) -> None:
            processed.append(task.item_id)
            if task.item_id == "2":
                second_ready_processed.set()

        syncer._process_download_task = process_download_task
        syncer._process_ready_task = process_ready_task

        runner = threading.Thread(target=syncer.run, name="test-syncer-run")
        runner.start()
        self.assertTrue(first_started.wait(timeout=1))
        self.assertTrue(second_started.wait(timeout=1))
        self.assertTrue(
            overlap_detected.wait(timeout=1),
            "download workers should overlap while the first archive task is still running",
        )
        self.assertTrue(
            second_ready_processed.wait(timeout=1),
            "second archive task should complete while the first one is still blocked",
        )
        allow_first_finish.set()
        runner.join(timeout=2)
        self.assertFalse(runner.is_alive(), "syncer.run should complete")
        self.assertCountEqual(processed, ["1", "2"])

    def test_catalog_producer_waits_for_backlog_to_drop_below_low_watermark(self) -> None:
        syncer = self._make_syncer()
        syncer.catalog_backpressure_high_watermark = 2
        syncer.catalog_backpressure_low_watermark = 1
        syncer.queue.enqueue_ready("101", self._payload("101"))
        syncer.queue.enqueue_ready("102", self._payload("102"))

        fetch_called = threading.Event()

        def fetch_next_page() -> bool:
            fetch_called.set()
            return False

        syncer._fetch_next_page = fetch_next_page

        runner = threading.Thread(target=syncer._run_producer, name="test-producer-backpressure")
        runner.start()

        self.assertFalse(
            fetch_called.wait(timeout=0.3),
            "producer should pause while downstream backlog is at the high watermark",
        )

        syncer.queue.pop_ready(timeout=0.1)

        self.assertTrue(
            fetch_called.wait(timeout=1),
            "producer should resume as soon as backlog falls to the low watermark",
        )
        runner.join(timeout=1)
        self.assertFalse(runner.is_alive(), "producer should exit after fetch_next_page returns False")
        self.assertEqual(syncer.queue.downstream_backlog(), 1)

    def test_build_payload_uses_text_and_image_helpers(self) -> None:
        syncer = self._make_syncer()
        mod = types.SimpleNamespace(
            item_id="42",
            title="Test Mod",
            summary="Short summary",
            description="Some [b]desc[/b]",
            git_url="https://github.com/example/mod",
            tags=["a", "b"],
            dependency_items=[
                self.syncer.SourceDependency("12"),
                self.syncer.SourceDependency("42"),
                self.syncer.SourceDependency("13", optional=True),
            ],
            conflicts=["99", "42"],
            page_ok=True,
            logo="https://cdn/logo.png",
            screenshots=[
                "https://cdn/logo.png",
                "https://cdn/1.png",
                "https://cdn/1.png",
            ],
        )

        payload = syncer._build_payload(mod, "42")

        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload.short_desc, "Short summary")
        self.assertEqual(payload.description, "Some [b]desc[/b]")
        self.assertEqual([dep.source_id for dep in payload.deps], ["12", "13"])
        self.assertEqual([dep.optional for dep in payload.deps], [False, True])
        self.assertEqual(
            payload.images,
            ["https://cdn/logo.png", "https://cdn/1.png"],
        )

    def test_build_payload_converts_factorio_markdown_to_bbcode(self) -> None:
        syncer = self._make_syncer(parser_type="factorio")
        mod = types.SimpleNamespace(
            item_id="43",
            title="Fallback Mod",
            summary="Short summary",
            description=(
                "# Heading\n\n"
                "* item one\n"
                "* item two\n\n"
                "Visit [GitHub](https://github.com).\n\n"
                "![Logo](https://cdn/logo.png)\n"
            ),
            git_url="https://github.com/example/mod",
            tags=[],
            dependencies=[],
            conflicts=[],
            page_ok=True,
            logo="",
            screenshots=[],
        )

        payload = syncer._build_payload(mod, "43")

        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload.short_desc, "Short summary")
        self.assertIn("[h1]Heading[/h1]", payload.description)
        self.assertIn("[list]", payload.description)
        self.assertIn("[url=https://github.com]GitHub[/url]", payload.description)
        self.assertIn("[img]https://cdn/logo.png[/img]", payload.description)

    def test_factorio_file_update_passes_git_url_and_conflicts(self) -> None:
        syncer = self._make_syncer(parser_type="factorio")
        recorded: dict[str, object] = {}

        class ApiStub:
            def upsert_mod_with_file(
                self,
                name,
                short_desc,
                desc,
                source,
                source_id,
                game_id,
                public_mode,
                without_author,
                file_path,
                *,
                existing_id=None,
                git_url=None,
            ):
                recorded["git_url"] = git_url
                return 42, False

        syncer._worker_api = lambda: ApiStub()
        syncer._worker_tag_manager = lambda: types.SimpleNamespace(sync_mod_tags=lambda *args, **kwargs: None)
        syncer._worker_dependency_manager = lambda: types.SimpleNamespace(
            sync_dependencies=lambda ow_mod_id, dep_items, deps_ok: recorded.setdefault(
                "deps",
                [(dep.source_id, dep.optional) for dep in dep_items],
            ),
            retry_pending=lambda: None,
        )
        syncer._worker_conflict_manager = lambda: types.SimpleNamespace(
            sync_conflicts=lambda ow_mod_id, conflict_source_ids: recorded.setdefault("conflicts", list(conflict_source_ids)),
            retry_pending=lambda: None,
        )
        syncer._worker_resource_syncer = lambda: types.SimpleNamespace(sync_resources=lambda *args, **kwargs: None)

        payload = self.syncer.ModPayload(
            mod=types.SimpleNamespace(
                item_id="factorio-dimension-warp",
                git_url="https://github.com/Kyria/dimension-warp",
                conflicts=["dimension-fix"],
                version="0.7.2",
            ),
            title="Dimension Warp",
            short_desc="short",
            description="desc",
            tags=[],
            deps=[
                self.syncer.SourceDependency("dimension-fix"),
                self.syncer.SourceDependency("dimension-opt", optional=True),
            ],
            deps_ok=True,
            images=[],
            images_incomplete=False,
            ow_mod={"id": 42, "source_id": "factorio-dimension-warp"},
            ow_mod_id=42,
            is_new=False,
        )

        syncer._process_file_update("factorio-dimension-warp", payload, Path("/tmp/factorio-dimension-warp.zip"))

        self.assertEqual(recorded["git_url"], "https://github.com/Kyria/dimension-warp")
        self.assertEqual(recorded["conflicts"], ["dimension-fix"])
        self.assertEqual(
            recorded["deps"],
            [("dimension-fix", False), ("dimension-opt", True)],
        )

    def test_dependency_manager_upserts_optional_dependency_flags(self) -> None:
        recorded: list[tuple[str, int, int, bool]] = []

        api = types.SimpleNamespace(
            get_mod_dependency_links=lambda _mod_id: [],
            upsert_mod_dependency=lambda mod_id, dep_id, *, optional=False: recorded.append(
                ("upsert", mod_id, dep_id, optional)
            ),
            delete_mod_dependency=lambda mod_id, dep_id: recorded.append(
                ("delete", mod_id, dep_id, False)
            ),
        )
        manager = self.syncer.DependencyManager(
            api,
            enabled=True,
            prune=True,
            scrape_required_items=True,
            enqueue_metadata=lambda _source_id: None,
            lookup_mod=lambda source_id: {"id": 10} if source_id == "required" else {"id": 11},
        )

        manager.sync_dependencies(
            42,
            [
                self.syncer.SourceDependency("required"),
                self.syncer.SourceDependency("optional", optional=True),
            ],
            deps_ok=True,
        )

        self.assertCountEqual(
            recorded,
            [
                ("upsert", 42, 10, False),
                ("upsert", 42, 11, True),
            ],
        )

    def test_file_update_passes_known_mod_id_to_upsert(self) -> None:
        syncer = self._make_syncer()
        recorded: dict[str, object] = {}

        class ApiStub:
            def upsert_mod_with_file(
                self,
                name,
                short_desc,
                desc,
                source,
                source_id,
                game_id,
                public_mode,
                without_author,
                file_path,
                *,
                existing_id=None,
                git_url=None,
            ):
                recorded["name"] = name
                recorded["source"] = source
                recorded["source_id"] = source_id
                recorded["existing_id"] = existing_id
                return 42, False

        syncer._worker_api = lambda: ApiStub()
        syncer._worker_tag_manager = lambda: types.SimpleNamespace(sync_mod_tags=lambda *args, **kwargs: None)
        syncer._worker_dependency_manager = lambda: types.SimpleNamespace(sync_dependencies=lambda *args, **kwargs: None, retry_pending=lambda: None)
        syncer._worker_conflict_manager = lambda: types.SimpleNamespace(sync_conflicts=lambda *args, **kwargs: None, retry_pending=lambda: None)
        syncer._worker_resource_syncer = lambda: types.SimpleNamespace(sync_resources=lambda *args, **kwargs: None)

        syncer._process_file_update("42", self._payload("42"), Path("/tmp/42.zip"))

        self.assertEqual(recorded["source"], "steam")
        self.assertEqual(recorded["source_id"], "42")
        self.assertEqual(recorded["existing_id"], 42)

    def test_file_update_preserves_string_source_id(self) -> None:
        syncer = self._make_syncer()
        recorded: dict[str, object] = {}

        class ApiStub:
            def upsert_mod_with_file(
                self,
                name,
                short_desc,
                desc,
                source,
                source_id,
                game_id,
                public_mode,
                without_author,
                file_path,
                *,
                existing_id=None,
                git_url=None,
            ):
                recorded["source_id"] = source_id
                return 42, False

        payload = self.syncer.ModPayload(
            mod=types.SimpleNamespace(item_id="factorio-dimension-warp", version="0.7.2"),
            title="Dimension Warp",
            short_desc="short",
            description="desc",
            tags=[],
            deps=[],
            deps_ok=True,
            images=[],
            images_incomplete=False,
            ow_mod={"id": 42, "source_id": "factorio-dimension-warp"},
            ow_mod_id=42,
            is_new=False,
        )

        syncer._worker_api = lambda: ApiStub()
        syncer._worker_tag_manager = lambda: types.SimpleNamespace(sync_mod_tags=lambda *args, **kwargs: None)
        syncer._worker_dependency_manager = lambda: types.SimpleNamespace(sync_dependencies=lambda *args, **kwargs: None, retry_pending=lambda: None)
        syncer._worker_conflict_manager = lambda: types.SimpleNamespace(sync_conflicts=lambda *args, **kwargs: None, retry_pending=lambda: None)
        syncer._worker_resource_syncer = lambda: types.SimpleNamespace(sync_resources=lambda *args, **kwargs: None)

        syncer._process_file_update("factorio-dimension-warp", payload, Path("/tmp/factorio-dimension-warp.zip"))

        self.assertEqual(recorded["source_id"], "factorio-dimension-warp")


if __name__ == "__main__":
    unittest.main()
