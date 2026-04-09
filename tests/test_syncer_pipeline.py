import importlib
import sys
import threading
import types
import unittest
from contextlib import nullcontext
from pathlib import Path


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
    utils.strip_bbcode = lambda value: value
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


class SyncerPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.syncer = _load_syncer_module()

    def _make_syncer(self):
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
        )
        syncer._clear_local_caches = lambda _reason: None
        syncer.tag_manager.preload = lambda: None
        syncer._create_lookup_api = lambda: types.SimpleNamespace(
            session=types.SimpleNamespace(close=lambda: None)
        )
        return syncer

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
        self.assertEqual(processed, ["1", "2"])

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
            description="Some [b]desc[/b]",
            tags=["a", "b"],
            dependencies=["12", "42", "13"],
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
        self.assertEqual(payload.short_desc, "Some [b]desc[/b]")
        self.assertEqual(payload.description, "Some [b]desc[/b]")
        self.assertEqual(payload.deps, ["12", "13"])
        self.assertEqual(
            payload.images,
            ["https://cdn/logo.png", "https://cdn/1.png"],
        )


if __name__ == "__main__":
    unittest.main()
