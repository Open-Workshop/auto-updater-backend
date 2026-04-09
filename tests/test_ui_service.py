import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from kube.mirror_instance import managed_secret_names

try:
    from aiohttp.test_utils import TestClient, TestServer
    from ui.ui_service import _create_app, load_ui_settings
    from ui.ui_instance import _derive_health
except ModuleNotFoundError:
    TestClient = None
    TestServer = None
    _create_app = None
    _derive_health = None
    load_ui_settings = None


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Basic YWRtaW46c2VjcmV0"}


def _sample_summary() -> dict:
    return {
        "name": "demo",
        "enabled": True,
        "health": "Healthy",
        "healthTone": "healthy",
        "phase": "Ready",
        "syncState": "Succeeded",
        "lastSyncResult": "success",
        "lastSyncLabel": "Succeeded at 2026-03-26 18:30 UTC",
        "lastSyncStartedAt": "2026-03-26T18:20:00+00:00",
        "lastSyncFinishedAt": "2026-03-26T18:30:00+00:00",
        "errorSummary": "—",
        "lastError": "",
        "source": {
            "steamAppId": 602960,
            "owGameId": 3,
            "language": "english",
        },
        "parser": {
            "podName": "demo-parser-0",
            "state": "Ready",
            "tone": "healthy",
            "ready": True,
            "image": "auto-updater-backend:prod",
            "resources": {
                "cpuMilliCores": 42,
                "memoryBytes": 155189248,
                "diskCapacityBytes": 21474836480,
                "diskUsedBytes": 7516192768,
                "diskRequestedBytes": 21474836480,
                "cpuLabel": "42m",
                "memoryLabel": "148Mi",
                "diskLabel": "20Gi cap / 7Gi used / 20Gi req",
            },
        },
        "runner": {
            "podName": "demo-steamcmd-0",
            "state": "Ready",
            "tone": "healthy",
            "ready": True,
            "image": "auto-updater-backend:prod",
            "tunImage": "ghcr.io/sagernet/sing-box:latest",
            "tunReady": True,
            "resources": {
                "cpuMilliCores": 88,
                "memoryBytes": 127926272,
                "diskCapacityBytes": 10737418240,
                "diskUsedBytes": 536870912,
                "diskRequestedBytes": 10737418240,
                "cpuLabel": "88m",
                "memoryLabel": "122Mi",
                "diskLabel": "10Gi cap / 512Mi used / 10Gi req",
            },
        },
        "resources": {
            "cpuMilliCores": 130,
            "memoryBytes": 283115520,
            "diskCapacityBytes": 32212254720,
            "diskUsedBytes": 8053063680,
            "diskRequestedBytes": 32212254720,
            "cpuLabel": "130m",
            "memoryLabel": "270Mi",
            "diskLabel": "30Gi cap / 7.5Gi used / 30Gi req",
        },
        "conditions": [{"type": "Ready", "status": "True"}],
        "urls": {
            "detail": "/auto-updater/instances/demo",
            "overview": "/auto-updater/instances/demo?tab=overview",
            "logs": "/auto-updater/instances/demo?tab=logs",
            "resources": "/auto-updater/instances/demo?tab=resources",
            "settings": "/auto-updater/instances/demo?tab=settings",
            "edit": "/auto-updater/instances/demo/edit",
            "legacyLogs": "/auto-updater/instances/demo/logs/parser",
            "legacyResources": "/auto-updater/instances/demo/resources",
            "sync": "/auto-updater/instances/demo/sync",
            "toggle": "/auto-updater/instances/demo/toggle",
            "delete": "/auto-updater/instances/demo/delete",
            "logsApi": "/auto-updater/api/instances/demo/logs",
        },
    }


def _sample_instance() -> dict:
    return {
        "apiVersion": "auto-updater.miskler.ru/v1alpha1",
        "kind": "MirrorInstance",
        "metadata": {
            "name": "demo",
            "namespace": "auto-updater",
            "uid": "uid-existing",
        },
        "spec": {
            "enabled": True,
            "source": {
                "steamAppId": 602960,
                "owGameId": 3,
                "language": "english",
            },
            "sync": {
                "pollIntervalSeconds": 600,
                "timeoutSeconds": 60,
                "httpRetries": 3,
                "httpRetryBackoff": 5.0,
                "steamHttpRetries": 2,
                "steamHttpBackoff": 2.0,
                "steamRequestDelay": 1.0,
                "logLevel": "INFO",
                "runOnce": False,
                "syncTags": True,
                "pruneTags": True,
                "syncDependencies": True,
                "pruneDependencies": True,
                "syncResources": True,
                "pruneResources": True,
                "uploadResourceFiles": True,
                "scrapePreviewImages": True,
                "scrapeRequiredItems": True,
                "maxScreenshots": 20,
                "pageSize": 77,
                "customMirrorSetting": {"keep": True},
            },
            "credentials": {"secretRef": "demo-ow-credentials"},
            "parser": {"proxyPoolSecretRef": "demo-parser-proxies"},
            "steamcmd": {
                "proxy": {
                    "type": "socks5",
                    "secretRef": "demo-steamcmd-proxy",
                }
            },
            "storage": {
                "parser": {"size": "20Gi", "storageClassName": "local-path"},
                "runner": {"size": "10Gi", "storageClassName": "local-path"},
            },
        },
        "status": {
            "phase": "Ready",
            "parserPod": "demo-parser-0",
            "runnerPod": "demo-steamcmd-0",
            "lastSyncResult": "success",
        },
    }


def _secret_value(_: str, __: str, key: str) -> str:
    values = {
        "login": "demo-login",
        "password": "stored-password",
        "proxyPool": "socks5://pool-user:pool-pass@127.0.0.1:3001",
        "proxyUrl": "socks5://runner-user:runner-pass@127.0.0.1:3001",
    }
    return values[key]


@unittest.skipUnless(_create_app is not None, "aiohttp dependency is not installed")
class UIDashboardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.env = patch.dict(
            "os.environ",
            {
                "OW_UI_BASE_PATH": "/auto-updater",
                "OW_UI_USERNAME": "admin",
                "OW_UI_PASSWORD": "secret",
            },
            clear=False,
        )
        self.env.start()

    async def asyncTearDown(self) -> None:
        self.env.stop()

    async def test_dashboard_accepts_trailing_slash_under_base_path(self) -> None:
        with patch("ui.ui_handlers._load_instance_summaries", return_value=[]):
            app = _create_app(load_ui_settings())
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                response = await client.get("/auto-updater/", headers=_auth_headers())
                self.assertEqual(response.status, 200)
                text = await response.text()
                self.assertIn("Operations Control Center", text)
                self.assertIn("Search instances", text)
                self.assertIn("Running sync", text)
                self.assertIn("CPU live", text)
                self.assertIn("Disk cap / used / req", text)
                self.assertIn("Resources", text)
                self.assertIn("/auto-updater/assets/app.css", text)
                self.assertIn("/auto-updater/assets/dashboard.js", text)
            finally:
                await client.close()

    async def test_static_assets_are_served_under_base_path(self) -> None:
        app = _create_app(load_ui_settings())
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/auto-updater/assets/app.css", headers=_auth_headers())
            self.assertEqual(response.status, 200)
            text = await response.text()
            self.assertIn("--accent", text)
        finally:
            await client.close()

    async def test_instances_api_returns_json_under_base_path(self) -> None:
        with patch("ui.ui_handlers._load_instance_summaries", return_value=[_sample_summary()]):
            app = _create_app(load_ui_settings())
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                response = await client.get("/auto-updater/api/instances", headers=_auth_headers())
                self.assertEqual(response.status, 200)
                payload = await response.json()
                self.assertEqual(payload["items"][0]["name"], "demo")
                self.assertEqual(payload["items"][0]["health"], "Healthy")
                self.assertEqual(payload["counts"]["Healthy"], 1)
                self.assertEqual(payload["resources"]["cpuLabel"], "130m")
                self.assertEqual(payload["resources"]["diskLabel"], "n/a cap / n/a used / 32.2GB req")
            finally:
                await client.close()

    async def test_dashboard_offloads_summary_loading_to_thread(self) -> None:
        threaded_calls: list[str] = []

        async def run_in_band(func, *args, **kwargs):
            threaded_calls.append(getattr(func, "__name__", str(func)))
            return func(*args, **kwargs)

        with patch("ui.ui_handlers.asyncio.to_thread", side_effect=run_in_band):
            with patch("ui.ui_handlers._load_instance_summaries", return_value=[]):
                app = _create_app(load_ui_settings())
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    response = await client.get("/auto-updater/", headers=_auth_headers())
                    self.assertEqual(response.status, 200)
                    self.assertEqual(len(threaded_calls), 1)
                    self.assertIn("_load_instance_summaries", threaded_calls[0])
                finally:
                    await client.close()

    async def test_detail_page_logs_tab_contains_live_console(self) -> None:
        with patch("ui.ui_handlers._load_instance_summary", return_value=_sample_summary()):
            app = _create_app(load_ui_settings())
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                response = await client.get(
                    "/auto-updater/instances/demo?tab=logs",
                    headers=_auth_headers(),
                )
                self.assertEqual(response.status, 200)
                text = await response.text()
                self.assertIn("Copy", text)
                self.assertIn("Pause", text)
                self.assertIn("/auto-updater/api/instances/demo/logs", text)
                self.assertIn('id="logs-config"', text)
                self.assertIn('id="log-tag-filters"', text)
                self.assertIn("/auto-updater/assets/logs.js", text)
            finally:
                await client.close()

    async def test_logs_asset_contains_status_highlighting(self) -> None:
        app = _create_app(load_ui_settings())
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/auto-updater/assets/logs.js", headers=_auth_headers())
            self.assertEqual(response.status, 200)
            text = await response.text()
            self.assertIn("STATUS_TONES", text)
            self.assertIn("log-status", text)
            self.assertIn("INFO", text)
        finally:
            await client.close()

    async def test_pod_logs_api_offloads_snapshot_to_thread(self) -> None:
        payload = {
            "instance": "demo",
            "target": "parser",
            "targetLabel": "Parser",
            "component": "parser",
            "container": "parser",
            "podName": "demo-parser-0",
            "tailLines": 400,
            "logText": "hello",
            "selectedTag": "steam",
            "availableTags": ["steam", "ow"],
            "tagOptions": [
                {"value": "all", "label": "All"},
                {"value": "steam", "label": "STEAM"},
                {"value": "ow", "label": "OW"},
            ],
            "rxBytes": 1,
            "txBytes": 2,
        }
        threaded_calls: list[str] = []

        async def run_in_band(func, *args, **kwargs):
            threaded_calls.append(getattr(func, "__name__", str(func)))
            return func(*args, **kwargs)

        with patch("ui.ui_handlers.asyncio.to_thread", side_effect=run_in_band):
            with patch("ui.ui_handlers._pod_log_snapshot", return_value=payload):
                app = _create_app(load_ui_settings())
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    response = await client.get(
                        "/auto-updater/api/instances/demo/logs/parser",
                        headers=_auth_headers(),
                    )
                    self.assertEqual(response.status, 200)
                    body = await response.json()
                    self.assertEqual(body["logText"], "hello")
                    self.assertEqual(body["selectedTag"], "steam")
                    self.assertEqual(len(threaded_calls), 1)
                    self.assertIn("_pod_log_snapshot", threaded_calls[0])
                finally:
                    await client.close()

    async def test_instances_api_counts_running_sync_separately_from_health(self) -> None:
        summary = _sample_summary()
        summary["syncState"] = "Running"
        summary["lastSyncResult"] = "running"
        summary["lastSyncLabel"] = "Running since 2026-03-26 18:20 UTC"
        with patch("ui.ui_handlers._load_instance_summaries", return_value=[summary]):
            app = _create_app(load_ui_settings())
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                response = await client.get("/auto-updater/api/instances", headers=_auth_headers())
                self.assertEqual(response.status, 200)
                payload = await response.json()
                self.assertEqual(payload["items"][0]["health"], "Healthy")
                self.assertEqual(payload["items"][0]["syncState"], "Running")
                self.assertEqual(payload["counts"]["Healthy"], 1)
                self.assertEqual(payload["counts"]["Running"], 1)
            finally:
                await client.close()

    async def test_legacy_logs_route_redirects_to_detail_tab(self) -> None:
        app = _create_app(load_ui_settings())
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get(
                "/auto-updater/instances/demo/logs/parser",
                headers=_auth_headers(),
                allow_redirects=False,
            )
            self.assertEqual(response.status, 302)
            self.assertIn("/auto-updater/instances/demo?tab=logs&target=parser", response.headers["Location"])
        finally:
            await client.close()

    async def test_settings_tab_renders_expert_mode_collapsed(self) -> None:
        with patch("ui.ui_handlers._load_instance_summary", return_value=_sample_summary()):
            with patch("ui.ui_handlers.get_instance", return_value=_sample_instance()):
                with patch("ui.ui_forms.read_secret_value", side_effect=_secret_value):
                    app = _create_app(load_ui_settings())
                    client = TestClient(TestServer(app))
                    await client.start_server()
                    try:
                        response = await client.get(
                            "/auto-updater/instances/demo?tab=settings",
                            headers=_auth_headers(),
                        )
                        self.assertEqual(response.status, 200)
                        text = await response.text()
                        self.assertIn("Expert mode", text)
                        self.assertIn("Raw sync JSON merge", text)
                        self.assertIn('<details class="panel-section expert-panel">', text)
                    finally:
                        await client.close()

    async def test_resources_tab_serializes_datetime_payload(self) -> None:
        resources = [
            {
                "kind": "MirrorInstance",
                "name": "demo",
                "payload": {
                    "status": {
                        "lastSyncStartedAt": datetime(2026, 3, 26, 16, 29, tzinfo=UTC),
                    }
                },
                "error": "",
            }
        ]
        with patch("ui.ui_handlers._load_instance_summary", return_value=_sample_summary()):
            with patch("ui.ui_handlers._load_resource_entries", return_value=resources):
                app = _create_app(load_ui_settings())
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    response = await client.get(
                        "/auto-updater/instances/demo?tab=resources",
                        headers=_auth_headers(),
                    )
                    self.assertEqual(response.status, 200)
                    text = await response.text()
                    self.assertIn("2026-03-26T16:29:00+00:00", text)
                finally:
                    await client.close()

    async def test_save_instance_preserves_unedited_sync_fields(self) -> None:
        captured: dict[str, dict] = {}
        saved_instance = _sample_instance()
        saved_instance["metadata"] = dict(saved_instance["metadata"])
        saved_instance["metadata"]["uid"] = "uid-saved"
        upserted_secrets: list[dict] = []

        def remember_replace(_: str, name: str, body: dict) -> dict:
            captured["name"] = name
            captured["body"] = body
            return body

        def remember_secret(_: str, body: dict) -> dict:
            upserted_secrets.append(body)
            return body

        with patch("ui.ui_handlers.get_instance", side_effect=[_sample_instance(), saved_instance]):
            with patch("ui.ui_handlers.read_secret_value", side_effect=_secret_value):
                with patch("ui.ui_forms.read_secret_value", side_effect=_secret_value):
                    with patch("ui.ui_handlers.upsert_secret", side_effect=remember_secret):
                        with patch("ui.ui_handlers.delete_secret"):
                            with patch("ui.ui_handlers.replace_or_create_instance", side_effect=remember_replace):
                                app = _create_app(load_ui_settings())
                                client = TestClient(TestServer(app))
                                await client.start_server()
                                try:
                                    response = await client.post(
                                        "/auto-updater/instances/save",
                                        headers=_auth_headers(),
                                        data={
                                            "original_name": "demo",
                                            "name": "demo",
                                            "return_path": "/instances/demo?tab=settings",
                                            "enabled": "on",
                                            "steam_app_id": "602960",
                                            "ow_game_id": "3",
                                            "language": "english",
                                            "parser_storage_size": "20Gi",
                                            "runner_storage_size": "10Gi",
                                            "ow_login": "demo-login",
                                            "ow_password": "",
                                            "runner_proxy_type": "socks5",
                                            "runner_proxy_url": "socks5://runner-user:runner-pass@127.0.0.1:3001",
                                            "parser_proxy_pool": "socks5://pool-user:pool-pass@127.0.0.1:3001",
                                            "api_base": "https://api.openworkshop.miskler.ru",
                                            "page_size": "77",
                                            "poll_interval_seconds": "600",
                                            "timeout_seconds": "60",
                                            "http_retries": "3",
                                            "http_retry_backoff": "5.0",
                                            "steam_http_retries": "2",
                                            "steam_http_backoff": "2.0",
                                            "steam_request_delay": "1.0",
                                            "steam_max_pages": "3000",
                                            "steam_start_page": "1",
                                            "steam_max_items": "0",
                                            "steam_delay": "1.0",
                                            "log_level": "INFO",
                                            "max_screenshots": "20",
                                            "public_mode": "0",
                                            "force_required_item_id": "",
                                            "sync_json_patch": "",
                                            "sync_tags": "on",
                                            "prune_tags": "on",
                                            "sync_dependencies": "on",
                                            "prune_dependencies": "on",
                                            "sync_resources": "on",
                                            "prune_resources": "on",
                                            "upload_resource_files": "on",
                                            "scrape_preview_images": "on",
                                            "scrape_required_items": "on",
                                        },
                                        allow_redirects=False,
                                    )
                                    self.assertEqual(response.status, 302)
                                    self.assertEqual(captured["name"], "demo")
                                    self.assertEqual(captured["body"]["spec"]["sync"]["pageSize"], 77)
                                    self.assertEqual(
                                        captured["body"]["spec"]["sync"]["customMirrorSetting"],
                                        {"keep": True},
                                    )
                                    self.assertEqual(captured["body"]["spec"]["sync"]["pollIntervalSeconds"], 600)
                                    self.assertEqual(captured["body"]["spec"]["sync"]["steamMaxPages"], 3000)
                                    self.assertEqual(len(upserted_secrets), 3)
                                    for secret in upserted_secrets:
                                        self.assertEqual(
                                            secret["metadata"]["ownerReferences"][0]["uid"],
                                            "uid-saved",
                                        )
                                finally:
                                    await client.close()

    async def test_rename_instance_reowns_new_secrets_before_legacy_cleanup(self) -> None:
        saved_instance = _sample_instance()
        saved_instance["metadata"] = {
            "name": "demo-renamed",
            "namespace": "auto-updater",
            "uid": "uid-renamed",
        }
        events: list[tuple[str, str]] = []

        def remember_secret(_: str, body: dict) -> dict:
            events.append(("upsert_secret", body["metadata"]["name"]))
            return body

        def remember_replace(_: str, name: str, body: dict) -> dict:
            events.append(("replace_instance", name))
            return body

        def remember_delete_instance(_: str, name: str) -> None:
            events.append(("delete_instance", name))

        def remember_delete_secret(_: str, name: str) -> None:
            events.append(("delete_secret", name))

        with patch("ui.ui_handlers.get_instance", side_effect=[_sample_instance(), saved_instance]):
            with patch("ui.ui_handlers.read_secret_value", side_effect=_secret_value):
                with patch("ui.ui_forms.read_secret_value", side_effect=_secret_value):
                    with patch("ui.ui_handlers.upsert_secret", side_effect=remember_secret):
                        with patch("ui.ui_handlers.delete_secret", side_effect=remember_delete_secret):
                            with patch("ui.ui_handlers.delete_instance", side_effect=remember_delete_instance):
                                with patch("ui.ui_handlers.replace_or_create_instance", side_effect=remember_replace):
                                    app = _create_app(load_ui_settings())
                                    client = TestClient(TestServer(app))
                                    await client.start_server()
                                    try:
                                        response = await client.post(
                                            "/auto-updater/instances/save",
                                            headers=_auth_headers(),
                                            data={
                                                "original_name": "demo",
                                                "name": "demo-renamed",
                                                "return_path": "/instances/demo?tab=settings",
                                                "enabled": "on",
                                                "steam_app_id": "602960",
                                                "ow_game_id": "3",
                                                "language": "english",
                                                "parser_storage_size": "20Gi",
                                                "runner_storage_size": "10Gi",
                                                "ow_login": "demo-login",
                                                "ow_password": "",
                                                "runner_proxy_type": "socks5",
                                                "runner_proxy_url": "socks5://runner-user:runner-pass@127.0.0.1:3001",
                                                "parser_proxy_pool": "socks5://pool-user:pool-pass@127.0.0.1:3001",
                                                "api_base": "https://api.openworkshop.miskler.ru",
                                                "page_size": "77",
                                                "poll_interval_seconds": "600",
                                                "timeout_seconds": "60",
                                                "http_retries": "3",
                                                "http_retry_backoff": "5.0",
                                                "steam_http_retries": "2",
                                                "steam_http_backoff": "2.0",
                                                "steam_request_delay": "1.0",
                                                "steam_max_pages": "1000",
                                                "steam_start_page": "1",
                                                "steam_max_items": "0",
                                                "steam_delay": "1.0",
                                                "log_level": "INFO",
                                                "max_screenshots": "20",
                                                "public_mode": "0",
                                                "force_required_item_id": "",
                                                "sync_json_patch": "",
                                                "sync_tags": "on",
                                                "prune_tags": "on",
                                                "sync_dependencies": "on",
                                                "prune_dependencies": "on",
                                                "sync_resources": "on",
                                                "prune_resources": "on",
                                                "upload_resource_files": "on",
                                                "scrape_preview_images": "on",
                                                "scrape_required_items": "on",
                                            },
                                            allow_redirects=False,
                                        )
                                        self.assertEqual(response.status, 302)
                                        delete_index = events.index(("delete_instance", "demo"))
                                        for expected_name in managed_secret_names("demo-renamed"):
                                            self.assertIn(("upsert_secret", expected_name), events)
                                            self.assertLess(events.index(("upsert_secret", expected_name)), delete_index)
                                        for expected_name in managed_secret_names("demo"):
                                            self.assertIn(("delete_secret", expected_name), events)
                                            self.assertGreater(events.index(("delete_secret", expected_name)), delete_index)
                                    finally:
                                        await client.close()

    async def test_save_validation_opens_expert_panel_and_shows_summary(self) -> None:
        with patch("ui.ui_handlers.get_instance", return_value=_sample_instance()):
            with patch("ui.ui_handlers.read_secret_value", side_effect=_secret_value):
                with patch("ui.ui_forms.read_secret_value", side_effect=_secret_value):
                    with patch("ui.ui_handlers._load_instance_summary", return_value=_sample_summary()):
                        app = _create_app(load_ui_settings())
                        client = TestClient(TestServer(app))
                        await client.start_server()
                        try:
                            response = await client.post(
                                "/auto-updater/instances/save",
                                headers=_auth_headers(),
                                data={
                                    "original_name": "demo",
                                    "name": "demo",
                                    "return_path": "/instances/demo?tab=settings",
                                    "enabled": "on",
                                    "steam_app_id": "602960",
                                    "ow_game_id": "3",
                                    "language": "english",
                                    "parser_storage_size": "20Gi",
                                    "runner_storage_size": "10Gi",
                                    "ow_login": "demo-login",
                                    "ow_password": "",
                                    "runner_proxy_type": "socks5",
                                    "runner_proxy_url": "socks5://runner-user:runner-pass@127.0.0.1:3001",
                                    "parser_proxy_pool": "socks5://pool-user:pool-pass@127.0.0.1:3001",
                                    "api_base": "https://api.openworkshop.miskler.ru",
                                    "page_size": "77",
                                    "poll_interval_seconds": "600",
                                    "timeout_seconds": "60",
                                    "http_retries": "3",
                                    "http_retry_backoff": "5.0",
                                    "steam_http_retries": "2",
                                    "steam_http_backoff": "2.0",
                                    "steam_request_delay": "1.0",
                                    "steam_max_pages": "3000",
                                    "steam_start_page": "1",
                                    "steam_max_items": "0",
                                    "steam_delay": "1.0",
                                    "log_level": "INFO",
                                    "max_screenshots": "20",
                                    "public_mode": "0",
                                    "force_required_item_id": "",
                                    "sync_json_patch": "{broken",
                                    "sync_tags": "on",
                                    "prune_tags": "on",
                                    "sync_dependencies": "on",
                                    "prune_dependencies": "on",
                                    "sync_resources": "on",
                                    "prune_resources": "on",
                                    "upload_resource_files": "on",
                                    "scrape_preview_images": "on",
                                    "scrape_required_items": "on",
                                },
                            )
                            self.assertEqual(response.status, 400)
                            text = await response.text()
                            self.assertIn("Save failed.", text)
                            self.assertIn("sync_json_patch", text)
                            self.assertIn("<details class=\"panel-section expert-panel\" open>", text)
                        finally:
                            await client.close()

    async def test_delete_instance_keeps_legacy_secret_cleanup_as_fallback(self) -> None:
        events: list[tuple[str, str]] = []

        def remember_delete_instance(_: str, name: str) -> None:
            events.append(("delete_instance", name))

        def remember_delete_secret(_: str, name: str) -> None:
            events.append(("delete_secret", name))

        with patch("ui.ui_handlers.delete_instance", side_effect=remember_delete_instance):
            with patch("ui.ui_handlers.delete_secret", side_effect=remember_delete_secret):
                app = _create_app(load_ui_settings())
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    response = await client.post(
                        "/auto-updater/instances/demo/delete",
                        headers=_auth_headers(),
                        data={},
                        allow_redirects=False,
                    )
                    self.assertEqual(response.status, 302)
                    self.assertEqual(events[0], ("delete_instance", "demo"))
                    for expected_name in managed_secret_names("demo"):
                        self.assertIn(("delete_secret", expected_name), events)
                        self.assertGreater(events.index(("delete_secret", expected_name)), 0)
                finally:
                    await client.close()


@unittest.skipUnless(_derive_health is not None, "aiohttp dependency is not installed")
class UIHealthTests(unittest.TestCase):
    def test_derive_health_variants(self) -> None:
        self.assertEqual(
            _derive_health(
                enabled=False,
                phase="Ready",
                last_error="",
                parser_ready=True,
                runner_ready=True,
            ),
            "Disabled",
        )
        self.assertEqual(
            _derive_health(
                enabled=True,
                phase="Ready",
                last_error="",
                parser_ready=True,
                runner_ready=True,
            ),
            "Healthy",
        )
        self.assertEqual(
            _derive_health(
                enabled=True,
                phase="Ready",
                last_error="Connection refused",
                parser_ready=True,
                runner_ready=True,
            ),
            "Error",
        )
        self.assertEqual(
            _derive_health(
                enabled=True,
                phase="Ready",
                last_error="",
                parser_ready=True,
                runner_ready=True,
            ),
            "Healthy",
        )


if __name__ == "__main__":
    unittest.main()
