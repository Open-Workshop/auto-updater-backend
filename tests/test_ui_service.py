import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from aiohttp.test_utils import TestClient, TestServer

from ui.ui_service import _create_app, _derive_health, load_ui_settings


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
        },
        "runner": {
            "podName": "demo-steamcmd-0",
            "state": "Ready",
            "tone": "healthy",
            "ready": True,
            "image": "auto-updater-backend:prod",
            "tunImage": "ghcr.io/sagernet/sing-box:latest",
            "tunReady": True,
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
        with patch("ui.ui_service._load_instance_summaries", return_value=[]):
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
        with patch("ui.ui_service._load_instance_summaries", return_value=[_sample_summary()]):
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
            finally:
                await client.close()

    async def test_detail_page_logs_tab_contains_live_console(self) -> None:
        with patch("ui.ui_service._load_instance_summary", return_value=_sample_summary()):
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

    async def test_instances_api_counts_running_sync_separately_from_health(self) -> None:
        summary = _sample_summary()
        summary["syncState"] = "Running"
        summary["lastSyncResult"] = "running"
        summary["lastSyncLabel"] = "Running since 2026-03-26 18:20 UTC"
        with patch("ui.ui_service._load_instance_summaries", return_value=[summary]):
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
        with patch("ui.ui_service._load_instance_summary", return_value=_sample_summary()):
            with patch("ui.ui_service.get_instance", return_value=_sample_instance()):
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
        with patch("ui.ui_service._load_instance_summary", return_value=_sample_summary()):
            with patch("ui.ui_service._load_resource_entries", return_value=resources):
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

        def remember_replace(_: str, name: str, body: dict) -> dict:
            captured["name"] = name
            captured["body"] = body
            return body

        with patch("ui.ui_service.get_instance", return_value=_sample_instance()):
            with patch("ui.ui_service.read_secret_value", side_effect=_secret_value):
                with patch("ui.ui_service.upsert_secret"):
                    with patch("ui.ui_service.delete_secret"):
                        with patch("ui.ui_service.replace_or_create_instance", side_effect=remember_replace):
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
                                        "poll_interval_seconds": "600",
                                        "timeout_seconds": "60",
                                        "http_retries": "3",
                                        "http_retry_backoff": "5.0",
                                        "steam_http_retries": "2",
                                        "steam_http_backoff": "2.0",
                                        "steam_request_delay": "1.0",
                                        "log_level": "INFO",
                                        "max_screenshots": "20",
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
                                self.assertEqual(captured["body"]["spec"]["sync"]["pollIntervalSeconds"], 600)
                            finally:
                                await client.close()


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
