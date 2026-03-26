import unittest
from unittest.mock import patch

from aiohttp.test_utils import TestClient, TestServer

from ui_service import _create_app, load_ui_settings


class UIBasePathTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_accepts_trailing_slash_under_base_path(self) -> None:
        with patch("ui_service.list_instances", return_value=[]):
            with patch.dict(
                "os.environ",
                {
                    "OW_UI_BASE_PATH": "/auto-updater",
                    "OW_UI_USERNAME": "admin",
                    "OW_UI_PASSWORD": "secret",
                },
                clear=False,
            ):
                app = _create_app(load_ui_settings())
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    response = await client.get(
                        "/auto-updater/",
                        headers={"Authorization": "Basic YWRtaW46c2VjcmV0"},
                    )
                    self.assertEqual(response.status, 200)
                    self.assertIn("MirrorInstance Control Plane", await response.text())
                finally:
                    await client.close()

    async def test_live_logs_page_includes_realtime_controls(self) -> None:
        with patch("ui_service._latest_pod_name", return_value="demo-parser-0"):
            with patch("ui_service.read_pod_log", return_value="line 1\nline 2"):
                with patch.dict(
                    "os.environ",
                    {
                        "OW_UI_BASE_PATH": "/auto-updater",
                        "OW_UI_USERNAME": "admin",
                        "OW_UI_PASSWORD": "secret",
                    },
                    clear=False,
                ):
                    app = _create_app(load_ui_settings())
                    client = TestClient(TestServer(app))
                    await client.start_server()
                    try:
                        response = await client.get(
                            "/auto-updater/instances/demo/logs/parser",
                            headers={"Authorization": "Basic YWRtaW46c2VjcmV0"},
                        )
                        self.assertEqual(response.status, 200)
                        text = await response.text()
                        self.assertIn("Refresh now", text)
                        self.assertIn("Pause", text)
                        self.assertIn("/auto-updater/api/instances/demo/logs/parser", text)
                    finally:
                        await client.close()

    async def test_live_logs_api_returns_json_under_base_path(self) -> None:
        with patch("ui_service._latest_pod_name", return_value="demo-parser-0"):
            with patch("ui_service.read_pod_log", return_value="alpha\nbeta"):
                with patch.dict(
                    "os.environ",
                    {
                        "OW_UI_BASE_PATH": "/auto-updater",
                        "OW_UI_USERNAME": "admin",
                        "OW_UI_PASSWORD": "secret",
                    },
                    clear=False,
                ):
                    app = _create_app(load_ui_settings())
                    client = TestClient(TestServer(app))
                    await client.start_server()
                    try:
                        response = await client.get(
                            "/auto-updater/api/instances/demo/logs/parser?tail=123",
                            headers={"Authorization": "Basic YWRtaW46c2VjcmV0"},
                        )
                        self.assertEqual(response.status, 200)
                        payload = await response.json()
                        self.assertEqual(payload["podName"], "demo-parser-0")
                        self.assertEqual(payload["container"], "parser")
                        self.assertEqual(payload["tailLines"], 123)
                        self.assertEqual(payload["logText"], "alpha\nbeta")
                    finally:
                        await client.close()

    async def test_live_logs_api_returns_json_error_when_pod_missing(self) -> None:
        with patch("ui_service._latest_pod_name", return_value=""):
            with patch.dict(
                "os.environ",
                {
                    "OW_UI_BASE_PATH": "/auto-updater",
                    "OW_UI_USERNAME": "admin",
                    "OW_UI_PASSWORD": "secret",
                },
                clear=False,
            ):
                app = _create_app(load_ui_settings())
                client = TestClient(TestServer(app))
                await client.start_server()
                try:
                    response = await client.get(
                        "/auto-updater/api/instances/demo/logs/parser",
                        headers={"Authorization": "Basic YWRtaW46c2VjcmV0"},
                    )
                    self.assertEqual(response.status, 404)
                    payload = await response.json()
                    self.assertIn("Pod для demo/parser пока не найден", payload["error"])
                finally:
                    await client.close()


if __name__ == "__main__":
    unittest.main()
