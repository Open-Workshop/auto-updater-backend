import json
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from steam.steamcmd import download_mod_archive, download_steam_mod


class _SuccessHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.end_headers()
        self.wfile.write(b"PK\x03\x04test-zip")

    def log_message(self, _format: str, *args) -> None:
        return


class _FailureHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        self.send_response(502)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "reason": "upstream failed",
                    "retryable": True,
                    "diagnostics": "failure details",
                }
            ).encode("utf-8")
        )

    def log_message(self, _format: str, *args) -> None:
        return


class RemoteSteamcmdTests(unittest.TestCase):
    def _serve(self, handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, str]:
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, f"http://{host}:{port}"

    def test_remote_archive_success(self) -> None:
        server, base_url = self._serve(_SuccessHandler)
        try:
            with TemporaryDirectory() as tmp:
                result = download_mod_archive(
                    Path("/missing"),
                    Path(tmp),
                    294100,
                    12345,
                    Path(tmp) / "out.zip",
                    base_url,
                )
                self.assertTrue(result.ok)
                self.assertTrue(result.archive_path and result.archive_path.exists())
        finally:
            server.shutdown()
            server.server_close()

    def test_remote_archive_error_payload(self) -> None:
        server, base_url = self._serve(_FailureHandler)
        try:
            with TemporaryDirectory() as tmp:
                result = download_mod_archive(
                    Path("/missing"),
                    Path(tmp),
                    294100,
                    12345,
                    Path(tmp) / "out.zip",
                    base_url,
                )
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "upstream failed")
                self.assertTrue(result.retryable)
                self.assertEqual(result.diagnostics, "failure details")
        finally:
            server.shutdown()
            server.server_close()

    def test_retryable_local_failure_clears_steam_cache(self) -> None:
        with TemporaryDirectory() as tmp:
            steam_root = Path(tmp) / "steam"
            steamcmd_path = Path(tmp) / "steamcmd.sh"
            steamcmd_path.write_text("#!/bin/sh\n", encoding="utf-8")

            workshop_root = steam_root / "steamapps" / "workshop"
            item_dir = workshop_root / "content" / "294100" / "3701694787"
            keep_dir = workshop_root / "content" / "294100" / "keep-me"
            downloads_dir = workshop_root / "downloads" / "294100"
            temp_dir = workshop_root / "temp" / "294100"
            appworkshop = workshop_root / "appworkshop_294100.acf"

            item_dir.mkdir(parents=True)
            keep_dir.mkdir(parents=True)
            downloads_dir.mkdir(parents=True)
            temp_dir.mkdir(parents=True)
            (item_dir / "file.txt").write_text("broken", encoding="utf-8")
            (keep_dir / "file.txt").write_text("keep", encoding="utf-8")
            (downloads_dir / "partial.bin").write_bytes(b"partial")
            (temp_dir / "partial.tmp").write_bytes(b"temp")
            appworkshop.write_text("state", encoding="utf-8")

            failed = subprocess.CompletedProcess(
                args=["steamcmd"],
                returncode=1,
                stdout=(
                    "Downloading item 3701694787 ..."
                    "ERROR! Timeout downloading item 3701694787"
                ),
            )

            with (
                patch("steam.steamcmd.subprocess.run", return_value=failed),
                patch("steam.steamcmd._collect_steam_diagnostics", return_value=None),
            ):
                result = download_steam_mod(
                    steamcmd_path,
                    steam_root,
                    294100,
                    3701694787,
                )

            self.assertFalse(result.ok)
            self.assertTrue(result.retryable)
            self.assertFalse(item_dir.exists())
            self.assertTrue(keep_dir.exists())
            self.assertFalse(downloads_dir.exists())
            self.assertFalse(temp_dir.exists())
            self.assertFalse(appworkshop.exists())


if __name__ == "__main__":
    unittest.main()
