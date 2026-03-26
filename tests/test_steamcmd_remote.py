import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from steamcmd import download_mod_archive


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


if __name__ == "__main__":
    unittest.main()
