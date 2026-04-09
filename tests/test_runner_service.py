import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


try:
    import services.runner_service as runner_service
except ModuleNotFoundError:
    runner_service = None


@unittest.skipUnless(runner_service is not None, "aiohttp dependency is not installed")
class RunnerServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_archive_cleans_workshop_content_but_keeps_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            steam_root = Path(tmp) / "steam"
            archive_dir = steam_root / "archives"
            archive_dir.mkdir(parents=True)
            workshop_path = (
                steam_root
                / "steamapps"
                / "workshop"
                / "content"
                / "108600"
                / "123"
            )
            workshop_path.mkdir(parents=True)
            (workshop_path / "mod.info").write_text("payload", encoding="utf-8")

            archive_path = archive_dir / "108600-123.zip"

            def fake_download_mod_archive(*_args, **_kwargs):
                archive_path.write_bytes(b"zip-data")
                return types.SimpleNamespace(
                    ok=True,
                    archive_path=archive_path,
                    reason=None,
                    retryable=False,
                    diagnostics=None,
                )

            class _FakeLoop:
                async def run_in_executor(self, _executor, func):
                    return func()

            class _FakeRequest:
                app = {"loop": _FakeLoop()}

                async def json(self):
                    return {"appId": 108600, "workshopId": 123}

            with patch.object(runner_service, "_steam_root", return_value=steam_root):
                with patch.object(
                    runner_service,
                    "download_mod_archive",
                    side_effect=fake_download_mod_archive,
                ):
                    response = await runner_service._archive(_FakeRequest())

            self.assertIsInstance(response, runner_service.web.FileResponse)
            self.assertTrue(archive_path.exists())
            self.assertFalse(workshop_path.exists())


if __name__ == "__main__":
    unittest.main()
