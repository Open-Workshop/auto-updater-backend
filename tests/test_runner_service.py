import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from core.parser_registry import (
    ParserContract,
    ParserConfigFieldSpec,
    ParserSecretSpec,
    ParserWorkloadSpec,
    WorkloadLogTargetSpec,
)


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

    def test_run_runner_accepts_registered_non_default_parser_type(self) -> None:
        fake_type = "custom-parser"
        contract = ParserContract(
            parser_type=fake_type,
            label="Custom Parser",
            description="Test-only parser contract.",
            config_fields=(
                ParserConfigFieldSpec(
                    "sourceUrl",
                    "OW_SOURCE_URL",
                    "source_url",
                    "source_url",
                    "Source URL",
                    "str",
                    "https://api.example.test",
                    required=True,
                    ui_section="basic",
                ),
            ),
            secret_specs=(
                ParserSecretSpec(
                    key="parserProxyPoolSecretRef",
                    label="Parser proxy pool",
                    form_field="parser_proxy_pool",
                    secret_component="parser-proxies",
                    secret_data_key="proxyPool",
                    validator="proxy-pool",
                ),
                ParserSecretSpec(
                    key="runnerProxySecretRef",
                    label="Runner proxy URL",
                    form_field="runner_proxy_url",
                    secret_component="runner-proxy",
                    secret_data_key="proxyUrl",
                    validator="proxy-url",
                ),
            ),
            workloads=(
                ParserWorkloadSpec(
                    workload_id="ingestor",
                    component="parser",
                    name_suffix="ingestor",
                    display_label="Ingestor",
                    mode="parser",
                    main_container_name="parser",
                    storage_form_field="parser_storage_size",
                    storage_label="Parser PVC size",
                    default_storage_size="20Gi",
                    log_targets=(WorkloadLogTargetSpec("ingestor", "Parser", "parser"),),
                ),
                ParserWorkloadSpec(
                    workload_id="fetcher",
                    component="runner",
                    name_suffix="fetcher",
                    display_label="Fetcher",
                    mode="runner",
                    main_container_name="runner",
                    storage_form_field="runner_storage_size",
                    storage_label="Runner PVC size",
                    default_storage_size="10Gi",
                    config_fields=(
                        ParserConfigFieldSpec(
                            "proxyType",
                            "",
                            "runner_proxy_type",
                            "runner_proxy_type",
                            "Runner proxy type",
                            "str",
                            "http",
                            required=False,
                            ui_section="workload",
                            options=(("socks5", "SOCKS5"), ("http", "HTTP")),
                        ),
                    ),
                    log_targets=(WorkloadLogTargetSpec("fetcher", "Runner", "runner"),),
                ),
            ),
        )

        with (
            patch.dict("core.parser_registry._PARSER_REGISTRY", {fake_type: contract}, clear=False),
            patch.dict("os.environ", {"OW_PARSER_TYPE": fake_type, "OW_WORKLOAD_ID": "fetcher"}, clear=False),
            patch.object(runner_service, "_cleanup_old_archives"),
            patch.object(runner_service.web, "run_app"),
        ):
            result = runner_service.run_runner()

        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
