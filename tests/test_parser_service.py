import unittest
from unittest.mock import patch

from core.config import Config
from core.parser_registry import (
    ParserContract,
    ParserConfigFieldSpec,
    ParserSecretSpec,
    ParserWorkloadSpec,
    WorkloadLogTargetSpec,
)

try:
    from services.parser_service import ParserRuntime, run_parser
except ModuleNotFoundError:
    ParserRuntime = None
    run_parser = None


def _config(**overrides) -> Config:
    values = {
        "api_base": "https://api.openworkshop.example",
        "login_name": "demo-login",
        "password": "demo-password",
        "steam_app_id": 4000,
        "game_id": 7,
        "mirror_root": "/tmp/mirror",
        "steam_root": "/tmp/steam",
        "page_size": 50,
        "poll_interval": 10,
        "timeout": 60,
        "http_retries": 3,
        "http_retry_backoff": 5.0,
        "run_once": False,
        "log_level": "INFO",
        "log_steam_requests": False,
        "steam_http_retries": 2,
        "steam_http_backoff": 2.0,
        "steam_request_delay": 1.0,
        "steam_proxy_pool": [],
        "steam_proxy_scope": "none",
        "steam_max_pages": 1000,
        "steam_start_page": 1,
        "steam_max_items": 0,
        "steam_delay": 1.0,
        "max_screenshots": 20,
        "depotdownloader_path": "/opt/depotdownloader/DepotDownloader",
        "upload_resource_files": True,
        "scrape_preview_images": True,
        "scrape_required_items": True,
        "force_required_item_id": None,
        "public_mode": 0,
        "without_author": False,
        "sync_tags": True,
        "prune_tags": True,
        "sync_dependencies": True,
        "prune_dependencies": True,
        "sync_resources": True,
        "prune_resources": True,
        "language": "english",
        "steamcmd_runner_url": "http://demo-steamcmd.auto-updater.svc.cluster.local:8080",
        "admin_host": "0.0.0.0",
        "admin_port": 8080,
        "instance_name": "demo",
        "instance_namespace": "auto-updater",
    }
    values.update(overrides)
    return Config(**values)


def _instance(steam_max_pages: int) -> dict:
    return {
        "metadata": {
            "name": "demo",
            "namespace": "auto-updater",
        },
        "spec": {
            "enabled": True,
            "source": {
                "steamAppId": 4000,
                "owGameId": 7,
                "language": "english",
            },
            "sync": {
                "apiBase": "https://api.openworkshop.example",
                "pageSize": 50,
                "pollIntervalSeconds": 10,
                "timeoutSeconds": 60,
                "httpRetries": 3,
                "httpRetryBackoff": 5.0,
                "runOnce": False,
                "logLevel": "INFO",
                "logSteamRequests": False,
                "steamHttpRetries": 2,
                "steamHttpBackoff": 2.0,
                "steamRequestDelay": 1.0,
                "steamMaxPages": steam_max_pages,
                "steamStartPage": 1,
                "steamMaxItems": 0,
                "steamDelay": 1.0,
                "maxScreenshots": 20,
                "uploadResourceFiles": True,
                "scrapePreviewImages": True,
                "scrapeRequiredItems": True,
                "forceRequiredItemId": "",
                "publicMode": 0,
                "withoutAuthor": False,
                "syncTags": True,
                "pruneTags": True,
                "syncDependencies": True,
                "pruneDependencies": True,
                "syncResources": True,
                "pruneResources": True,
            },
            "credentials": {
                "secretRef": "demo-ow-credentials",
            },
            "parser": {
                "proxyPoolSecretRef": "",
            },
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
    }


def _secret_value(_: str, __: str, key: str) -> str:
    return {
        "login": "demo-login",
        "password": "demo-password",
    }[key]


async def _immediate_to_thread(func, /, *args, **kwargs):
    return func(*args, **kwargs)


FAKE_PARSER_TYPE = "custom-parser"


def _fake_contract() -> ParserContract:
    return ParserContract(
        parser_type=FAKE_PARSER_TYPE,
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


class _FakeParserAdapter:
    def __init__(self) -> None:
        self.bootstrap_calls = 0
        self.sync_calls = 0

    def bootstrap(self, runtime: ParserRuntime) -> int:
        self.bootstrap_calls += 1
        runtime.api = object()
        runtime.game_id = 1
        runtime.steam_app_id = 2
        return 0

    async def run_sync_once(self, runtime: ParserRuntime) -> None:
        self.sync_calls += 1


@unittest.skipUnless(ParserRuntime is not None, "aiohttp dependency is not installed")
class ParserRuntimeConfigReloadTests(unittest.IsolatedAsyncioTestCase):
    def test_refresh_config_from_cluster_updates_hot_sync_settings(self) -> None:
        runtime = ParserRuntime(_config())
        runtime.api = object()
        runtime.game_id = 7
        runtime.steam_app_id = 4000
        with (
            patch("services.parser_service.get_instance", return_value=_instance(3000)),
            patch("services.parser_service.read_secret_value", side_effect=_secret_value),
            patch.object(runtime, "_apply_runtime_settings"),
            patch.object(runtime, "_reinitialize_client_state", return_value=True) as reinitialize,
        ):
            runtime._refresh_config_from_cluster()

        self.assertEqual(runtime.cfg.steam_max_pages, 3000)
        reinitialize.assert_not_called()

    async def test_run_sync_once_uses_latest_cluster_sync_settings(self) -> None:
        runtime = ParserRuntime(_config())
        runtime.api = object()
        runtime.game_id = 7
        runtime.steam_app_id = 4000
        with (
            patch("services.parser_service.get_instance", return_value=_instance(3000)),
            patch("services.parser_service.read_secret_value", side_effect=_secret_value),
            patch("services.parser_service.asyncio.to_thread", side_effect=_immediate_to_thread),
            patch("services.parser_service.sync_mods") as sync_mods,
            patch.object(runtime, "_report_status"),
            patch.object(runtime, "_apply_runtime_settings"),
            patch.object(runtime, "_reinitialize_client_state", return_value=True) as reinitialize,
        ):
            await runtime.run_sync_once()

        self.assertEqual(runtime.last_sync_result, "success")
        self.assertEqual(sync_mods.call_args.args[7], 3000)
        reinitialize.assert_not_called()

    def test_proxy_snapshot_includes_pod_and_stats_metadata(self) -> None:
        runtime = ParserRuntime(
            _config(
                steam_proxy_pool=["socks5://user:pass@46.8.223.44:3001"],
                steam_proxy_scope="mod_pages",
                instance_name="demo",
            )
        )
        with (
            patch.dict("os.environ", {"HOSTNAME": "demo-parser-0"}, clear=False),
            patch("services.parser_service.snapshot_proxy_stats", return_value={"totalCalls": 7}),
        ):
            snapshot = runtime.proxy_snapshot()

        self.assertEqual(snapshot["instanceName"], "demo")
        self.assertEqual(snapshot["podName"], "demo-parser-0")
        self.assertEqual(snapshot["windowLabel"], "1h")
        self.assertEqual(snapshot["proxyConfigured"], True)
        self.assertEqual(snapshot["proxyPoolSize"], 1)
        self.assertEqual(snapshot["proxyScope"], "mod_pages")
        self.assertEqual(snapshot["stats"]["totalCalls"], 7)
        self.assertEqual(snapshot["proxies"], [])

    def test_run_parser_accepts_registered_non_default_parser_type(self) -> None:
        fake_adapter = _FakeParserAdapter()
        with (
            patch.dict("core.parser_registry._PARSER_REGISTRY", {FAKE_PARSER_TYPE: _fake_contract()}, clear=False),
            patch.dict("services.parser_service._RUNTIME_ADAPTERS", {FAKE_PARSER_TYPE: fake_adapter}, clear=False),
            patch.dict(
                "os.environ",
                {
                    "OW_PARSER_TYPE": FAKE_PARSER_TYPE,
                    "OW_WORKLOAD_ID": "ingestor",
                },
                clear=False,
            ),
            patch("services.parser_service.load_config", return_value=_config(run_once=True, instance_name="", instance_namespace="")),
            patch("services.parser_service.init_telemetry"),
            patch("services.parser_service.shutdown_telemetry"),
        ):
            result = run_parser()

        self.assertEqual(result, 0)
        self.assertEqual(fake_adapter.bootstrap_calls, 1)
        self.assertEqual(fake_adapter.sync_calls, 1)

    def test_proxy_detail_snapshot_wraps_collector_detail(self) -> None:
        runtime = ParserRuntime(
            _config(
                steam_proxy_pool=["socks5://user:pass@46.8.223.44:3001"],
                steam_proxy_scope="mod_pages",
                instance_name="demo",
            )
        )
        detail_payload = {
            "proxyKey": "socks5://46.8.223.44:3001",
            "proxyLabel": "socks5://46.8.223.44:3001",
            "found": True,
            "bucketCount": 24,
            "bucketSizeSeconds": 150.0,
            "stats": {
                "proxyKey": "socks5://46.8.223.44:3001",
                "proxyLabel": "socks5://46.8.223.44:3001",
                "totalCalls": 6,
                "successCalls": 4,
                "failureCalls": 2,
                "totalElapsedSeconds": 1.8,
                "averageResponseMs": 300.0,
                "recentRequests": 6,
                "recentWindowSeconds": 3600.0,
                "windowSeconds": 3600.0,
                "windowLabel": "1h",
                "requestsPerSecond": 6 / 3600.0,
                "requestsPerMinute": 6 / 60.0,
                "errorCounts": {"ProxyTimeoutError": 2},
                "failureRate": 1 / 3,
                "topError": {"label": "ProxyTimeoutError", "count": 2},
            },
            "buckets": [],
            "recentFailures": [],
        }
        with (
            patch("services.parser_service.snapshot_proxy_detail", return_value=detail_payload),
            patch.dict("os.environ", {"HOSTNAME": "demo-parser-0"}, clear=False),
        ):
            snapshot = runtime.proxy_detail_snapshot(
                proxy="socks5://46.8.223.44:3001",
                window_seconds=3600.0,
            )

        self.assertEqual(snapshot["instanceName"], "demo")
        self.assertEqual(snapshot["podName"], "demo-parser-0")
        self.assertEqual(snapshot["proxyKey"], "socks5://46.8.223.44:3001")
        self.assertEqual(snapshot["proxyLabel"], "socks5://46.8.223.44:3001")
        self.assertEqual(snapshot["bucketCount"], 24)
        self.assertTrue(snapshot["found"])
        self.assertEqual(snapshot["stats"]["totalCalls"], 6)
        self.assertEqual(snapshot["stats"]["topError"]["label"], "ProxyTimeoutError")


if __name__ == "__main__":
    unittest.main()
