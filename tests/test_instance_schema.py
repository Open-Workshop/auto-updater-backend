import unittest
from unittest.mock import patch

from core.config import load_config
from core.instance_schema import (
    MirrorInstanceSpecModel,
    build_sync_spec_from_form,
    default_spec,
    sync_form_values,
    validate_sync_form_inputs,
)
from core.parser_registry import (
    ParserConfigFieldSpec,
    ParserContract,
    ParserSecretSpec,
    ParserWorkloadSpec,
    WorkloadLogTargetSpec,
)
from kube.kube_resources import build_parser_env


INSTANCE = {
    "apiVersion": "auto-updater.miskler.ru/v1alpha1",
    "kind": "MirrorInstance",
    "metadata": {
        "name": "demo",
        "namespace": "auto-updater",
        "uid": "uid-1",
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
            "pageSize": 77,
            "customMirrorSetting": {"keep": True},
        },
        "credentials": {"secretRef": "demo-ow-credentials"},
        "parser": {"proxyPoolSecretRef": "demo-parser-proxies"},
        "steamcmd": {"proxy": {"type": "socks5", "secretRef": "demo-steamcmd-proxy"}},
        "storage": {
            "parser": {"size": "20Gi", "storageClassName": "local-path"},
            "runner": {"size": "10Gi", "storageClassName": "local-path"},
        },
    },
}


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


def _fake_instance() -> dict:
    return {
        "apiVersion": "auto-updater.miskler.ru/v1alpha1",
        "kind": "MirrorInstance",
        "metadata": {
            "name": "demo",
            "namespace": "auto-updater",
            "uid": "uid-1",
        },
        "spec": {
            "enabled": True,
            "parser": {
                "type": FAKE_PARSER_TYPE,
                "config": {
                    "sourceUrl": "https://api.example.test",
                },
                "secretRefs": {
                    "parserProxyPoolSecretRef": "demo-parser-proxies",
                    "runnerProxySecretRef": "demo-runner-proxy",
                },
                "workloads": {
                    "ingestor": {
                        "storage": {
                            "size": "20Gi",
                            "storageClassName": "local-path",
                        },
                        "config": {},
                    },
                    "fetcher": {
                        "storage": {
                            "size": "10Gi",
                            "storageClassName": "local-path",
                        },
                        "config": {
                            "proxyType": "http",
                        },
                    },
                },
            },
            "credentials": {"secretRef": "demo-ow-credentials"},
        },
    }


class InstanceSchemaTests(unittest.TestCase):
    def test_round_trip_preserves_sync_extras(self) -> None:
        model = MirrorInstanceSpecModel.from_instance_dict(INSTANCE)
        self.assertEqual(model.sync["pageSize"], 77)
        self.assertEqual(model.sync_extras, {"customMirrorSetting": {"keep": True}})

        rebuilt = model.to_spec_dict()
        self.assertEqual(rebuilt["parser"]["config"]["pageSize"], 77)
        self.assertEqual(rebuilt["parser"]["config"]["customMirrorSetting"], {"keep": True})

    def test_non_default_parser_round_trip_stays_canonical(self) -> None:
        with patch.dict("core.parser_registry._PARSER_REGISTRY", {FAKE_PARSER_TYPE: _fake_contract()}, clear=False):
            model = MirrorInstanceSpecModel.from_instance_dict(_fake_instance())
            rebuilt = model.to_compat_spec_dict()

        self.assertEqual(model.parser_type, FAKE_PARSER_TYPE)
        self.assertEqual(model.parser_config["sourceUrl"], "https://api.example.test")
        self.assertEqual(model.parser_workloads["ingestor"]["storage"]["size"], "20Gi")
        self.assertEqual(rebuilt["parser"]["type"], FAKE_PARSER_TYPE)
        self.assertNotIn("source", rebuilt)
        self.assertNotIn("sync", rebuilt)
        self.assertNotIn("steamcmd", rebuilt)
        self.assertNotIn("storage", rebuilt)

    def test_defaults_match_form_values_and_runtime_env_projection(self) -> None:
        spec = default_spec()
        form_values = sync_form_values(spec["sync"])
        env = {
            item["name"]: item["value"]
            for item in build_parser_env({"metadata": {"name": "demo", "namespace": "auto-updater"}, "spec": spec})
            if "value" in item
        }

        with patch.dict("os.environ", env, clear=False):
            cfg = load_config()

        self.assertEqual(form_values["api_base"], spec["sync"]["apiBase"])
        self.assertEqual(form_values["page_size"], spec["sync"]["pageSize"])
        self.assertEqual(form_values["poll_interval_seconds"], spec["sync"]["pollIntervalSeconds"])
        self.assertEqual(form_values["steam_max_pages"], spec["sync"]["steamMaxPages"])
        self.assertEqual(form_values["steam_start_page"], spec["sync"]["steamStartPage"])
        self.assertEqual(form_values["steam_max_items"], spec["sync"]["steamMaxItems"])
        self.assertEqual(form_values["steam_delay"], spec["sync"]["steamDelay"])
        self.assertEqual(form_values["force_required_item_id"], spec["sync"]["forceRequiredItemId"])
        self.assertEqual(form_values["public_mode"], spec["sync"]["publicMode"])
        self.assertEqual(form_values["without_author"], spec["sync"]["withoutAuthor"])
        self.assertEqual(form_values["timeout_seconds"], spec["sync"]["timeoutSeconds"])
        self.assertEqual(cfg.poll_interval, spec["sync"]["pollIntervalSeconds"])
        self.assertEqual(cfg.page_size, spec["sync"]["pageSize"])
        self.assertEqual(cfg.steam_max_pages, spec["sync"]["steamMaxPages"])
        self.assertEqual(cfg.timeout, spec["sync"]["timeoutSeconds"])
        self.assertEqual(cfg.http_retries, spec["sync"]["httpRetries"])
        self.assertEqual(cfg.max_screenshots, spec["sync"]["maxScreenshots"])

    def test_schema_validation_uses_registry_rules(self) -> None:
        errors = validate_sync_form_inputs(
            {
                "poll_interval_seconds": "0",
                "page_size": "foo",
                "timeout_seconds": "-1",
                "http_retries": "-2",
                "http_retry_backoff": "-0.5",
                "steam_http_retries": "-1",
                "steam_http_backoff": "-1",
                "steam_request_delay": "-0.5",
                "steam_max_pages": "-1",
                "steam_start_page": "0",
                "steam_max_items": "-3",
                "steam_delay": "-0.1",
                "max_screenshots": "-3",
            }
        )

        self.assertEqual(errors["page_size"], "Page size must be an integer")
        self.assertEqual(errors["poll_interval_seconds"], "Poll interval must be at least 1")
        self.assertEqual(errors["timeout_seconds"], "HTTP timeout must be at least 1")
        self.assertEqual(errors["http_retries"], "HTTP retries must be zero or greater")
        self.assertEqual(errors["steam_max_pages"], "Steam max pages must be zero or greater")
        self.assertEqual(errors["steam_start_page"], "Steam start page must be at least 1")
        self.assertEqual(errors["steam_max_items"], "Steam max items must be zero or greater")
        self.assertEqual(errors["steam_request_delay"], "Steam request delay must be zero or greater")
        self.assertEqual(errors["steam_delay"], "Steam page delay must be zero or greater")

    def test_optional_numeric_fields_accept_blank_and_use_defaults(self) -> None:
        errors = validate_sync_form_inputs(
            {
                "steam_max_items": "",
                "public_mode": "",
            }
        )

        self.assertNotIn("steam_max_items", errors)
        self.assertNotIn("public_mode", errors)

        sync = build_sync_spec_from_form(
            default_spec()["sync"],
            {
                "steam_max_items": "",
                "public_mode": "",
            },
        )

        self.assertEqual(sync["steamMaxItems"], 0)
        self.assertEqual(sync["publicMode"], 0)

    def test_sync_json_patch_is_additive_only_for_unknown_fields(self) -> None:
        sync = build_sync_spec_from_form(
            INSTANCE["spec"]["sync"],
            {
                "api_base": "https://api.example.test",
                "page_size": "88",
                "poll_interval_seconds": "600",
                "timeout_seconds": "60",
                "http_retries": "3",
                "http_retry_backoff": "5.0",
                "log_steam_requests": "on",
                "steam_http_retries": "2",
                "steam_http_backoff": "2.0",
                "steam_request_delay": "1.0",
                "steam_max_pages": "0",
                "steam_start_page": "3",
                "steam_max_items": "500",
                "steam_delay": "2.5",
                "log_level": "INFO",
                "max_screenshots": "20",
                "force_required_item_id": "123456",
                "public_mode": "2",
                "run_once": "",
                "without_author": "on",
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
            {
                "pageSize": 999,
                "customMirrorSetting": {"mode": "extra"},
            },
        )

        self.assertEqual(sync["apiBase"], "https://api.example.test")
        self.assertEqual(sync["pageSize"], 88)
        self.assertTrue(sync["logSteamRequests"])
        self.assertEqual(sync["steamMaxPages"], 0)
        self.assertEqual(sync["steamStartPage"], 3)
        self.assertEqual(sync["steamMaxItems"], 500)
        self.assertEqual(sync["steamDelay"], 2.5)
        self.assertEqual(sync["forceRequiredItemId"], "123456")
        self.assertEqual(sync["publicMode"], 2)
        self.assertTrue(sync["withoutAuthor"])
        self.assertEqual(
            sync["customMirrorSetting"],
            {"keep": True, "mode": "extra"},
        )


if __name__ == "__main__":
    unittest.main()
