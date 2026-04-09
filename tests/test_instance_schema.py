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


class InstanceSchemaTests(unittest.TestCase):
    def test_round_trip_preserves_sync_extras(self) -> None:
        model = MirrorInstanceSpecModel.from_instance_dict(INSTANCE)
        self.assertEqual(model.sync["pageSize"], 77)
        self.assertEqual(model.sync_extras, {"customMirrorSetting": {"keep": True}})

        rebuilt = model.to_spec_dict()
        self.assertEqual(rebuilt["sync"]["pageSize"], 77)
        self.assertEqual(rebuilt["sync"]["customMirrorSetting"], {"keep": True})

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

        self.assertEqual(form_values["poll_interval_seconds"], spec["sync"]["pollIntervalSeconds"])
        self.assertEqual(form_values["timeout_seconds"], spec["sync"]["timeoutSeconds"])
        self.assertEqual(cfg.poll_interval, spec["sync"]["pollIntervalSeconds"])
        self.assertEqual(cfg.timeout, spec["sync"]["timeoutSeconds"])
        self.assertEqual(cfg.http_retries, spec["sync"]["httpRetries"])
        self.assertEqual(cfg.max_screenshots, spec["sync"]["maxScreenshots"])

    def test_schema_validation_uses_registry_rules(self) -> None:
        errors = validate_sync_form_inputs(
            {
                "poll_interval_seconds": "0",
                "timeout_seconds": "-1",
                "http_retries": "-2",
                "http_retry_backoff": "-0.5",
                "steam_http_retries": "-1",
                "steam_http_backoff": "-1",
                "steam_request_delay": "-0.5",
                "max_screenshots": "-3",
            }
        )

        self.assertEqual(errors["poll_interval_seconds"], "Poll interval must be at least 1")
        self.assertEqual(errors["timeout_seconds"], "HTTP timeout must be at least 1")
        self.assertEqual(errors["http_retries"], "HTTP retries must be zero or greater")
        self.assertEqual(errors["steam_request_delay"], "Steam request delay must be zero or greater")

    def test_sync_json_patch_is_additive_only_for_unknown_fields(self) -> None:
        sync = build_sync_spec_from_form(
            INSTANCE["spec"]["sync"],
            {
                "poll_interval_seconds": "600",
                "timeout_seconds": "60",
                "http_retries": "3",
                "http_retry_backoff": "5.0",
                "steam_http_retries": "2",
                "steam_http_backoff": "2.0",
                "steam_request_delay": "1.0",
                "log_level": "INFO",
                "max_screenshots": "20",
                "run_once": "",
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

        self.assertEqual(sync["pageSize"], 77)
        self.assertEqual(
            sync["customMirrorSetting"],
            {"keep": True, "mode": "extra"},
        )


if __name__ == "__main__":
    unittest.main()
