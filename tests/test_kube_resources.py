import json
import unittest
from unittest.mock import patch

from kube.kube_resources import (
    build_parser_statefulset,
    build_parser_env,
    build_runner_config_secret,
    build_runner_statefulset,
    render_singbox_config,
)
from core.parser_registry import (
    ParserConfigFieldSpec,
    ParserContract,
    ParserSecretSpec,
    ParserWorkloadSpec,
    WorkloadLogTargetSpec,
)
from kube.mirror_instance import managed_runner_proxy_secret_name, runner_service_url


INSTANCE = {
    "apiVersion": "auto-updater.miskler.ru/v1alpha1",
    "kind": "MirrorInstance",
    "metadata": {
        "name": "rimworld",
        "namespace": "auto-updater",
        "uid": "uid-1",
    },
    "spec": {
        "enabled": True,
        "source": {
            "steamAppId": 294100,
            "owGameId": 12,
            "language": "english",
        },
        "sync": {
            "pollIntervalSeconds": 600,
            "pageSize": 50,
            "timeoutSeconds": 60,
        },
        "credentials": {"secretRef": "rimworld-ow-credentials"},
        "parser": {"proxyPoolSecretRef": "rimworld-parser-proxies"},
        "steamcmd": {"proxy": {"type": "socks5", "secretRef": "rimworld-steamcmd-proxy"}},
        "storage": {
            "parser": {"size": "30Gi", "storageClassName": "local-path"},
            "runner": {"size": "12Gi", "storageClassName": "local-path"},
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


class KubeResourceTests(unittest.TestCase):
    def test_parser_statefulset_contains_runner_url(self) -> None:
        statefulset = build_parser_statefulset(INSTANCE, "example/image:latest")
        self.assertEqual(statefulset["spec"]["replicas"], 1)
        env = {item["name"]: item for item in statefulset["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(
            env["OW_STEAMCMD_RUNNER_URL"]["value"],
            runner_service_url("rimworld", "auto-updater"),
        )
        self.assertEqual(env["OW_INSTANCE_NAME"]["value"], "rimworld")
        self.assertEqual(
            statefulset["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"],
            "30Gi",
        )

    def test_runner_config_secret_renders_socks_outbound(self) -> None:
        secret = build_runner_config_secret(
            INSTANCE,
            "socks5://user:pass@46.8.223.44:3001",
        )
        payload = json.loads(secret["stringData"]["config.json"])
        self.assertEqual(payload["outbounds"][0]["type"], "socks")
        self.assertEqual(payload["outbounds"][0]["server_port"], 3001)
        self.assertEqual(payload["route"]["final"], "proxy")

    def test_runner_config_rejects_type_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            render_singbox_config("http://46.8.223.44:3000", "socks5")

    def test_runner_statefulset_has_tun_sidecar(self) -> None:
        statefulset = build_runner_statefulset(
            INSTANCE,
            "example/image:latest",
            "ghcr.io/sagernet/sing-box:latest",
            "socks5://user:pass@46.8.223.44:3001",
        )
        containers = statefulset["spec"]["template"]["spec"]["containers"]
        self.assertEqual(len(containers), 2)
        self.assertEqual(containers[1]["name"], "tun-proxy")
        self.assertEqual(
            containers[1]["securityContext"]["capabilities"]["add"],
            ["NET_ADMIN"],
        )

    def test_runner_statefulset_without_proxy_keeps_persistent_data_volume(self) -> None:
        statefulset = build_runner_statefulset(
            INSTANCE,
            "example/image:latest",
            "ghcr.io/sagernet/sing-box:latest",
        )
        containers = statefulset["spec"]["template"]["spec"]["containers"]
        self.assertEqual([item["name"] for item in containers], ["runner"])
        self.assertNotIn("volumes", statefulset["spec"]["template"]["spec"])
        self.assertEqual(
            statefulset["spec"]["volumeClaimTemplates"][0]["metadata"]["name"],
            "data",
        )

    def test_contract_driven_names_and_secrets_follow_registered_parser(self) -> None:
        with patch.dict("core.parser_registry._PARSER_REGISTRY", {FAKE_PARSER_TYPE: _fake_contract()}, clear=False):
            parser_env = {
                item["name"]: item["value"]
                for item in build_parser_env(_fake_instance())
                if "value" in item
            }
            self.assertEqual(parser_env["OW_WORKLOAD_ID"], "ingestor")
            self.assertEqual(parser_env["OW_SOURCE_URL"], "https://api.example.test")
            self.assertEqual(
                parser_env["OW_STEAMCMD_RUNNER_URL"],
                "http://demo-fetcher.auto-updater.svc.cluster.local:8080",
            )

            parser_statefulset = build_parser_statefulset(_fake_instance(), "example/image:latest")
            self.assertEqual(parser_statefulset["metadata"]["name"], "demo-ingestor")
            self.assertEqual(parser_statefulset["spec"]["serviceName"], "demo-ingestor")
            self.assertEqual(
                managed_runner_proxy_secret_name("demo", FAKE_PARSER_TYPE),
                "demo-runner-proxy",
            )

            runner_statefulset = build_runner_statefulset(
                _fake_instance(),
                "example/image:latest",
                "ghcr.io/sagernet/sing-box:latest",
                "http://proxy:3000",
            )
            self.assertEqual(runner_statefulset["metadata"]["name"], "demo-fetcher")
            self.assertEqual(runner_statefulset["spec"]["serviceName"], "demo-fetcher")
            self.assertEqual(
                runner_statefulset["spec"]["template"]["spec"]["volumes"][0]["secret"]["secretName"],
                "demo-fetcher-config",
            )

            secret = build_runner_config_secret(_fake_instance(), "http://proxy:3000")
            self.assertEqual(secret["metadata"]["name"], "demo-fetcher-config")
            self.assertEqual(secret["metadata"]["labels"]["app.kubernetes.io/component"], "fetcher-config")


if __name__ == "__main__":
    unittest.main()
