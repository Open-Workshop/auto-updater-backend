import json
import unittest

from kube_resources import (
    build_parser_statefulset,
    build_runner_config_secret,
    build_runner_statefulset,
    render_singbox_config,
)
from mirror_instance import runner_service_url


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
        )
        containers = statefulset["spec"]["template"]["spec"]["containers"]
        self.assertEqual(len(containers), 2)
        self.assertEqual(containers[1]["name"], "tun-proxy")
        self.assertEqual(
            containers[1]["securityContext"]["capabilities"]["add"],
            ["NET_ADMIN"],
        )


if __name__ == "__main__":
    unittest.main()
