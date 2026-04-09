import unittest
from unittest.mock import patch

from kube.mirror_instance import runner_config_secret_name

try:
    from kube.operator_service import MirrorInstanceOperator, OperatorSettings
except ModuleNotFoundError:
    MirrorInstanceOperator = None
    OperatorSettings = None


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
            "pollIntervalSeconds": 10,
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


@unittest.skipUnless(MirrorInstanceOperator is not None, "kubernetes dependency is not installed")
class OperatorServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.operator = MirrorInstanceOperator(
            OperatorSettings(
                namespace="auto-updater",
                interval_seconds=15,
                app_image="example/image:latest",
                singbox_image="ghcr.io/sagernet/sing-box:latest",
            )
        )

    def test_reconcile_instance_upserts_runner_config_when_proxy_is_present(self) -> None:
        with patch("kube.operator_service.read_secret_value", side_effect=["login", "password", "pool", "socks5://127.0.0.1:3001"]):
            with patch("kube.operator_service.build_runner_config_secret", return_value={"metadata": {"name": runner_config_secret_name("demo")}}) as build_secret:
                with patch("kube.operator_service.upsert_secret") as upsert_secret:
                    with patch("kube.operator_service.delete_secret") as delete_secret:
                        with patch("kube.operator_service.upsert_service"):
                            with patch("kube.operator_service.upsert_statefulset"):
                                with patch.object(self.operator, "_sync_status"):
                                    self.operator.reconcile_instance(INSTANCE)

        build_secret.assert_called_once()
        upsert_secret.assert_called_once_with(
            "auto-updater",
            {"metadata": {"name": runner_config_secret_name("demo")}},
        )
        delete_secret.assert_not_called()

    def test_reconcile_instance_deletes_stale_runner_config_when_proxy_is_disabled(self) -> None:
        with patch("kube.operator_service.read_secret_value", side_effect=["login", "password", "pool", ""]):
            with patch("kube.operator_service.build_runner_config_secret") as build_secret:
                with patch("kube.operator_service.upsert_secret") as upsert_secret:
                    with patch("kube.operator_service.delete_secret") as delete_secret:
                        with patch("kube.operator_service.upsert_service"):
                            with patch("kube.operator_service.upsert_statefulset"):
                                with patch.object(self.operator, "_sync_status"):
                                    self.operator.reconcile_instance(INSTANCE)

        build_secret.assert_not_called()
        upsert_secret.assert_not_called()
        delete_secret.assert_called_once_with("auto-updater", runner_config_secret_name("demo"))


if __name__ == "__main__":
    unittest.main()
