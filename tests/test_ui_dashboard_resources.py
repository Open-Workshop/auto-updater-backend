import importlib
import sys
import types
import unittest

from ui.ui_formatting import (
    _format_cpu_percent,
    _format_decimal,
    _format_disk_usage,
    _format_memory_percent,
)


def _install_ui_instance_stubs() -> None:
    kube_client = types.ModuleType("kube.kube_client")
    kube_client.get_instance = lambda *_args, **_kwargs: {}
    kube_client.list_instances = lambda *_args, **_kwargs: []
    sys.modules["kube.kube_client"] = kube_client

    mirror_instance = types.ModuleType("kube.mirror_instance")
    mirror_instance.common_labels = lambda *_args, **_kwargs: {}
    mirror_instance.instance_name = lambda instance: str(
        dict(instance.get("metadata") or {}).get("name") or ""
    )
    mirror_instance.normalize_instance = lambda instance: instance
    mirror_instance.parser_name = lambda name: f"{name}-parser"
    mirror_instance.parser_service_name = lambda name: f"{name}-parser"
    mirror_instance.runner_name = lambda name: f"{name}-runner"
    mirror_instance.runner_service_name = lambda name: f"{name}-runner"
    sys.modules["kube.mirror_instance"] = mirror_instance

    ui_common = types.ModuleType("ui.ui_common")

    class UISettings:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    ui_common.UISettings = UISettings
    ui_common._format_time = lambda value: str(value or "n/a")
    ui_common._url = lambda _settings, path: path
    sys.modules["ui.ui_common"] = ui_common

    ui_kube_utils = types.ModuleType("ui.ui_kube_utils")
    ui_kube_utils._get_cluster_cpu_capacity = lambda: 8000
    ui_kube_utils._get_cluster_memory_capacity = lambda: 8_000_000_000
    ui_kube_utils._get_cluster_disk_stats = lambda: {
        "capacityBytes": 100_000_000_000,
        "usedBytes": 76_000_000_000,
    }
    ui_kube_utils._get_node_cpu_capacity = lambda _node_name: 4000
    ui_kube_utils._get_node_memory_capacity = lambda _node_name: 4_000_000_000
    sys.modules["ui.ui_kube_utils"] = ui_kube_utils

    ui_resources = types.ModuleType("ui.ui_resources")

    def _resource_usage(
        *,
        cpu_millicores,
        memory_bytes,
        disk_capacity_bytes,
        disk_used_bytes,
        disk_requested_bytes,
        node_capacity_millicores=None,
        node_capacity_bytes=None,
    ):
        return {
            "cpuMilliCores": cpu_millicores,
            "memoryBytes": memory_bytes,
            "diskCapacityBytes": disk_capacity_bytes,
            "diskUsedBytes": disk_used_bytes,
            "diskRequestedBytes": disk_requested_bytes,
            "cpuLabel": _format_cpu_percent(cpu_millicores, node_capacity_millicores),
            "memoryLabel": _format_memory_percent(memory_bytes, node_capacity_bytes),
            "diskLabel": _format_disk_usage(
                disk_capacity_bytes,
                disk_used_bytes,
                disk_requested_bytes,
            ),
        }

    ui_resources._component_snapshots_for_names = lambda *_args, **_kwargs: {}
    ui_resources._component_resource_metrics_for_names = (
        lambda *_args, **_kwargs: {}
    )
    ui_resources._component_state = lambda *_args, **_kwargs: {
        "label": "Ready",
        "tone": "healthy",
    }
    ui_resources._resource_usage = _resource_usage
    ui_resources._storage_capacity_bytes = (
        lambda instance, component: dict(
            dict(dict(instance.get("spec") or {}).get("storage") or {}).get(component)
            or {}
        ).get("capacity")
    )
    ui_resources._storage_request_bytes = (
        lambda instance, component: dict(
            dict(dict(instance.get("spec") or {}).get("storage") or {}).get(component)
            or {}
        ).get("requested")
    )
    sys.modules["ui.ui_resources"] = ui_resources


def _load_ui_instance_module():
    _install_ui_instance_stubs()
    sys.modules.pop("ui.ui_instance", None)
    return importlib.import_module("ui.ui_instance")


class UIDashboardResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ui_instance = _load_ui_instance_module()

    def test_dashboard_totals_use_child_memory_and_cluster_disk(self) -> None:
        totals = self.ui_instance._dashboard_resource_totals(
            [
                {
                    "resources": {
                        "cpuMilliCores": 1,
                        "memoryBytes": 1,
                        "diskUsedBytes": 999_000_000_000,
                        "diskRequestedBytes": 1,
                    },
                    "parser": {
                        "resources": {
                            "cpuMilliCores": 100,
                            "memoryBytes": 150_000_000,
                            "diskRequestedBytes": 20_000_000_000,
                        }
                    },
                    "runner": {
                        "resources": {
                            "cpuMilliCores": 200,
                            "memoryBytes": 250_000_000,
                            "diskRequestedBytes": 10_000_000_000,
                        }
                    },
                }
            ]
        )

        self.assertEqual(totals["cpuMilliCores"], 300)
        self.assertEqual(totals["memoryBytes"], 400_000_000)
        self.assertEqual(totals["diskCapacityBytes"], 100_000_000_000)
        self.assertEqual(totals["diskUsedBytes"], 76_000_000_000)
        self.assertEqual(totals["diskRequestedBytes"], 30_000_000_000)
        self.assertEqual(
            totals["diskLabel"],
            "100GB cap / 76GB used / 30GB req",
        )

    def test_format_decimal_keeps_significant_integer_zeroes(self) -> None:
        self.assertEqual(_format_decimal(100.0, 0), "100")
        self.assertEqual(_format_decimal(480.0, 0), "480")

    def test_trusted_persistent_disk_used_bytes_rejects_host_filesystem_metrics(self) -> None:
        self.assertIsNone(
            self.ui_instance._trusted_persistent_disk_used_bytes(
                70_000_000_000,
                123_000_000_000,
                20_000_000_000,
            )
        )
        self.assertEqual(
            self.ui_instance._trusted_persistent_disk_used_bytes(
                7_000_000_000,
                20_000_000_000,
                20_000_000_000,
            ),
            7_000_000_000,
        )


if __name__ == "__main__":
    unittest.main()
