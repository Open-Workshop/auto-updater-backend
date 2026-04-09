"""Resource utilities for UI service."""
from __future__ import annotations

import json
import logging
from typing import Any

from kubernetes.client.rest import ApiException

from kube.kube_client import get_kube_clients
from ui.ui_formatting import _int_value
from ui.ui_kube_utils import (
    _pod_snapshot,
    _pod_usage_metrics,
    _read_node_stats_summary,
    _select_best_pod,
)


def _resource_usage(
    *,
    cpu_millicores: int | None,
    memory_bytes: int | None,
    disk_capacity_bytes: int | None,
    disk_used_bytes: int | None,
    disk_requested_bytes: int | None,
    node_capacity_millicores: int | None = None,
    node_capacity_bytes: int | None = None,
) -> dict[str, Any]:
    """Create a resource usage dictionary with formatted labels."""
    from ui.ui_formatting import _format_cpu_percent, _format_memory_percent, _format_disk_usage
    
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


def _storage_request_bytes(instance: dict[str, Any], component: str) -> int | None:
    """Get storage request bytes for a component."""
    from ui.ui_formatting import _parse_bytes
    
    spec = dict(instance.get("spec") or {})
    storage = dict(spec.get("storage") or {})
    component_storage = dict(storage.get(component) or {})
    return _parse_bytes(component_storage.get("size"))


def _storage_capacity_bytes(instance: dict[str, Any], component: str) -> int | None:
    """Get effective storage capacity bytes for a component."""
    return _storage_request_bytes(instance, component)


def _pod_persistent_disk_metrics(
    namespace: str,
    component_snapshots: dict[str, dict[str, Any]],
) -> dict[str, dict[str, int | None]]:
    """Get PVC-backed disk metrics for pods from node stats summary."""
    pods_by_node: dict[str, set[str]] = {}
    for components in component_snapshots.values():
        for component in ("parser", "runner"):
            snapshot = dict(components.get(component) or {})
            pod_name = str(snapshot.get("podName") or "")
            node_name = str(snapshot.get("nodeName") or "")
            if pod_name and node_name:
                pods_by_node.setdefault(node_name, set()).add(pod_name)
    disk_usage: dict[str, dict[str, int | None]] = {}
    for node_name, pod_names in pods_by_node.items():
        try:
            summary = _read_node_stats_summary(node_name)
        except ApiException as exc:
            if exc.status in {403, 404, 503}:
                continue
            raise
        except json.JSONDecodeError:
            logging.warning("Failed to decode node stats summary for %s", node_name)
            continue
        for pod in list(summary.get("pods") or []):
            pod_ref = dict(pod.get("podRef") or {})
            if str(pod_ref.get("namespace") or "") != namespace:
                continue
            pod_name = str(pod_ref.get("name") or "")
            if pod_name not in pod_names:
                continue
            total_used = 0
            total_capacity = 0
            found_usage = False
            for volume in list(pod.get("volume") or []):
                pvc_ref = dict(volume.get("pvcRef") or {})
                if not pvc_ref:
                    continue
                used_bytes = _int_value(volume.get("usedBytes"))
                capacity_bytes = _int_value(volume.get("capacityBytes"))
                if used_bytes is None:
                    continue
                total_used += used_bytes
                if capacity_bytes is not None:
                    total_capacity += capacity_bytes
                found_usage = True
            if found_usage:
                disk_usage[pod_name] = {
                    "usedBytes": total_used,
                    "reportedCapacityBytes": total_capacity or None,
                }
    return disk_usage


def _component_resource_metrics_for_names(
    namespace: str,
    component_snapshots: dict[str, dict[str, Any]],
) -> dict[str, dict[str, dict[str, int | None]]]:
    """Get resource metrics for components."""
    pod_names = {
        str(snapshot.get("podName") or "")
        for components in component_snapshots.values()
        for snapshot in components.values()
        if str(snapshot.get("podName") or "")
    }
    usage_metrics = _pod_usage_metrics(namespace, pod_names)
    disk_usage = _pod_persistent_disk_metrics(namespace, component_snapshots)
    resources: dict[str, dict[str, dict[str, int | None]]] = {}
    for name, components in component_snapshots.items():
        resources[name] = {}
        for component in ("parser", "runner"):
            snapshot = dict(components.get(component) or {})
            pod_name = str(snapshot.get("podName") or "")
            usage = dict(usage_metrics.get(pod_name) or {})
            disk = dict(disk_usage.get(pod_name) or {})
            resources[name][component] = {
                "cpuMilliCores": _int_value(usage.get("cpuMilliCores")),
                "memoryBytes": _int_value(usage.get("memoryBytes")),
                "diskUsedBytes": _int_value(disk.get("usedBytes")),
                "diskReportedCapacityBytes": _int_value(
                    disk.get("reportedCapacityBytes")
                ),
                "rxBytes": _int_value(usage.get("rxBytes")),
                "txBytes": _int_value(usage.get("txBytes")),
            }
    return resources


def _component_snapshots_for_names(namespace: str, names: set[str]) -> dict[str, dict[str, Any]]:
    """Get pod snapshots for components by instance names."""
    if not names:
        return {}
    try:
        pods = get_kube_clients().core.list_namespaced_pod(
            namespace,
            label_selector="app.kubernetes.io/name=auto-updater",
        ).items
    except Exception:
        return {}
    grouped: dict[str, dict[str, list[Any]]] = {}
    for pod in pods:
        labels = dict(getattr(pod.metadata, "labels", None) or {})
        instance = str(labels.get("auto-updater.miskler.ru/instance") or "")
        component = str(labels.get("app.kubernetes.io/component") or "")
        if instance not in names or component not in {"parser", "runner"}:
            continue
        grouped.setdefault(instance, {}).setdefault(component, []).append(pod)
    snapshots: dict[str, dict[str, Any]] = {}
    for name in names:
        snapshots[name] = {}
        for component in ("parser", "runner"):
            best = _select_best_pod(grouped.get(name, {}).get(component, []))
            snapshots[name][component] = _pod_snapshot(best)
    return snapshots


def _component_state(snapshot: dict[str, Any], fallback_pod_name: str = "") -> dict[str, str]:
    """Get component state from pod snapshot."""
    pod_name = str(snapshot.get("podName") or fallback_pod_name or "")
    if not pod_name:
        return {"label": "Missing", "tone": "error"}
    if snapshot.get("deleting"):
        return {"label": "Updating", "tone": "warning"}
    if snapshot.get("ready"):
        return {"label": "Ready", "tone": "healthy"}
    phase = str(snapshot.get("phase") or "Unknown")
    if phase in {"Pending", "ContainerCreating"}:
        return {"label": "Starting", "tone": "warning"}
    return {"label": phase or "Not ready", "tone": "warning"}
