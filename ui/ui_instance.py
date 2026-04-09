"""Instance-related utilities for UI service."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from core.instance_schema import (
    MirrorInstanceSpecModel,
    get_parser_contract,
    parser_overview_pairs,
    parser_subtitle_label,
)
from kube.kube_client import get_instance, list_instances
from kube.mirror_instance import (
    common_labels,
    instance_name,
    normalize_instance,
    parser_name,
    parser_service_name,
    runner_name,
    runner_service_name,
)
from ui.ui_common import UISettings, _format_time, _url
from ui.ui_formatting import _int_value, _sum_values
from ui.ui_kube_utils import (
    _get_cluster_cpu_capacity,
    _get_cluster_disk_stats,
    _get_cluster_memory_capacity,
    _get_node_cpu_capacity,
    _get_node_memory_capacity,
)
from ui.ui_resources import (
    _component_resource_metrics_for_names,
    _component_state,
    _resource_usage,
    _storage_capacity_bytes,
    _storage_request_bytes,
)

try:
    from ui.ui_resources import _component_snapshots_for_instances
except ImportError:  # pragma: no cover - compatibility for lightweight test stubs
    from ui.ui_resources import _component_snapshots_for_names as _component_snapshots_for_instances


def _derive_health(
    *,
    enabled: bool,
    phase: str,
    last_error: str,
    parser_ready: bool,
    runner_ready: bool,
) -> str:
    """Derive health status from various indicators."""
    if not enabled:
        return "Disabled"
    if phase == "Error" or last_error:
        return "Error"
    if phase == "Ready" and parser_ready and runner_ready:
        return "Healthy"
    return "Degraded"


def _health_tone(health: str) -> str:
    """Get CSS tone class for health status."""
    return {
        "Healthy": "healthy",
        "Syncing": "info",
        "Degraded": "warning",
        "Error": "error",
        "Disabled": "muted",
    }.get(health, "muted")


def _sync_state_label(status: dict[str, Any]) -> str:
    """Get label for sync state."""
    result = str(status.get("lastSyncResult") or "").strip().lower()
    if result == "running":
        return "Running"
    if result == "success":
        return "Succeeded"
    if result == "failed":
        return "Failed"
    if result:
        return result.title()
    return "Idle"


def _last_sync_label(status: dict[str, Any]) -> str:
    """Get label for last sync time."""
    result = str(status.get("lastSyncResult") or "").strip().lower()
    started_at = _format_time(status.get("lastSyncStartedAt"))
    finished_at = _format_time(status.get("lastSyncFinishedAt"))
    if result == "running":
        return f"Running since {started_at}"
    if result == "success":
        return f"Succeeded at {finished_at}"
    if result == "failed":
        return f"Failed at {finished_at}"
    if finished_at != "n/a":
        return finished_at
    if started_at != "n/a":
        return started_at
    return "Never"


def _error_summary(
    health: str,
    phase: str,
    status: dict[str, Any],
    parser_snapshot: dict[str, Any],
    runner_snapshot: dict[str, Any],
) -> str:
    """Get error summary for instance."""
    from ui.ui_common import _truncate
    
    last_error = str(status.get("lastError") or "").strip()
    sync_state = _sync_state_label(status)
    if last_error:
        return _truncate(last_error, 110)
    if health == "Disabled":
        return "Paused by operator"
    if sync_state == "Running":
        return "Sync in progress"
    if not parser_snapshot.get("ready"):
        return "Parser pod is not ready"
    if not runner_snapshot.get("ready"):
        return "Runner pod is not ready"
    if phase and phase != "Ready":
        return phase
    return "—"


def _instance_urls(settings: UISettings, name: str) -> dict[str, str]:
    """Get all URLs for an instance."""
    return {
        "detail": _url(settings, f"/instances/{quote(name)}"),
        "overview": _url(settings, f"/instances/{quote(name)}?tab=overview"),
        "logs": _url(settings, f"/instances/{quote(name)}?tab=logs"),
        "resources": _url(settings, f"/instances/{quote(name)}?tab=resources"),
        "settings": _url(settings, f"/instances/{quote(name)}?tab=settings"),
        "edit": _url(settings, f"/instances/{quote(name)}/edit"),
        "legacyLogs": _url(settings, f"/instances/{quote(name)}/logs/parser"),
        "legacyResources": _url(settings, f"/instances/{quote(name)}/resources"),
        "sync": _url(settings, f"/instances/{quote(name)}/sync"),
        "toggle": _url(settings, f"/instances/{quote(name)}/toggle"),
        "delete": _url(settings, f"/instances/{quote(name)}/delete"),
        "logsApi": _url(settings, f"/api/instances/{quote(name)}/logs"),
    }


def _trusted_persistent_disk_used_bytes(
    used_bytes: int | None,
    reported_capacity_bytes: int | None,
    expected_capacity_bytes: int | None,
) -> int | None:
    """Return PVC usage only when kubelet stats look scoped to the actual claim."""
    if used_bytes is None:
        return None
    if expected_capacity_bytes is None or expected_capacity_bytes <= 0:
        return None
    if reported_capacity_bytes is None or reported_capacity_bytes <= 0:
        return None
    if reported_capacity_bytes > int(expected_capacity_bytes * 1.5):
        return None
    if used_bytes > int(expected_capacity_bytes * 1.1):
        return None
    return used_bytes


def _rollup_component_resources(
    workload_resources: list[dict[str, Any]],
    *,
    node_capacity_millicores: int | None,
    node_capacity_bytes: int | None,
) -> dict[str, Any]:
    """Build a consistent total resource block from parser and runner resources."""
    return _resource_usage(
        cpu_millicores=_sum_values(
            [_int_value(item.get("cpuMilliCores")) for item in workload_resources]
        ),
        memory_bytes=_sum_values(
            [_int_value(item.get("memoryBytes")) for item in workload_resources]
        ),
        disk_capacity_bytes=_sum_values(
            [_int_value(item.get("diskCapacityBytes")) for item in workload_resources]
        ),
        disk_used_bytes=_sum_values(
            [_int_value(item.get("diskUsedBytes")) for item in workload_resources]
        ),
        disk_requested_bytes=_sum_values(
            [_int_value(item.get("diskRequestedBytes")) for item in workload_resources]
        ),
        node_capacity_millicores=node_capacity_millicores,
        node_capacity_bytes=node_capacity_bytes,
    )


def _instance_summary(
    settings: UISettings,
    instance: dict[str, Any],
    component_snapshots: dict[str, Any] | None = None,
    component_resources: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a summary of an instance."""
    normalized = normalize_instance(instance)
    model = MirrorInstanceSpecModel.from_instance_dict(normalized)
    contract = get_parser_contract(model.parser_type)
    status = dict(normalized.get("status") or {})
    workload_status = dict(status.get("workloads") or {})
    name = instance_name(normalized)
    component_snapshots = component_snapshots or {}
    component_resources = component_resources or {}
    parser_snapshot = dict(component_snapshots.get("parser") or {})
    runner_snapshot = dict(component_snapshots.get("steamcmd") or {})

    # Get node CPU and memory capacity for percentage calculation
    node_name = next(
        (
            str(dict(component_snapshots.get(workload.workload_id) or {}).get("nodeName") or "")
            for workload in contract.workloads
            if str(dict(component_snapshots.get(workload.workload_id) or {}).get("nodeName") or "")
        ),
        "",
    )
    logging.debug("Instance %s: node_name=%r, parser_nodeName=%r, runner_nodeName=%r",
                  name, node_name, parser_snapshot.get("nodeName"), runner_snapshot.get("nodeName"))
    node_capacity_millicores = _get_node_cpu_capacity(node_name) if node_name else None
    node_capacity_bytes = _get_node_memory_capacity(node_name) if node_name else None
    logging.debug("Instance %s: node_capacity_millicores=%r, node_capacity_bytes=%r", name, node_capacity_millicores, node_capacity_bytes)

    workload_summaries: list[dict[str, Any]] = []
    for workload in contract.workloads:
        workload_id = workload.workload_id
        snapshot = dict(component_snapshots.get(workload_id) or {})
        resource_snapshot = dict(component_resources.get(workload_id) or {})
        status_entry = dict(workload_status.get(workload_id) or {})
        pod_name = str(status_entry.get("podName") or "") or str(snapshot.get("podName") or "")
        state = _component_state(snapshot, pod_name)
        disk_capacity_bytes = _storage_capacity_bytes(normalized, workload_id)
        disk_requested_bytes = _storage_request_bytes(normalized, workload_id)
        disk_used_bytes = _trusted_persistent_disk_used_bytes(
            _int_value(resource_snapshot.get("diskUsedBytes")),
            _int_value(resource_snapshot.get("diskReportedCapacityBytes")),
            disk_capacity_bytes,
        )
        resources = _resource_usage(
            cpu_millicores=_int_value(resource_snapshot.get("cpuMilliCores")),
            memory_bytes=_int_value(resource_snapshot.get("memoryBytes")),
            disk_capacity_bytes=disk_capacity_bytes,
            disk_used_bytes=disk_used_bytes,
            disk_requested_bytes=disk_requested_bytes,
            node_capacity_millicores=node_capacity_millicores,
            node_capacity_bytes=node_capacity_bytes,
        )
        images = dict(snapshot.get("images") or {})
        workload_summaries.append(
            {
                "id": workload_id,
                "label": workload.display_label,
                "component": workload.component,
                "podName": pod_name,
                "state": state["label"],
                "tone": state["tone"],
                "ready": bool(snapshot.get("ready")),
                "image": str(status_entry.get("image") or images.get(workload.main_container_name) or ""),
                "serviceName": str(status_entry.get("serviceName") or ""),
                "resources": resources,
                "logTargets": [
                    {
                        "target": item.target,
                        "label": item.label,
                        "container": item.container_name,
                    }
                    for item in workload.log_targets
                ],
                "containerReady": dict(snapshot.get("containerReady") or {}),
                "images": images,
            }
        )
    total_resources = _rollup_component_resources(
        [dict(item.get("resources") or {}) for item in workload_summaries],
        node_capacity_millicores=node_capacity_millicores,
        node_capacity_bytes=node_capacity_bytes,
    )
    phase = str(status.get("phase") or "Unknown")
    last_sync_result = str(status.get("lastSyncResult") or "").strip().lower()
    enabled = bool(normalized["spec"].get("enabled", True))
    all_ready = bool(workload_summaries) and all(bool(item.get("ready")) for item in workload_summaries)
    parser_alias = next((item for item in workload_summaries if item["id"] == "parser"), {})
    runner_alias = next((item for item in workload_summaries if item["id"] == "steamcmd"), {})
    health = _derive_health(
        enabled=enabled,
        phase=phase,
        last_error=str(status.get("lastError") or "").strip(),
        parser_ready=all_ready,
        runner_ready=all_ready,
    )
    return {
        "name": name,
        "parserType": model.parser_type,
        "parserLabel": contract.label,
        "enabled": enabled,
        "health": health,
        "healthTone": _health_tone(health),
        "phase": phase,
        "syncState": _sync_state_label(status),
        "lastSyncResult": last_sync_result or "idle",
        "lastSyncLabel": _last_sync_label(status),
        "lastSyncStartedAt": str(status.get("lastSyncStartedAt") or ""),
        "lastSyncFinishedAt": str(status.get("lastSyncFinishedAt") or ""),
        "errorSummary": _error_summary(health, phase, status, parser_snapshot, runner_snapshot),
        "lastError": str(status.get("lastError") or ""),
        "source": model.source,
        "sourceSubtitle": parser_subtitle_label(model.parser_type, model.parser_config),
        "overviewPairs": parser_overview_pairs(model.parser_type, model.parser_config),
        "workloads": workload_summaries,
        "parser": {
            "podName": str(parser_alias.get("podName") or ""),
            "state": str(parser_alias.get("state") or "Missing"),
            "tone": str(parser_alias.get("tone") or "error"),
            "ready": bool(parser_alias.get("ready")),
            "image": str(parser_alias.get("image") or ""),
            "resources": dict(parser_alias.get("resources") or {}),
        },
        "runner": {
            "podName": str(runner_alias.get("podName") or ""),
            "state": str(runner_alias.get("state") or "Missing"),
            "tone": str(runner_alias.get("tone") or "error"),
            "ready": bool(runner_alias.get("ready")),
            "image": str(runner_alias.get("image") or ""),
            "tunImage": str(dict(runner_alias.get("images") or {}).get("tun-proxy") or ""),
            "tunReady": bool(dict(runner_alias.get("containerReady") or {}).get("tun-proxy", False)),
            "resources": dict(runner_alias.get("resources") or {}),
        },
        "resources": total_resources,
        "conditions": list(status.get("conditions") or []),
        "urls": _instance_urls(settings, name),
    }


def _load_instance_summaries(settings: UISettings) -> list[dict[str, Any]]:
    """Load summaries for all instances."""
    instances = list_instances(settings.namespace)
    instances_by_name = {
        instance_name(item): item for item in instances if instance_name(item)
    }
    snapshots = _component_snapshots_for_instances(settings.namespace, instances_by_name)
    resources = _component_resource_metrics_for_names(settings.namespace, snapshots)
    summaries = [
        _instance_summary(
            settings,
            item,
            snapshots.get(instance_name(item), {}),
            resources.get(instance_name(item), {}),
        )
        for item in instances
    ]
    summaries.sort(key=lambda item: item["name"].lower())
    return summaries


def _load_instance_summary(settings: UISettings, name: str) -> dict[str, Any]:
    """Load summary for a single instance."""
    instance = get_instance(settings.namespace, name)
    snapshots = _component_snapshots_for_instances(settings.namespace, {name: instance})
    resources = _component_resource_metrics_for_names(settings.namespace, snapshots)
    return _instance_summary(settings, instance, snapshots.get(name, {}), resources.get(name, {}))


def _dashboard_resource_totals(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate total resource usage across all instances."""
    from ui.ui_formatting import _int_value

    cpu_millicores = _sum_values(
        [
            _sum_values(
                [
                    _int_value(dict(dict(workload.get("resources") or {})).get("cpuMilliCores"))
                    for workload in (
                        list(item.get("workloads") or [])
                        or [item.get("parser") or {}, item.get("runner") or {}]
                    )
                ]
            )
            for item in items
        ]
    )
    memory_bytes = _sum_values(
        [
            _sum_values(
                [
                    _int_value(dict(dict(workload.get("resources") or {})).get("memoryBytes"))
                    for workload in (
                        list(item.get("workloads") or [])
                        or [item.get("parser") or {}, item.get("runner") or {}]
                    )
                ]
            )
            for item in items
        ]
    )
    disk_requested_bytes = _sum_values(
        [
            _sum_values(
                [
                    _int_value(
                        dict(dict(workload.get("resources") or {})).get("diskRequestedBytes")
                    )
                    for workload in (
                        list(item.get("workloads") or [])
                        or [item.get("parser") or {}, item.get("runner") or {}]
                    )
                ]
            )
            for item in items
        ]
    )
    cluster_capacity_millicores = _get_cluster_cpu_capacity()
    cluster_capacity_bytes = _get_cluster_memory_capacity()
    cluster_disk_stats = _get_cluster_disk_stats()
    logging.debug("_dashboard_resource_totals: cpu_millicores=%r, memory_bytes=%r, cluster_capacity_millicores=%r, cluster_capacity_bytes=%r",
                  cpu_millicores, memory_bytes, cluster_capacity_millicores, cluster_capacity_bytes)
    return _resource_usage(
        cpu_millicores=cpu_millicores,
        memory_bytes=memory_bytes,
        disk_capacity_bytes=_int_value(cluster_disk_stats.get("capacityBytes")),
        disk_used_bytes=_int_value(cluster_disk_stats.get("usedBytes")),
        disk_requested_bytes=disk_requested_bytes,
        node_capacity_millicores=cluster_capacity_millicores,
        node_capacity_bytes=cluster_capacity_bytes,
    )
