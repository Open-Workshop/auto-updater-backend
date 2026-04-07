"""Instance-related utilities for UI service."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

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
from ui.ui_kube_utils import _get_cluster_cpu_capacity, _get_cluster_memory_capacity, _get_node_cpu_capacity, _get_node_memory_capacity
from ui.ui_resources import _component_snapshots_for_names, _component_resource_metrics_for_names, _component_state, _resource_usage, _storage_request_bytes


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


def _instance_summary(
    settings: UISettings,
    instance: dict[str, Any],
    component_snapshots: dict[str, Any] | None = None,
    component_resources: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a summary of an instance."""
    normalized = normalize_instance(instance)
    status = dict(normalized.get("status") or {})
    name = instance_name(normalized)
    component_snapshots = component_snapshots or {}
    component_resources = component_resources or {}
    parser_snapshot = dict(component_snapshots.get("parser") or {})
    runner_snapshot = dict(component_snapshots.get("runner") or {})
    parser_resource_snapshot = dict(component_resources.get("parser") or {})
    runner_resource_snapshot = dict(component_resources.get("runner") or {})
    parser_pod_name = str(status.get("parserPod") or "") or str(parser_snapshot.get("podName") or "")
    runner_pod_name = str(status.get("runnerPod") or "") or str(runner_snapshot.get("podName") or "")
    parser_state = _component_state(parser_snapshot, parser_pod_name)
    runner_state = _component_state(runner_snapshot, runner_pod_name)
    
    # Get node CPU and memory capacity for percentage calculation
    node_name = str(parser_snapshot.get("nodeName") or runner_snapshot.get("nodeName") or "")
    logging.debug("Instance %s: node_name=%r, parser_nodeName=%r, runner_nodeName=%r",
                  name, node_name, parser_snapshot.get("nodeName"), runner_snapshot.get("nodeName"))
    node_capacity_millicores = _get_node_cpu_capacity(node_name) if node_name else None
    node_capacity_bytes = _get_node_memory_capacity(node_name) if node_name else None
    logging.debug("Instance %s: node_capacity_millicores=%r, node_capacity_bytes=%r", name, node_capacity_millicores, node_capacity_bytes)
    
    parser_resources = _resource_usage(
        cpu_millicores=_int_value(parser_resource_snapshot.get("cpuMilliCores")),
        memory_bytes=_int_value(parser_resource_snapshot.get("memoryBytes")),
        disk_used_bytes=_int_value(parser_resource_snapshot.get("diskUsedBytes")),
        disk_requested_bytes=_storage_request_bytes(normalized, "parser"),
        node_capacity_millicores=node_capacity_millicores,
        node_capacity_bytes=node_capacity_bytes,
    )
    runner_resources = _resource_usage(
        cpu_millicores=_int_value(runner_resource_snapshot.get("cpuMilliCores")),
        memory_bytes=_int_value(runner_resource_snapshot.get("memoryBytes")),
        disk_used_bytes=_int_value(runner_resource_snapshot.get("diskUsedBytes")),
        disk_requested_bytes=_storage_request_bytes(normalized, "runner"),
        node_capacity_millicores=node_capacity_millicores,
        node_capacity_bytes=node_capacity_bytes,
    )
    total_resources = _resource_usage(
        cpu_millicores=_sum_values(
            [parser_resources["cpuMilliCores"], runner_resources["cpuMilliCores"]]
        ),
        memory_bytes=_sum_values(
            [parser_resources["memoryBytes"], runner_resources["memoryBytes"]]
        ),
        disk_used_bytes=_sum_values(
            [parser_resources["diskUsedBytes"], runner_resources["diskUsedBytes"]]
        ),
        disk_requested_bytes=_sum_values(
            [parser_resources["diskRequestedBytes"], runner_resources["diskRequestedBytes"]]
        ),
        node_capacity_millicores=node_capacity_millicores,
        node_capacity_bytes=node_capacity_bytes,
    )
    phase = str(status.get("phase") or "Unknown")
    last_sync_result = str(status.get("lastSyncResult") or "").strip().lower()
    enabled = bool(normalized["spec"].get("enabled", True))
    health = _derive_health(
        enabled=enabled,
        phase=phase,
        last_error=str(status.get("lastError") or "").strip(),
        parser_ready=bool(parser_snapshot.get("ready")),
        runner_ready=bool(runner_snapshot.get("ready")),
    )
    return {
        "name": name,
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
        "source": {
            "steamAppId": normalized["spec"]["source"].get("steamAppId", 0),
            "owGameId": normalized["spec"]["source"].get("owGameId", 0),
            "language": normalized["spec"]["source"].get("language", "english"),
        },
        "parser": {
            "podName": parser_pod_name,
            "state": parser_state["label"],
            "tone": parser_state["tone"],
            "ready": bool(parser_snapshot.get("ready")),
            "image": str(parser_snapshot.get("images", {}).get("parser") or ""),
            "resources": parser_resources,
        },
        "runner": {
            "podName": runner_pod_name,
            "state": runner_state["label"],
            "tone": runner_state["tone"],
            "ready": bool(runner_snapshot.get("ready")),
            "image": str(runner_snapshot.get("images", {}).get("runner") or ""),
            "tunImage": str(runner_snapshot.get("images", {}).get("tun-proxy") or ""),
            "tunReady": bool(runner_snapshot.get("containerReady", {}).get("tun-proxy", False)),
            "resources": runner_resources,
        },
        "resources": total_resources,
        "conditions": list(status.get("conditions") or []),
        "urls": _instance_urls(settings, name),
    }


def _load_instance_summaries(settings: UISettings) -> list[dict[str, Any]]:
    """Load summaries for all instances."""
    instances = list_instances(settings.namespace)
    names = {instance_name(item) for item in instances if instance_name(item)}
    snapshots = _component_snapshots_for_names(settings.namespace, names)
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
    snapshots = _component_snapshots_for_names(settings.namespace, {name})
    resources = _component_resource_metrics_for_names(settings.namespace, snapshots)
    return _instance_summary(settings, instance, snapshots.get(name, {}), resources.get(name, {}))


def _dashboard_resource_totals(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate total resource usage across all instances."""
    from ui.ui_formatting import _int_value
    
    cpu_millicores = _sum_values(
        [_int_value(dict(item.get("resources") or {}).get("cpuMilliCores")) for item in items]
    )
    memory_bytes = _sum_values(
        [_int_value(dict(item.get("resources") or {}).get("memoryBytes")) for item in items]
    )
    disk_used_bytes = _sum_values(
        [_int_value(dict(item.get("resources") or {}).get("diskUsedBytes")) for item in items]
    )
    disk_requested_bytes = _sum_values(
        [_int_value(dict(item.get("resources") or {}).get("diskRequestedBytes")) for item in items]
    )
    cluster_capacity_millicores = _get_cluster_cpu_capacity()
    cluster_capacity_bytes = _get_cluster_memory_capacity()
    logging.debug("_dashboard_resource_totals: cpu_millicores=%r, memory_bytes=%r, cluster_capacity_millicores=%r, cluster_capacity_bytes=%r",
                  cpu_millicores, memory_bytes, cluster_capacity_millicores, cluster_capacity_bytes)
    return _resource_usage(
        cpu_millicores=cpu_millicores,
        memory_bytes=memory_bytes,
        disk_used_bytes=disk_used_bytes,
        disk_requested_bytes=disk_requested_bytes,
        node_capacity_millicores=cluster_capacity_millicores,
        node_capacity_bytes=cluster_capacity_bytes,
    )
