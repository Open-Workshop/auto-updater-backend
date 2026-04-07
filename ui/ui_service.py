from __future__ import annotations

import ast
import base64
import hmac
import json
import logging
import re
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any
from urllib.parse import quote, urlencode

import requests
from aiohttp import web
from kubernetes.client.rest import ApiException

from kube.kube_client import (
    delete_instance,
    delete_secret,
    get_instance,
    get_kube_clients,
    list_instances,
    patch_instance,
    read_pod_log,
    read_secret_value,
    replace_or_create_instance,
    upsert_secret,
)
from kube.mirror_instance import (
    API_VERSION,
    DEFAULT_SPEC,
    KIND,
    common_labels,
    deep_merge,
    instance_name,
    managed_credentials_secret_name,
    managed_parser_proxy_secret_name,
    managed_runner_proxy_secret_name,
    normalize_instance,
    parser_name,
    parser_service_name,
    parser_service_url,
    runner_name,
    runner_service_name,
)
from ui.ui_assets import STATIC_DIR
from ui.ui_common import UISettings, _bool_from_form, _format_time, _int_from_form, _truncate, _url, load_ui_settings
from ui.ui_forms import (
    _build_sync_spec,
    _editor_context,
    _settings_form,
    _validation_errors,
    _validate_proxy_pool,
    _validate_runner_proxy,
)
from ui.ui_pages import _dashboard, _dashboard_counts, _detail_page, _new_instance_page


_QUANTITY_RE = re.compile(r"^([+-]?(?:\d+(?:\.\d+)?|\.\d+))(Ei|Pi|Ti|Gi|Mi|Ki|E|P|T|G|M|k|m|u|n)?$")
_QUANTITY_FACTORS: dict[str, Decimal] = {
    "": Decimal("1"),
    "n": Decimal("1e-9"),
    "u": Decimal("1e-6"),
    "m": Decimal("1e-3"),
    "k": Decimal("1e3"),
    "M": Decimal("1e6"),
    "G": Decimal("1e9"),
    "T": Decimal("1e12"),
    "P": Decimal("1e15"),
    "E": Decimal("1e18"),
    "Ki": Decimal(2**10),
    "Mi": Decimal(2**20),
    "Gi": Decimal(2**30),
    "Ti": Decimal(2**40),
    "Pi": Decimal(2**50),
    "Ei": Decimal(2**60),
}


def _flash_redirect(settings: UISettings, path: str, message: str, kind: str = "info") -> web.HTTPFound:
    target = _url(settings, path)
    separator = "&" if "?" in path else "?"
    query = urlencode({"flash": message, "flashKind": kind})
    return web.HTTPFound(f"{target}{separator}{query}")


def _flash_from_request(request: web.Request) -> tuple[str, str]:
    message = str(request.query.get("flash", "")).strip()
    kind = str(request.query.get("flashKind", "info")).strip().lower() or "info"
    return message, kind


def _wants_json(request: web.Request) -> bool:
    accept = request.headers.get("Accept", "")
    return "application/json" in accept or request.path.startswith("/api/") or "/api/" in request.path


def _component_log_target(target: str) -> tuple[str, str]:
    normalized = str(target or "").strip().lower()
    if normalized == "parser":
        return "parser", "parser"
    if normalized == "runner":
        return "runner", "runner"
    if normalized == "tun":
        return "runner", "tun-proxy"
    raise web.HTTPNotFound(text="unknown log target")


def _component_label(target: str) -> str:
    normalized = str(target or "").strip().lower()
    if normalized == "parser":
        return "Parser"
    if normalized == "runner":
        return "Runner"
    if normalized == "tun":
        return "TUN"
    return normalized.title()


def _managed_secret_names(name: str) -> set[str]:
    return {
        managed_credentials_secret_name(name),
        managed_parser_proxy_secret_name(name),
        managed_runner_proxy_secret_name(name),
    }


def _json_ready(value: Any) -> Any:
    payload = value.to_dict() if hasattr(value, "to_dict") else value
    if isinstance(payload, dict):
        payload = dict(payload)
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            metadata = dict(metadata)
            metadata.pop("managed_fields", None)
            metadata.pop("managedFields", None)
            payload["metadata"] = metadata
    return payload


def _labels_selector(name: str, component: str) -> str:
    return ",".join(f"{key}={value}" for key, value in common_labels(name, component).items())


def _select_best_pod(pods: list[Any]) -> Any | None:
    if not pods:
        return None
    ranked = sorted(
        pods,
        key=lambda item: (
            item.metadata.deletion_timestamp is None,
            item.metadata.creation_timestamp.isoformat() if item.metadata.creation_timestamp else "",
        ),
        reverse=True,
    )
    return ranked[0]


def _pod_snapshot(pod: Any | None) -> dict[str, Any]:
    if pod is None:
        return {
            "podName": "",
            "phase": "Missing",
            "ready": False,
            "deleting": False,
            "images": {},
            "containerReady": {},
            "nodeName": "",
        }
    container_statuses = list(getattr(pod.status, "container_statuses", None) or [])
    container_ready = {status.name: bool(status.ready) for status in container_statuses}
    images = {container.name: container.image for container in list(getattr(pod.spec, "containers", None) or [])}
    conditions = {condition.type: condition.status for condition in list(getattr(pod.status, "conditions", None) or [])}
    # Try both node_name (snake_case) and nodeName (camelCase) for compatibility
    node_name = getattr(pod.spec, "node_name", None) or getattr(pod.spec, "nodeName", None) or ""
    logging.debug("_pod_snapshot: pod=%s, nodeName=%r", pod.metadata.name, node_name)
    return {
        "podName": str(pod.metadata.name or ""),
        "phase": str(getattr(pod.status, "phase", "") or "Unknown"),
        "ready": conditions.get("Ready") == "True",
        "deleting": getattr(pod.metadata, "deletion_timestamp", None) is not None,
        "images": images,
        "containerReady": container_ready,
        "nodeName": str(node_name),
    }


def _parse_quantity_decimal(value: Any) -> Decimal | None:
    text = str(value or "").strip()
    if not text:
        return None
    match = _QUANTITY_RE.fullmatch(text)
    if not match:
        return None
    amount_text, suffix = match.groups()
    factor = _QUANTITY_FACTORS.get(suffix or "")
    if factor is None:
        return None
    try:
        return Decimal(amount_text) * factor
    except InvalidOperation:
        return None


def _parse_cpu_millicores(value: Any) -> int | None:
    logging.debug("_parse_cpu_millicores: value=%r (type: %s)", value, type(value))
    parsed = _parse_quantity_decimal(value)
    if parsed is None:
        logging.debug("_parse_cpu_millicores: parsed is None")
        return None
    result = int((parsed * Decimal("1000")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    logging.debug("_parse_cpu_millicores: result=%d", result)
    return result


def _parse_bytes(value: Any) -> int | None:
    parsed = _parse_quantity_decimal(value)
    if parsed is None:
        return None
    return int(parsed.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _int_value(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _sum_values(values: list[int | None]) -> int | None:
    defined = [value for value in values if value is not None]
    if not defined:
        return None
    return sum(defined)


def _format_decimal(value: float, digits: int) -> str:
    return f"{value:.{digits}f}".rstrip("0").rstrip(".")


def _format_cpu_millicores(value: int | None) -> str:
    if value is None:
        return "n/a"
    return f"{value}m"


def _format_cpu_percent(cpu_millicores: int | None, node_capacity_millicores: int | None) -> str:
    logging.debug("_format_cpu_percent: cpu_millicores=%r, node_capacity_millicores=%r", cpu_millicores, node_capacity_millicores)
    if cpu_millicores is None:
        return "n/a"
    if node_capacity_millicores is None or node_capacity_millicores <= 0:
        logging.debug("_format_cpu_percent: returning millicores because node_capacity is None or <= 0")
        return f"{cpu_millicores}m"
    percent = (cpu_millicores / node_capacity_millicores) * 100
    logging.debug("_format_cpu_percent: returning percent=%s", f"{_format_decimal(percent, 1)}%")
    return f"{_format_decimal(percent, 1)}%"


def _format_bytes(value: int | None) -> str:
    if value is None:
        return "n/a"
    if value < 1024:
        return f"{value}B"
    units = [
        ("EB", 2**60),
        ("PB", 2**50),
        ("TB", 2**40),
        ("GB", 2**30),
        ("MB", 2**20),
        ("KB", 2**10),
    ]
    for suffix, factor in units:
        if value >= factor:
            amount = value / factor
            digits = 0 if amount >= 100 else 1
            return f"{_format_decimal(amount, digits)}{suffix}"
    return f"{value}B"


def _format_memory_percent(memory_bytes: int | None, node_capacity_bytes: int | None) -> str:
    logging.debug("_format_memory_percent: memory_bytes=%r, node_capacity_bytes=%r", memory_bytes, node_capacity_bytes)
    if memory_bytes is None:
        return "n/a"
    if node_capacity_bytes is None or node_capacity_bytes <= 0:
        logging.debug("_format_memory_percent: returning bytes because node_capacity is None or <= 0")
        return _format_bytes(memory_bytes)
    percent = (memory_bytes / node_capacity_bytes) * 100
    logging.debug("_format_memory_percent: returning percent=%s", f"{_format_decimal(percent, 1)}%")
    return f"{_format_bytes(memory_bytes)} ({_format_decimal(percent, 1)}%)"


def _format_disk_usage(used_bytes: int | None, requested_bytes: int | None) -> str:
    if used_bytes is not None and requested_bytes is not None:
        return f"{_format_bytes(used_bytes)} / {_format_bytes(requested_bytes)} req"
    if used_bytes is not None:
        return f"{_format_bytes(used_bytes)} used"
    if requested_bytes is not None:
        return f"{_format_bytes(requested_bytes)} req"
    return "n/a"


def _resource_usage(
    *,
    cpu_millicores: int | None,
    memory_bytes: int | None,
    disk_used_bytes: int | None,
    disk_requested_bytes: int | None,
    node_capacity_millicores: int | None = None,
    node_capacity_bytes: int | None = None,
) -> dict[str, Any]:
    return {
        "cpuMilliCores": cpu_millicores,
        "memoryBytes": memory_bytes,
        "diskUsedBytes": disk_used_bytes,
        "diskRequestedBytes": disk_requested_bytes,
        "cpuLabel": _format_cpu_percent(cpu_millicores, node_capacity_millicores),
        "memoryLabel": _format_memory_percent(memory_bytes, node_capacity_bytes),
        "diskLabel": _format_disk_usage(disk_used_bytes, disk_requested_bytes),
    }


def _storage_request_bytes(instance: dict[str, Any], component: str) -> int | None:
    spec = dict(instance.get("spec") or {})
    storage = dict(spec.get("storage") or {})
    component_storage = dict(storage.get(component) or {})
    return _parse_bytes(component_storage.get("size"))


def _pod_usage_metrics(namespace: str, pod_names: set[str]) -> dict[str, dict[str, int | None]]:
    logging.debug("_pod_usage_metrics: namespace=%s, pod_names=%r", namespace, pod_names)
    if not pod_names:
        return {}
    try:
        response = get_kube_clients().custom.list_namespaced_custom_object(
            "metrics.k8s.io",
            "v1beta1",
            namespace,
            "pods",
        )
        logging.debug("_pod_usage_metrics: response items count=%d", len(response.get("items", [])))
    except ApiException as exc:
        logging.warning("_pod_usage_metrics: ApiException status=%d, body=%r", exc.status, exc.body)
        if exc.status in {403, 404, 503}:
            return {}
        raise
    metrics: dict[str, dict[str, int | None]] = {}
    for item in list(response.get("items") or []):
        metadata = dict(item.get("metadata") or {})
        pod_name = str(metadata.get("name") or "")
        if pod_name not in pod_names:
            continue
        total_cpu = 0
        total_memory = 0
        cpu_seen = False
        memory_seen = False
        for container in list(item.get("containers") or []):
            usage = dict(container.get("usage") or {})
            cpu_value = _parse_cpu_millicores(usage.get("cpu"))
            memory_value = _parse_bytes(usage.get("memory"))
            if cpu_value is not None:
                total_cpu += cpu_value
                cpu_seen = True
            if memory_value is not None:
                total_memory += memory_value
                memory_seen = True
        metrics[pod_name] = {
            "cpuMilliCores": total_cpu if cpu_seen else None,
            "memoryBytes": total_memory if memory_seen else None,
        }
    return metrics


def _read_node_stats_summary(node_name: str) -> dict[str, Any]:
    proxy = getattr(get_kube_clients().core, "connect_get_node_proxy_with_path", None)
    if proxy is None:
        return {}
    raw = proxy(node_name, "stats/summary")
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            parsed = ast.literal_eval(raw)
            if isinstance(parsed, dict):
                return parsed
            return {}
    return dict(raw or {})


def _get_node_cpu_capacity(node_name: str) -> int | None:
    try:
        node = get_kube_clients().core.read_node(node_name)
        if node.status is None or node.status.capacity is None:
            logging.warning("Node %s has no status or capacity", node_name)
            return None
        cpu_raw = node.status.capacity.get("cpu")
        logging.debug("Node %s CPU capacity raw: %r (type: %s)", node_name, cpu_raw, type(cpu_raw))
        cpu_value = _parse_cpu_millicores(cpu_raw)
        if cpu_value is None:
            logging.warning("Could not parse CPU capacity for node %s, raw value: %r", node_name, cpu_raw)
        else:
            logging.debug("Node %s CPU capacity parsed: %d millicores", node_name, cpu_value)
        return cpu_value
    except Exception as exc:
        logging.warning("Failed to get node CPU capacity for %s: %s", node_name, exc)
        return None


def _get_node_memory_capacity(node_name: str) -> int | None:
    try:
        node = get_kube_clients().core.read_node(node_name)
        if node.status is None or node.status.capacity is None:
            logging.warning("Node %s has no status or capacity", node_name)
            return None
        memory_raw = node.status.capacity.get("memory")
        logging.debug("Node %s memory capacity raw: %r (type: %s)", node_name, memory_raw, type(memory_raw))
        memory_value = _parse_bytes(memory_raw)
        if memory_value is None:
            logging.warning("Could not parse memory capacity for node %s, raw value: %r", node_name, memory_raw)
        else:
            logging.debug("Node %s memory capacity parsed: %d bytes", node_name, memory_value)
        return memory_value
    except Exception as exc:
        logging.warning("Failed to get node memory capacity for %s: %s", node_name, exc)
        return None


def _pod_disk_usage(
    namespace: str,
    component_snapshots: dict[str, dict[str, Any]],
) -> dict[str, int | None]:
    pods_by_node: dict[str, set[str]] = {}
    for components in component_snapshots.values():
        for component in ("parser", "runner"):
            snapshot = dict(components.get(component) or {})
            pod_name = str(snapshot.get("podName") or "")
            node_name = str(snapshot.get("nodeName") or "")
            if pod_name and node_name:
                pods_by_node.setdefault(node_name, set()).add(pod_name)
    disk_usage: dict[str, int | None] = {}
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
            found_usage = False
            for volume in list(pod.get("volume") or []):
                pvc_ref = dict(volume.get("pvcRef") or {})
                if not pvc_ref:
                    continue
                used_bytes = _int_value(volume.get("usedBytes"))
                if used_bytes is None:
                    continue
                total_used += used_bytes
                found_usage = True
            if found_usage:
                disk_usage[pod_name] = total_used
    return disk_usage


def _component_resource_metrics_for_names(
    namespace: str,
    component_snapshots: dict[str, dict[str, Any]],
) -> dict[str, dict[str, dict[str, int | None]]]:
    pod_names = {
        str(snapshot.get("podName") or "")
        for components in component_snapshots.values()
        for snapshot in components.values()
        if str(snapshot.get("podName") or "")
    }
    usage_metrics = _pod_usage_metrics(namespace, pod_names)
    disk_usage = _pod_disk_usage(namespace, component_snapshots)
    resources: dict[str, dict[str, dict[str, int | None]]] = {}
    for name, components in component_snapshots.items():
        resources[name] = {}
        for component in ("parser", "runner"):
            snapshot = dict(components.get(component) or {})
            pod_name = str(snapshot.get("podName") or "")
            usage = dict(usage_metrics.get(pod_name) or {})
            resources[name][component] = {
                "cpuMilliCores": _int_value(usage.get("cpuMilliCores")),
                "memoryBytes": _int_value(usage.get("memoryBytes")),
                "diskUsedBytes": _int_value(disk_usage.get(pod_name)),
            }
    return resources


def _component_state(snapshot: dict[str, Any], fallback_pod_name: str = "") -> dict[str, str]:
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


def _component_snapshots_for_names(namespace: str, names: set[str]) -> dict[str, dict[str, Any]]:
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


def _derive_health(
    *,
    enabled: bool,
    phase: str,
    last_error: str,
    parser_ready: bool,
    runner_ready: bool,
) -> str:
    if not enabled:
        return "Disabled"
    if phase == "Error" or last_error:
        return "Error"
    if phase == "Ready" and parser_ready and runner_ready:
        return "Healthy"
    return "Degraded"


def _health_tone(health: str) -> str:
    return {
        "Healthy": "healthy",
        "Syncing": "info",
        "Degraded": "warning",
        "Error": "error",
        "Disabled": "muted",
    }.get(health, "muted")


def _sync_state_label(status: dict[str, Any]) -> str:
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
    instance = get_instance(settings.namespace, name)
    snapshots = _component_snapshots_for_names(settings.namespace, {name})
    resources = _component_resource_metrics_for_names(settings.namespace, snapshots)
    return _instance_summary(settings, instance, snapshots.get(name, {}), resources.get(name, {}))


def _get_cluster_cpu_capacity() -> int | None:
    try:
        nodes = get_kube_clients().core.list_node().items or []
        total_capacity = 0
        for node in nodes:
            capacity = dict(node.status or {}).get("capacity") or {}
            cpu_value = _parse_cpu_millicores(capacity.get("cpu"))
            if cpu_value is not None:
                total_capacity += cpu_value
        logging.debug("_get_cluster_cpu_capacity: total_capacity=%d", total_capacity)
        return total_capacity if total_capacity > 0 else None
    except Exception as e:
        logging.error("_get_cluster_cpu_capacity: exception=%s", e)
        return None


def _get_cluster_memory_capacity() -> int | None:
    try:
        nodes = get_kube_clients().core.list_node().items or []
        total_capacity = 0
        for node in nodes:
            capacity = dict(node.status or {}).get("capacity") or {}
            memory_value = _parse_bytes(capacity.get("memory"))
            if memory_value is not None:
                total_capacity += memory_value
        logging.debug("_get_cluster_memory_capacity: total_capacity=%d", total_capacity)
        return total_capacity if total_capacity > 0 else None
    except Exception as e:
        logging.error("_get_cluster_memory_capacity: exception=%s", e)
        return None


def _dashboard_resource_totals(items: list[dict[str, Any]]) -> dict[str, Any]:
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
    return _resource_usage(
        cpu_millicores=cpu_millicores,
        memory_bytes=memory_bytes,
        disk_used_bytes=disk_used_bytes,
        disk_requested_bytes=disk_requested_bytes,
        node_capacity_millicores=cluster_capacity_millicores,
        node_capacity_bytes=cluster_capacity_bytes,
    )


def _latest_pod_name(namespace: str, name: str, component: str) -> str:
    selector = _labels_selector(name, component)
    pods = get_kube_clients().core.list_namespaced_pod(namespace, label_selector=selector).items
    best = _select_best_pod(list(pods))
    return str(best.metadata.name or "") if best is not None else ""


def _tail_lines_from_request(request: web.Request, default: int = 400) -> int:
    try:
        value = int(str(request.query.get("tail", default)).strip())
    except (TypeError, ValueError):
        return default
    return max(50, min(value, 2000))


def _pod_log_snapshot(settings: UISettings, name: str, target: str, tail_lines: int) -> dict[str, Any]:
    component, container = _component_log_target(target)
    pod_name = _latest_pod_name(settings.namespace, name, component)
    if not pod_name:
        raise web.HTTPNotFound(text=f"Pod for {name}/{target} is not available yet")
    return {
        "instance": name,
        "target": target,
        "targetLabel": _component_label(target),
        "component": component,
        "container": container,
        "podName": pod_name,
        "tailLines": tail_lines,
        "logText": read_pod_log(
            settings.namespace,
            pod_name,
            container=container,
            tail_lines=tail_lines,
        ),
    }


def _load_resource_entries(settings: UISettings, name: str) -> list[dict[str, Any]]:
    kube = get_kube_clients()
    instance = get_instance(settings.namespace, name)
    status = dict(instance.get("status") or {})
    parser_pod_name = str(status.get("parserPod") or "") or _latest_pod_name(settings.namespace, name, "parser")
    runner_pod_name = str(status.get("runnerPod") or "") or _latest_pod_name(settings.namespace, name, "runner")
    readers: list[tuple[str, str, Any]] = [
        ("MirrorInstance", name, lambda: instance),
        ("StatefulSet", parser_name(name), lambda: kube.apps.read_namespaced_stateful_set(parser_name(name), settings.namespace)),
        ("StatefulSet", runner_name(name), lambda: kube.apps.read_namespaced_stateful_set(runner_name(name), settings.namespace)),
        ("Service", parser_service_name(name), lambda: kube.core.read_namespaced_service(parser_service_name(name), settings.namespace)),
        ("Service", runner_service_name(name), lambda: kube.core.read_namespaced_service(runner_service_name(name), settings.namespace)),
    ]
    if parser_pod_name:
        readers.append(("Pod", parser_pod_name, lambda: kube.core.read_namespaced_pod(parser_pod_name, settings.namespace)))
    if runner_pod_name:
        readers.append(("Pod", runner_pod_name, lambda: kube.core.read_namespaced_pod(runner_pod_name, settings.namespace)))
    entries = []
    for kind, resource_name, reader in readers:
        try:
            payload = _json_ready(reader())
            error = ""
        except Exception as exc:
            payload = {"error": str(exc)}
            error = str(exc)
        entries.append(
            {
                "kind": kind,
                "name": resource_name,
                "payload": payload,
                "error": error,
            }
        )
    return entries


def _json_response(message: str, *, kind: str = "success", status: int = 200, **extra: Any) -> web.Response:
    payload = {"message": message, "kind": kind}
    payload.update(extra)
    return web.json_response(payload, status=status)


def _action_response(
    request: web.Request,
    settings: UISettings,
    *,
    message: str,
    redirect_path: str,
    kind: str = "success",
    status: int = 200,
    extra: dict[str, Any] | None = None,
) -> web.StreamResponse:
    extra = extra or {}
    if _wants_json(request):
        return _json_response(
            message,
            kind=kind,
            status=status,
            redirectUrl=_url(settings, redirect_path),
            **extra,
        )
    raise _flash_redirect(settings, redirect_path, message, kind)


async def healthz(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def dashboard(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    flash, flash_kind = _flash_from_request(request)
    items = _load_instance_summaries(settings)
    resource_totals = _dashboard_resource_totals(items)
    return web.Response(
        text=_dashboard(settings, items, flash, flash_kind, resource_totals),
        content_type="text/html",
    )


async def instances_api(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    items = _load_instance_summaries(settings)
    return web.json_response(
        {
            "items": items,
            "counts": _dashboard_counts(items),
            "resources": _dashboard_resource_totals(items),
        }
    )


async def instance_summary_api(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    try:
        payload = _load_instance_summary(settings, name)
    except web.HTTPException:
        raise
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=502)
    return web.json_response(payload)


async def new_instance_page(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    flash, flash_kind = _flash_from_request(request)
    context = _editor_context(settings, None)
    return web.Response(text=_new_instance_page(settings, context, flash, flash_kind), content_type="text/html")


async def edit_instance_page(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    raise web.HTTPFound(_url(settings, f"/instances/{quote(name)}?tab=settings"))


async def instance_detail_page(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    tab = str(request.query.get("tab", "overview")).strip().lower() or "overview"
    target = str(request.query.get("target", "parser")).strip().lower() or "parser"
    tail_lines = _tail_lines_from_request(request)
    flash, flash_kind = _flash_from_request(request)
    summary = _load_instance_summary(settings, name)
    resources = _load_resource_entries(settings, name) if tab == "resources" else []
    instance = get_instance(settings.namespace, name) if tab == "settings" else None
    settings_form = ""
    if tab == "settings":
        context = _editor_context(settings, instance)
        settings_form = _settings_form(
            settings,
            context,
            return_path=f"/instances/{quote(name)}?tab=overview",
            embedded=True,
        )
    return web.Response(
        text=_detail_page(
            settings,
            summary,
            active_tab=tab,
            resources=resources,
            settings_form=settings_form,
            flash=flash,
            flash_kind=flash_kind,
            target=target,
            tail_lines=tail_lines,
        ),
        content_type="text/html",
    )


async def resource_page(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    query = dict(request.query)
    query["tab"] = "resources"
    raise web.HTTPFound(_url(settings, f"/instances/{quote(name)}?{urlencode(query)}"))


async def pod_logs_api(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    target = request.match_info["target"]
    tail_lines = _tail_lines_from_request(request)
    try:
        payload = _pod_log_snapshot(settings, name, target, tail_lines)
    except web.HTTPException as exc:
        return web.json_response(
            {
                "instance": name,
                "target": target,
                "tailLines": tail_lines,
                "error": exc.text or exc.reason,
            },
            status=exc.status,
        )
    except Exception as exc:
        return web.json_response(
            {
                "instance": name,
                "target": target,
                "tailLines": tail_lines,
                "error": str(exc),
            },
            status=502,
        )
    return web.json_response(payload)


async def pod_logs_page(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    target = request.match_info["target"]
    query = dict(request.query)
    query["tab"] = "logs"
    query["target"] = target
    raise web.HTTPFound(_url(settings, f"/instances/{quote(name)}?{urlencode(query)}"))


async def save_instance(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    form = await request.post()
    submitted = {key: value for key, value in form.items()}
    original_name = str(form.get("original_name", "")).strip()
    name = str(form.get("name", "")).strip()
    return_path = str(form.get("return_path", "")).strip() or (
        f"/instances/{quote(original_name)}?tab=settings" if original_name else "/"
    )
    instance = None
    existing_password = ""
    if original_name:
        try:
            instance = get_instance(settings.namespace, original_name)
            credentials_ref = normalize_instance(instance)["spec"]["credentials"]["secretRef"]
            existing_password = read_secret_value(settings.namespace, credentials_ref, "password")
        except Exception:
            instance = None
    runner_proxy_type = str(form.get("runner_proxy_type", "socks5")).strip() or "socks5"
    runner_proxy_url = str(form.get("runner_proxy_url", "")).strip()
    parser_proxy_pool = str(form.get("parser_proxy_pool", ""))
    password = str(form.get("ow_password", "")).strip()
    login = str(form.get("ow_login", "")).strip()
    parser_storage_size = str(form.get("parser_storage_size", "")).strip()
    runner_storage_size = str(form.get("runner_storage_size", "")).strip()
    sync_json_patch = str(form.get("sync_json_patch", form.get("sync_json", ""))).strip()
    steam_app_id = _int_from_form(form.get("steam_app_id"), 0)
    errors = _validation_errors(
        name=name,
        steam_app_id=steam_app_id,
        login=login,
        password=password,
        existing_password=existing_password,
        runner_proxy_url=runner_proxy_url,
        parser_proxy_pool=parser_proxy_pool,
        parser_storage_size=parser_storage_size,
        runner_storage_size=runner_storage_size,
        sync_json_patch=sync_json_patch,
    )
    if "runner_proxy_url" not in errors:
        try:
            _validate_runner_proxy(runner_proxy_url, runner_proxy_type)
        except Exception as exc:
            errors["runner_proxy_url"] = str(exc)
    if errors:
        context = _editor_context(
            settings,
            instance,
            form_data=submitted,
            errors=errors,
            sync_patch_value=sync_json_patch,
        )
        if _wants_json(request):
            return _json_response("Please correct the highlighted fields", kind="error", status=400, errors=errors)
        if instance is None:
            body = _new_instance_page(settings, context, "", "info")
        else:
            summary = _load_instance_summary(settings, original_name or name)
            body = _detail_page(
                settings,
                summary,
                active_tab="settings",
                settings_form=_settings_form(settings, context, return_path=return_path, embedded=True),
                flash="",
                flash_kind="info",
            )
        return web.Response(text=body, content_type="text/html", status=400)

    normalized_instance = normalize_instance(instance) if instance is not None else {"spec": deep_merge(DEFAULT_SPEC, {})}
    sync_spec = _build_sync_spec(dict(normalized_instance["spec"]["sync"]), submitted)
    parser_proxy_pool_value = _validate_proxy_pool(parser_proxy_pool)
    runner_proxy_url_value = _validate_runner_proxy(runner_proxy_url, runner_proxy_type)
    credentials_secret = managed_credentials_secret_name(name)
    parser_proxy_secret = managed_parser_proxy_secret_name(name)
    runner_proxy_secret = managed_runner_proxy_secret_name(name)
    final_password = password or existing_password

    upsert_secret(
        settings.namespace,
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": credentials_secret,
                "namespace": settings.namespace,
                "labels": {**common_labels(name, "credentials"), "auto-updater.miskler.ru/managed-secret": "true"},
            },
            "type": "Opaque",
            "stringData": {
                "login": login,
                "password": final_password,
            },
        },
    )
    if parser_proxy_pool_value:
        upsert_secret(
            settings.namespace,
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": parser_proxy_secret,
                    "namespace": settings.namespace,
                    "labels": {**common_labels(name, "parser-proxies"), "auto-updater.miskler.ru/managed-secret": "true"},
                },
                "type": "Opaque",
                "stringData": {
                    "proxyPool": parser_proxy_pool_value,
                },
            },
        )
        parser_proxy_ref = parser_proxy_secret
    else:
        parser_proxy_ref = ""
        delete_secret(settings.namespace, parser_proxy_secret)
    upsert_secret(
        settings.namespace,
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": runner_proxy_secret,
                "namespace": settings.namespace,
                "labels": {**common_labels(name, "runner-proxy"), "auto-updater.miskler.ru/managed-secret": "true"},
            },
            "type": "Opaque",
            "stringData": {
                "proxyUrl": runner_proxy_url_value,
            },
        },
    )
    body = {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {
            "name": name,
            "namespace": settings.namespace,
            "labels": common_labels(name, "instance"),
        },
        "spec": {
            "enabled": _bool_from_form(form.get("enabled")),
            "source": {
                "steamAppId": steam_app_id,
                "owGameId": _int_from_form(form.get("ow_game_id"), 0),
                "language": str(form.get("language", "")).strip() or "english",
            },
            "sync": sync_spec,
            "credentials": {"secretRef": credentials_secret},
            "parser": {"proxyPoolSecretRef": parser_proxy_ref},
            "steamcmd": {
                "proxy": {
                    "type": runner_proxy_type,
                    "secretRef": runner_proxy_secret,
                }
            },
            "storage": {
                "parser": {
                    "size": parser_storage_size or "20Gi",
                    "storageClassName": "local-path",
                },
                "runner": {
                    "size": runner_storage_size or "10Gi",
                    "storageClassName": "local-path",
                },
            },
        },
    }
    replace_or_create_instance(settings.namespace, name, body)
    if original_name and original_name != name:
        delete_instance(settings.namespace, original_name)
        for secret_name in _managed_secret_names(original_name):
            delete_secret(settings.namespace, secret_name)
    return _action_response(
        request,
        settings,
        message=f"Instance {name} saved",
        redirect_path=f"/instances/{quote(name)}?tab=overview",
        kind="success",
    )


async def sync_now(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    url = parser_service_url(name, settings.namespace) + "/api/v1/sync"
    form = await request.post() if request.can_read_body else {}
    return_path = str(form.get("return_path", "")).strip() if form else ""
    redirect_path = return_path or f"/instances/{quote(name)}?tab=overview"
    try:
        response = requests.post(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        if _wants_json(request):
            return _json_response(f"Sync now failed: {exc}", kind="error", status=502)
        raise _flash_redirect(settings, redirect_path, f"Sync now failed: {exc}", "error")
    return _action_response(
        request,
        settings,
        message=f"Sync requested for {name}",
        redirect_path=redirect_path,
        kind="success",
    )


async def toggle_instance(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    form = await request.post()
    return_path = str(form.get("return_path", "")).strip() or f"/instances/{quote(name)}?tab=overview"
    instance = normalize_instance(get_instance(settings.namespace, name))
    enabled = not bool(instance["spec"].get("enabled", True))
    patch_instance(settings.namespace, name, {"spec": {"enabled": enabled}})
    return _action_response(
        request,
        settings,
        message=f"{name} is now {'enabled' if enabled else 'paused'}",
        redirect_path=return_path,
        kind="success",
    )


async def delete_instance_route(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    await request.post()
    delete_instance(settings.namespace, name)
    for secret_name in _managed_secret_names(name):
        delete_secret(settings.namespace, secret_name)
    return _action_response(
        request,
        settings,
        message=f"{name} deleted",
        redirect_path="/",
        kind="warning",
    )


@web.middleware
async def _basic_auth(request: web.Request, handler: Any) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    if request.path in {"/healthz", _url(settings, "/healthz")}:
        return await handler(request)
    if not settings.username:
        return await handler(request)
    header = request.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
        except Exception:
            decoded = ""
        username, _, password = decoded.partition(":")
        if hmac.compare_digest(username, settings.username) and hmac.compare_digest(password, settings.password):
            return await handler(request)
    return web.Response(
        status=401,
        text="authentication required",
        headers={"WWW-Authenticate": 'Basic realm="auto-updater"'},
    )


def _create_app(settings: UISettings) -> web.Application:
    app = web.Application(middlewares=[_basic_auth])
    app["settings"] = settings

    def register(method: str, path: str, handler: Any) -> None:
        app.router.add_route(method, path, handler)
        if settings.base_path:
            if path == "/":
                app.router.add_route(method, settings.base_path, handler)
                app.router.add_route(method, settings.base_path + "/", handler)
            else:
                app.router.add_route(method, f"{settings.base_path}{path}", handler)

    register("GET", "/healthz", healthz)
    register("GET", "/", dashboard)
    register("GET", "/api/instances", instances_api)
    register("GET", "/api/instances/{name}", instance_summary_api)
    register("GET", "/instances/new", new_instance_page)
    register("GET", "/instances/{name}", instance_detail_page)
    register("GET", "/instances/{name}/edit", edit_instance_page)
    register("GET", "/instances/{name}/resources", resource_page)
    register("GET", "/api/instances/{name}/logs/{target}", pod_logs_api)
    register("GET", "/instances/{name}/logs/{target}", pod_logs_page)
    register("POST", "/instances/save", save_instance)
    register("POST", "/instances/{name}/sync", sync_now)
    register("POST", "/instances/{name}/toggle", toggle_instance)
    register("POST", "/instances/{name}/delete", delete_instance_route)
    app.router.add_static("/assets", str(STATIC_DIR), show_index=False)
    if settings.base_path:
        app.router.add_static(f"{settings.base_path}/assets", str(STATIC_DIR), show_index=False)
    return app


def run_ui() -> int:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    settings = load_ui_settings()
    get_kube_clients()
    app = _create_app(settings)
    web.run_app(app, host=settings.host, port=settings.port)
    return 0
