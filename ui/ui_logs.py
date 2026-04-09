"""Log and resource helpers for UI route handlers."""
from __future__ import annotations

from typing import Any

from aiohttp import web

from core.instance_schema import MirrorInstanceSpecModel, get_parser_contract
from core.log_tags import (
    filter_log_text_by_tag,
    format_log_tag_options,
    normalize_log_tag,
)
from kube.kube_client import get_instance, read_pod_log
from kube.mirror_instance import (
    common_labels,
    parser_name,
    parser_service_name,
    runner_name,
    runner_service_name,
    workload_name,
    workload_service_name,
)
from ui.ui_common import UISettings
from ui.ui_kube_utils import _select_best_pod


def _log_target_specs(instance: dict[str, Any]) -> dict[str, dict[str, str]]:
    model = MirrorInstanceSpecModel.from_instance_dict(instance)
    contract = get_parser_contract(model.parser_type)
    payload: dict[str, dict[str, str]] = {}
    for workload in contract.workloads:
        for target in workload.log_targets:
            payload[target.target] = {
                "workloadId": workload.workload_id,
                "component": workload.component,
                "container": target.container_name,
                "label": target.label,
            }
    return payload


def _component_log_target(instance: dict[str, Any], target: str) -> tuple[str, str, str]:
    """Get component, container name, and label from log target."""
    normalized = str(target or "").strip().lower()
    target_specs = _log_target_specs(instance)
    try:
        spec = target_specs[normalized]
    except KeyError as exc:
        raise web.HTTPNotFound(text="unknown log target") from exc
    return spec["component"], spec["container"], spec["label"]


def _labels_selector(name: str, component: str) -> str:
    """Create label selector for component."""
    return ",".join(
        f"{key}={value}" for key, value in common_labels(name, component).items()
    )


def _json_ready(value: Any) -> Any:
    """Convert Kubernetes client objects to JSON-ready dicts."""
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


def _tail_lines_from_request(request: web.Request, default: int = 400) -> int:
    """Get tail lines parameter from request."""
    try:
        value = int(str(request.query.get("tail", default)).strip())
    except (TypeError, ValueError):
        return default
    return max(50, min(value, 2000))


def _log_tag_from_request(request: web.Request) -> str:
    return normalize_log_tag(str(request.query.get("tag", "")).strip()) or "all"


def _latest_pod_name(namespace: str, name: str, component: str) -> str:
    """Get the latest pod name for a component."""
    from kube.kube_client import get_kube_clients

    selector = _labels_selector(name, component)
    pods = get_kube_clients().core.list_namespaced_pod(
        namespace,
        label_selector=selector,
    ).items
    best = _select_best_pod(list(pods))
    return str(best.metadata.name or "") if best is not None else ""


def _pod_log_snapshot(
    settings: UISettings,
    name: str,
    target: str,
    tail_lines: int,
    selected_tag: str = "all",
) -> dict[str, Any]:
    """Get pod log snapshot."""
    from ui.ui_kube_utils import _pod_network_metrics

    instance = get_instance(settings.namespace, name)
    component, container, target_label = _component_log_target(instance, target)
    pod_name = _latest_pod_name(settings.namespace, name, component)
    if not pod_name:
        raise web.HTTPNotFound(text=f"Pod for {name}/{target} is not available yet")
    network_metrics = _pod_network_metrics(settings.namespace, pod_name)

    log_text = read_pod_log(
        settings.namespace,
        pod_name,
        container=container,
        tail_lines=tail_lines,
    )
    filtered_log_text, available_tags, applied_tag = filter_log_text_by_tag(
        log_text,
        selected_tag,
    )
    return {
        "instance": name,
        "target": target,
        "targetLabel": target_label,
        "component": component,
        "container": container,
        "podName": pod_name,
        "tailLines": tail_lines,
        "logText": filtered_log_text,
        "selectedTag": applied_tag,
        "availableTags": available_tags,
        "tagOptions": format_log_tag_options(available_tags),
        "rxBytes": network_metrics.get("rxBytes"),
        "txBytes": network_metrics.get("txBytes"),
    }


def _load_resource_entries(settings: UISettings, name: str) -> list[dict[str, Any]]:
    """Load cluster resources related to a single instance."""
    from kube.kube_client import get_kube_clients

    kube = get_kube_clients()
    instance = get_instance(settings.namespace, name)
    status = dict(instance.get("status") or {})
    model = MirrorInstanceSpecModel.from_instance_dict(instance)
    contract = get_parser_contract(model.parser_type)
    workload_status = dict(status.get("workloads") or {})
    readers: list[tuple[str, str, Any]] = [("MirrorInstance", name, lambda: instance)]
    for workload in contract.workloads:
        workload_name_value = workload_name(name, model.parser_type, workload.workload_id)
        service_name_value = workload_service_name(name, model.parser_type, workload.workload_id)
        readers.extend(
            [
                (
                    "StatefulSet",
                    workload_name_value,
                    lambda workload_name_value=workload_name_value: kube.apps.read_namespaced_stateful_set(
                        workload_name_value,
                        settings.namespace,
                    ),
                ),
                (
                    "Service",
                    service_name_value,
                    lambda service_name_value=service_name_value: kube.core.read_namespaced_service(
                        service_name_value,
                        settings.namespace,
                    ),
                ),
            ]
        )
        pod_name = str(dict(workload_status.get(workload.workload_id) or {}).get("podName") or "") or _latest_pod_name(
            settings.namespace,
            name,
            workload.component,
        )
        if pod_name:
            readers.append(
                (
                    "Pod",
                    pod_name,
                    lambda pod_name=pod_name: kube.core.read_namespaced_pod(
                        pod_name,
                        settings.namespace,
                    ),
                )
            )
    entries: list[dict[str, Any]] = []
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
