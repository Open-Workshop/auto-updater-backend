"""Log and resource helpers for UI route handlers."""
from __future__ import annotations

from typing import Any

from aiohttp import web

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
)
from ui.ui_common import UISettings
from ui.ui_kube_utils import _select_best_pod


def _component_log_target(target: str) -> tuple[str, str]:
    """Get component and container name from log target."""
    normalized = str(target or "").strip().lower()
    if normalized == "parser":
        return "parser", "parser"
    if normalized == "runner":
        return "runner", "runner"
    if normalized == "tun":
        return "runner", "tun-proxy"
    raise web.HTTPNotFound(text="unknown log target")


def _component_label(target: str) -> str:
    """Get display label for component."""
    normalized = str(target or "").strip().lower()
    if normalized == "parser":
        return "Parser"
    if normalized == "runner":
        return "Runner"
    if normalized == "tun":
        return "TUN"
    return normalized.title()


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

    component, container = _component_log_target(target)
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
        "targetLabel": _component_label(target),
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
    parser_pod_name = str(status.get("parserPod") or "") or _latest_pod_name(
        settings.namespace,
        name,
        "parser",
    )
    runner_pod_name = str(status.get("runnerPod") or "") or _latest_pod_name(
        settings.namespace,
        name,
        "runner",
    )
    readers: list[tuple[str, str, Any]] = [
        ("MirrorInstance", name, lambda: instance),
        (
            "StatefulSet",
            parser_name(name),
            lambda: kube.apps.read_namespaced_stateful_set(
                parser_name(name),
                settings.namespace,
            ),
        ),
        (
            "StatefulSet",
            runner_name(name),
            lambda: kube.apps.read_namespaced_stateful_set(
                runner_name(name),
                settings.namespace,
            ),
        ),
        (
            "Service",
            parser_service_name(name),
            lambda: kube.core.read_namespaced_service(
                parser_service_name(name),
                settings.namespace,
            ),
        ),
        (
            "Service",
            runner_service_name(name),
            lambda: kube.core.read_namespaced_service(
                runner_service_name(name),
                settings.namespace,
            ),
        ),
    ]
    if parser_pod_name:
        readers.append(
            (
                "Pod",
                parser_pod_name,
                lambda: kube.core.read_namespaced_pod(
                    parser_pod_name,
                    settings.namespace,
                ),
            )
        )
    if runner_pod_name:
        readers.append(
            (
                "Pod",
                runner_pod_name,
                lambda: kube.core.read_namespaced_pod(
                    runner_pod_name,
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
