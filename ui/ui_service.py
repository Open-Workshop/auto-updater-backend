from __future__ import annotations

import base64
import hmac
import logging
from typing import Any
from urllib.parse import quote, urlencode

import requests
from aiohttp import web

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
        }
    container_statuses = list(getattr(pod.status, "container_statuses", None) or [])
    container_ready = {status.name: bool(status.ready) for status in container_statuses}
    images = {container.name: container.image for container in list(getattr(pod.spec, "containers", None) or [])}
    conditions = {condition.type: condition.status for condition in list(getattr(pod.status, "conditions", None) or [])}
    return {
        "podName": str(pod.metadata.name or ""),
        "phase": str(getattr(pod.status, "phase", "") or "Unknown"),
        "ready": conditions.get("Ready") == "True",
        "deleting": getattr(pod.metadata, "deletion_timestamp", None) is not None,
        "images": images,
        "containerReady": container_ready,
    }


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
    last_sync_result: str,
    last_error: str,
    parser_ready: bool,
    runner_ready: bool,
) -> str:
    if not enabled:
        return "Disabled"
    if phase == "Error" or last_error:
        return "Error"
    if last_sync_result == "running":
        return "Syncing"
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
    if last_error:
        return _truncate(last_error, 110)
    if health == "Disabled":
        return "Paused by operator"
    if health == "Syncing":
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
) -> dict[str, Any]:
    normalized = normalize_instance(instance)
    status = dict(normalized.get("status") or {})
    name = instance_name(normalized)
    component_snapshots = component_snapshots or {}
    parser_snapshot = dict(component_snapshots.get("parser") or {})
    runner_snapshot = dict(component_snapshots.get("runner") or {})
    parser_pod_name = str(status.get("parserPod") or "") or str(parser_snapshot.get("podName") or "")
    runner_pod_name = str(status.get("runnerPod") or "") or str(runner_snapshot.get("podName") or "")
    parser_state = _component_state(parser_snapshot, parser_pod_name)
    runner_state = _component_state(runner_snapshot, runner_pod_name)
    phase = str(status.get("phase") or "Unknown")
    last_sync_result = str(status.get("lastSyncResult") or "").strip().lower()
    enabled = bool(normalized["spec"].get("enabled", True))
    health = _derive_health(
        enabled=enabled,
        phase=phase,
        last_sync_result=last_sync_result,
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
        },
        "runner": {
            "podName": runner_pod_name,
            "state": runner_state["label"],
            "tone": runner_state["tone"],
            "ready": bool(runner_snapshot.get("ready")),
            "image": str(runner_snapshot.get("images", {}).get("runner") or ""),
            "tunImage": str(runner_snapshot.get("images", {}).get("tun-proxy") or ""),
            "tunReady": bool(runner_snapshot.get("containerReady", {}).get("tun-proxy", False)),
        },
        "conditions": list(status.get("conditions") or []),
        "urls": _instance_urls(settings, name),
    }


def _load_instance_summaries(settings: UISettings) -> list[dict[str, Any]]:
    instances = list_instances(settings.namespace)
    names = {instance_name(item) for item in instances if instance_name(item)}
    snapshots = _component_snapshots_for_names(settings.namespace, names)
    summaries = [
        _instance_summary(settings, item, snapshots.get(instance_name(item), {}))
        for item in instances
    ]
    summaries.sort(key=lambda item: item["name"].lower())
    return summaries


def _load_instance_summary(settings: UISettings, name: str) -> dict[str, Any]:
    instance = get_instance(settings.namespace, name)
    snapshots = _component_snapshots_for_names(settings.namespace, {name})
    return _instance_summary(settings, instance, snapshots.get(name, {}))


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
    return web.Response(text=_dashboard(settings, items, flash, flash_kind), content_type="text/html")


async def instances_api(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    items = _load_instance_summaries(settings)
    return web.json_response({"items": items, "counts": _dashboard_counts(items)})


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
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    settings = load_ui_settings()
    get_kube_clients()
    app = _create_app(settings)
    web.run_app(app, host=settings.host, port=settings.port)
    return 0
