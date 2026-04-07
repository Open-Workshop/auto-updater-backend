"""HTTP request handlers for UI service."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote, urlencode

import requests
from aiohttp import web

from kube.kube_client import delete_instance, delete_secret, get_instance, patch_instance, read_pod_log, read_secret_value
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
from ui.ui_common import UISettings, _bool_from_form, _int_from_form, _url
from ui.ui_forms import (
    _build_sync_spec,
    _editor_context,
    _settings_form,
    _validation_errors,
    _validate_proxy_pool,
    _validate_runner_proxy,
)
from ui.ui_instance import _dashboard_resource_totals, _load_instance_summary, _load_instance_summaries
from ui.ui_kube_utils import _select_best_pod
from ui.ui_pages import _dashboard, _dashboard_counts, _detail_page, _new_instance_page


def _flash_redirect(settings: UISettings, path: str, message: str, kind: str = "info") -> web.HTTPFound:
    """Create a redirect response with flash message."""
    target = _url(settings, path)
    separator = "&" if "?" in path else "?"
    query = urlencode({"flash": message, "flashKind": kind})
    return web.HTTPFound(f"{target}{separator}{query}")


def _flash_from_request(request: web.Request) -> tuple[str, str]:
    """Extract flash message from request."""
    message = str(request.query.get("flash", "")).strip()
    kind = str(request.query.get("flashKind", "info")).strip().lower() or "info"
    return message, kind


def _wants_json(request: web.Request) -> bool:
    """Check if request wants JSON response."""
    accept = request.headers.get("Accept", "")
    return "application/json" in accept or request.path.startswith("/api/") or "/api/" in request.path


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


def _managed_secret_names(name: str) -> set[str]:
    """Get all managed secret names for an instance."""
    return {
        managed_credentials_secret_name(name),
        managed_parser_proxy_secret_name(name),
        managed_runner_proxy_secret_name(name),
    }


def _labels_selector(name: str, component: str) -> str:
    """Create label selector for component."""
    return ",".join(f"{key}={value}" for key, value in common_labels(name, component).items())


def _json_ready(value: Any) -> Any:
    """Convert Kubernetes object to JSON-ready dict."""
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


def _latest_pod_name(namespace: str, name: str, component: str) -> str:
    """Get the latest pod name for a component."""
    from kube.kube_client import get_kube_clients
    
    selector = _labels_selector(name, component)
    pods = get_kube_clients().core.list_namespaced_pod(namespace, label_selector=selector).items
    best = _select_best_pod(list(pods))
    return str(best.metadata.name or "") if best is not None else ""


def _pod_log_snapshot(settings: UISettings, name: str, target: str, tail_lines: int) -> dict[str, Any]:
    """Get pod log snapshot."""
    from ui.ui_kube_utils import _pod_network_metrics
    from kube.kube_client import read_pod_log_merged
    
    component, container = _component_log_target(target)
    pod_name = _latest_pod_name(settings.namespace, name, component)
    if not pod_name:
        raise web.HTTPNotFound(text=f"Pod for {name}/{target} is not available yet")
    network_metrics = _pod_network_metrics(settings.namespace, pod_name)
    
    # For runner target, merge logs from runner and steamcmd containers
    if component == "runner":
        log_text = read_pod_log_merged(
            settings.namespace,
            pod_name,
            containers=["runner", "steamcmd"],
            tail_lines=tail_lines,
        )
    else:
        log_text = read_pod_log(
            settings.namespace,
            pod_name,
            container=container,
            tail_lines=tail_lines,
        )
    
    return {
        "instance": name,
        "target": target,
        "targetLabel": _component_label(target),
        "component": component,
        "container": container,
        "podName": pod_name,
        "tailLines": tail_lines,
        "logText": log_text,
        "rxBytes": network_metrics.get("rxBytes"),
        "txBytes": network_metrics.get("txBytes"),
    }


def _load_resource_entries(settings: UISettings, name: str) -> list[dict[str, Any]]:
    """Load resource entries for an instance."""
    from kube.kube_client import get_kube_clients
    
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
    """Create JSON response."""
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
    """Create action response (JSON or redirect)."""
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
    """Health check endpoint."""
    return web.json_response({"status": "ok"})


async def dashboard(request: web.Request) -> web.Response:
    """Dashboard page handler."""
    settings: UISettings = request.app["settings"]
    flash, flash_kind = _flash_from_request(request)
    items = _load_instance_summaries(settings)
    resource_totals = _dashboard_resource_totals(items)
    return web.Response(
        text=_dashboard(settings, items, flash, flash_kind, resource_totals),
        content_type="text/html",
    )


async def instances_api(request: web.Request) -> web.Response:
    """Instances API endpoint."""
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
    """Instance summary API endpoint."""
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
    """New instance page handler."""
    settings: UISettings = request.app["settings"]
    flash, flash_kind = _flash_from_request(request)
    context = _editor_context(settings, None)
    return web.Response(text=_new_instance_page(settings, context, flash, flash_kind), content_type="text/html")


async def edit_instance_page(request: web.Request) -> web.StreamResponse:
    """Edit instance page handler (redirects to settings tab)."""
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    raise web.HTTPFound(_url(settings, f"/instances/{quote(name)}?tab=settings"))


async def instance_detail_page(request: web.Request) -> web.Response:
    """Instance detail page handler."""
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
    """Resource page handler (redirects to resources tab)."""
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    query = dict(request.query)
    query["tab"] = "resources"
    raise web.HTTPFound(_url(settings, f"/instances/{quote(name)}?{urlencode(query)}"))


async def pod_logs_api(request: web.Request) -> web.Response:
    """Pod logs API endpoint."""
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
    """Pod logs page handler (redirects to logs tab)."""
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    target = request.match_info["target"]
    query = dict(request.query)
    query["tab"] = "logs"
    query["target"] = target
    raise web.HTTPFound(_url(settings, f"/instances/{quote(name)}?{urlencode(query)}"))


async def save_instance(request: web.Request) -> web.StreamResponse:
    """Save instance handler."""
    from kube.kube_client import replace_or_create_instance, upsert_secret
    
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
    """Sync now handler."""
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
    """Toggle instance handler."""
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
    """Delete instance handler."""
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
    """Basic authentication middleware."""
    import base64
    import hmac
    
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
