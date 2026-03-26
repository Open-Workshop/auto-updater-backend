from __future__ import annotations

import base64
import html
import hmac
import json
import logging
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

import requests
from aiohttp import web

from http_utils import parse_proxy_url, validate_proxy_url
from kube_client import (
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
from mirror_instance import (
    API_VERSION,
    DEFAULT_SPEC,
    KIND,
    PLURAL,
    common_labels,
    deep_merge,
    instance_name,
    managed_credentials_secret_name,
    managed_parser_proxy_secret_name,
    managed_runner_proxy_secret_name,
    normalize_instance,
    parser_name,
    parser_service_url,
    parser_service_name,
    runner_name,
    runner_service_name,
)


@dataclass
class UISettings:
    namespace: str
    host: str
    port: int
    title: str
    base_path: str
    username: str
    password: str


def _normalize_base_path(value: str) -> str:
    raw = (value or "").strip()
    if not raw or raw == "/":
        return ""
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw.rstrip("/")


def load_ui_settings() -> UISettings:
    try:
        port = int(os.environ.get("OW_UI_PORT", "8080"))
    except ValueError:
        port = 8080
    return UISettings(
        namespace=os.environ.get("AUTO_UPDATER_NAMESPACE", "auto-updater").strip() or "auto-updater",
        host=os.environ.get("OW_UI_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=port,
        title=os.environ.get("OW_UI_TITLE", "Auto Updater Control Plane").strip()
        or "Auto Updater Control Plane",
        base_path=_normalize_base_path(os.environ.get("OW_UI_BASE_PATH", "")),
        username=os.environ.get("OW_UI_USERNAME", "").strip(),
        password=os.environ.get("OW_UI_PASSWORD", ""),
    )


def _escape(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _bool_from_form(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "on", "yes"}


def _int_from_form(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _sync_json(spec: dict[str, Any]) -> str:
    return json.dumps(spec["sync"], ensure_ascii=False, indent=2, sort_keys=True)


def _url(settings: UISettings, path: str) -> str:
    normalized_path = path if path.startswith("/") else f"/{path}"
    if not settings.base_path:
        return normalized_path
    if normalized_path == "/":
        return settings.base_path + "/"
    return settings.base_path + normalized_path


def _layout(settings: UISettings, body: str, flash: str = "") -> str:
    flash_html = (
        f"<div class='flash'>{_escape(flash)}</div>"
        if flash
        else ""
    )
    return f"""<!doctype html>
<html lang="ru">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{_escape(settings.title)}</title>
    <style>
      :root {{
        --bg: #f6f1e8;
        --panel: #fffaf2;
        --ink: #16202a;
        --muted: #5c6670;
        --line: #ddcfbe;
        --accent: #1d6a58;
        --warn: #a33e2e;
        --mono: "IBM Plex Mono", "Consolas", monospace;
        --sans: "IBM Plex Sans", "Trebuchet MS", sans-serif;
      }}
      * {{ box-sizing: border-box; }}
      body {{ margin: 0; font-family: var(--sans); background: linear-gradient(180deg, #faf5ec, var(--bg)); color: var(--ink); }}
      main {{ max-width: 1220px; margin: 0 auto; padding: 24px 18px 42px; }}
      h1, h2 {{ margin: 0; }}
      .top {{ display: grid; gap: 8px; margin-bottom: 18px; }}
      .eyebrow {{ color: var(--accent); font-size: 12px; letter-spacing: .14em; text-transform: uppercase; font-weight: 700; }}
      .subtitle {{ color: var(--muted); max-width: 860px; }}
      .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0 22px; }}
      .button, button {{ appearance: none; border: 0; border-radius: 999px; padding: 10px 16px; text-decoration: none; cursor: pointer; font: inherit; background: var(--ink); color: white; }}
      .button.secondary, button.secondary {{ background: #e7ddcf; color: var(--ink); }}
      .button.warn, button.warn {{ background: var(--warn); }}
      .flash {{ padding: 14px 16px; border: 1px solid #f0c98f; background: #fff0d8; border-radius: 14px; margin-bottom: 16px; }}
      .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 14px; }}
      .card, form.panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 22px; padding: 18px; box-shadow: 0 12px 28px rgba(22,32,42,.05); }}
      .meta {{ display: grid; gap: 6px; font-size: 14px; color: var(--muted); margin: 12px 0; }}
      .status {{ display: inline-block; padding: 7px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; text-transform: uppercase; background: rgba(29,106,88,.12); color: var(--accent); }}
      .status.error {{ background: rgba(163,62,46,.12); color: var(--warn); }}
      .inline-actions {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }}
      .inline-actions form {{ margin: 0; }}
      .fields {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }}
      label {{ display: grid; gap: 7px; font-weight: 700; }}
      input, textarea, select {{ width: 100%; border-radius: 15px; border: 1px solid var(--line); padding: 11px 13px; font: inherit; background: #fffefb; color: var(--ink); }}
      textarea {{ min-height: 180px; font-family: var(--mono); font-size: 13px; resize: vertical; }}
      .hint {{ color: var(--muted); font-size: 13px; font-weight: 400; }}
      code, pre {{ font-family: var(--mono); }}
      pre {{ background: #19222b; color: #eef5ff; border-radius: 16px; padding: 12px; overflow: auto; }}
      .checkbox {{ display: flex; align-items: center; gap: 10px; }}
      .checkbox input {{ width: 18px; height: 18px; }}
    </style>
  </head>
  <body>
    <main>
      {flash_html}
      {body}
    </main>
  </body>
</html>"""


def _dashboard(settings: UISettings, instances: list[dict[str, Any]], flash: str) -> str:
    cards = []
    for item in instances:
        normalized = normalize_instance(item)
        status = dict(item.get("status") or {})
        name = instance_name(item)
        phase = str(status.get("phase") or "Unknown")
        status_class = "status error" if phase == "Error" else "status"
        conditions = list(status.get("conditions") or [])
        cards.append(
            f"""
            <section class="card">
              <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
                <div>
                  <h2>{_escape(name)}</h2>
                  <div class="hint">Steam App ID {_escape(normalized['spec']['source'].get('steamAppId', 0))}, OW Game ID {_escape(normalized['spec']['source'].get('owGameId', 0))}</div>
                </div>
                <span class="{status_class}">{_escape(phase)}</span>
              </div>
              <div class="meta">
                <div>enabled: <strong>{_escape(normalized['spec'].get('enabled', True))}</strong></div>
                <div>parser pod: <code>{_escape(status.get('parserPod') or 'n/a')}</code></div>
                <div>runner pod: <code>{_escape(status.get('runnerPod') or 'n/a')}</code></div>
                <div>last sync: <strong>{_escape(status.get('lastSyncResult') or 'n/a')}</strong></div>
                <div>last error: {_escape(status.get('lastError') or 'n/a')}</div>
              </div>
              <details>
                <summary>Sync spec</summary>
                <pre>{_escape(_sync_json(normalized['spec']))}</pre>
              </details>
              <details>
                <summary>Conditions</summary>
                <pre>{_escape(json.dumps(conditions, ensure_ascii=False, indent=2, sort_keys=True))}</pre>
              </details>
              <div class="inline-actions">
                <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/edit')}">Изменить</a>
                <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/resources')}">Ресурсы</a>
                <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/logs/parser')}">Parser logs</a>
                <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/logs/runner')}">Runner logs</a>
                <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/logs/tun')}">TUN logs</a>
                <form method="post" action="{_url(settings, f'/instances/{quote(name)}/sync')}"><button type="submit">Sync now</button></form>
                <form method="post" action="{_url(settings, f'/instances/{quote(name)}/toggle')}"><button type="submit" class="secondary">{'Pause' if normalized['spec'].get('enabled', True) else 'Resume'}</button></form>
                <form method="post" action="{_url(settings, f'/instances/{quote(name)}/delete')}" onsubmit="return confirm('Удалить {_escape(name)}?')"><button type="submit" class="warn">Удалить</button></form>
              </div>
            </section>
            """
        )
    body = f"""
    <section class="top">
      <div class="eyebrow">MirrorInstance Control Plane</div>
      <h1>{_escape(settings.title)}</h1>
      <div class="subtitle">Kubernetes-native управление инстансами. UI редактирует CR и связанные Secret, оператор раскладывает parser/steamcmd-runner workload'ы.</div>
    </section>
    <div class="actions">
      <a class="button" href="{_url(settings, '/instances/new')}">Новый экземпляр</a>
    </div>
    <div class="grid">
      {''.join(cards) or "<section class='card'>Экземпляров пока нет.</section>"}
    </div>
    """
    return _layout(settings, body, flash)


def _form(settings: UISettings, instance: dict[str, Any] | None, flash: str) -> str:
    if instance is None:
        spec = deep_merge(DEFAULT_SPEC, {})
        name = ""
        login = ""
        parser_proxy_pool = ""
        runner_proxy_url = ""
    else:
        normalized = normalize_instance(instance)
        spec = normalized["spec"]
        name = instance_name(instance)
        credentials_secret = spec["credentials"]["secretRef"]
        parser_secret = spec["parser"].get("proxyPoolSecretRef", "")
        runner_secret = spec["steamcmd"]["proxy"].get("secretRef", "")
        login = read_secret_value(settings.namespace, credentials_secret, "login")
        parser_proxy_pool = ""
        runner_proxy_url = ""
        if parser_secret:
            try:
                parser_proxy_pool = read_secret_value(settings.namespace, parser_secret, "proxyPool")
            except Exception:
                parser_proxy_pool = ""
        if runner_secret:
            try:
                runner_proxy_url = read_secret_value(settings.namespace, runner_secret, "proxyUrl")
            except Exception:
                runner_proxy_url = ""
    body = f"""
    <section class="top">
      <div class="eyebrow">MirrorInstance Editor</div>
      <h1>{_escape(name or 'Новый экземпляр')}</h1>
      <div class="subtitle">Основные поля вынесены отдельно, полный runtime можно править через JSON `spec.sync`.</div>
    </section>
    <div class="actions">
      <a class="button secondary" href="{_url(settings, '/')}">Назад</a>
    </div>
    <form class="panel" method="post" action="{_url(settings, '/instances/save')}">
      <input type="hidden" name="original_name" value="{_escape(name)}">
      <div class="fields">
        <label>
          <span>Имя экземпляра</span>
          <input type="text" name="name" value="{_escape(name)}" required>
        </label>
        <label class="checkbox">
          <input type="checkbox" name="enabled" {'checked' if spec.get('enabled', True) else ''}>
          <span>Enabled</span>
        </label>
        <label>
          <span>Steam App ID</span>
          <input type="number" name="steam_app_id" value="{_escape(spec['source'].get('steamAppId', 0))}">
        </label>
        <label>
          <span>OW Game ID</span>
          <input type="number" name="ow_game_id" value="{_escape(spec['source'].get('owGameId', 0))}">
        </label>
        <label>
          <span>Language</span>
          <input type="text" name="language" value="{_escape(spec['source'].get('language', 'english'))}">
        </label>
        <label>
          <span>Parser PVC size</span>
          <input type="text" name="parser_storage_size" value="{_escape(spec['storage']['parser'].get('size', '20Gi'))}">
        </label>
        <label>
          <span>Runner PVC size</span>
          <input type="text" name="runner_storage_size" value="{_escape(spec['storage']['runner'].get('size', '10Gi'))}">
        </label>
        <label>
          <span>OW login</span>
          <input type="text" name="ow_login" value="{_escape(login)}" required>
        </label>
        <label>
          <span>OW password</span>
          <input type="password" name="ow_password" value="">
          <span class="hint">Оставьте пустым, чтобы сохранить текущий пароль.</span>
        </label>
        <label>
          <span>Steamcmd proxy type</span>
          <select name="runner_proxy_type">
            <option value="socks5" {'selected' if spec['steamcmd']['proxy'].get('type') == 'socks5' else ''}>socks5</option>
            <option value="http" {'selected' if spec['steamcmd']['proxy'].get('type') == 'http' else ''}>http</option>
          </select>
        </label>
      </div>
      <label style="margin-top:16px;">
        <span>Steamcmd proxy URL</span>
        <textarea name="runner_proxy_url" style="min-height:90px;">{_escape(runner_proxy_url)}</textarea>
        <span class="hint">Один upstream proxy для TUN sidecar. Хранится в отдельном Secret как `proxyUrl`.</span>
      </label>
      <label style="margin-top:16px;">
        <span>Parser proxy pool</span>
        <textarea name="parser_proxy_pool">{_escape(parser_proxy_pool)}</textarea>
        <span class="hint">Один URL на строку или через запятую. Это отдельный pool только для parser HTTP-запросов.</span>
      </label>
      <label style="margin-top:16px;">
        <span>spec.sync JSON</span>
        <textarea name="sync_json">{_escape(_sync_json(spec))}</textarea>
      </label>
      <div class="actions">
        <button type="submit">Сохранить</button>
        <a class="button secondary" href="{_url(settings, '/')}">Отмена</a>
      </div>
    </form>
    """
    return _layout(settings, body, flash)


def _flash_redirect(settings: UISettings, path: str, message: str) -> web.HTTPFound:
    target = _url(settings, path)
    separator = "&" if "?" in path else "?"
    return web.HTTPFound(f"{target}{separator}{urlencode({'flash': message})}")


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


def _parse_sync_json(raw: str) -> dict[str, Any]:
    payload = json.loads(raw or "{}")
    if not isinstance(payload, dict):
        raise ValueError("spec.sync JSON must be an object")
    return payload


def _validate_proxy_pool(raw: str) -> str:
    values = []
    for chunk in raw.replace(",", "\n").splitlines():
        value = chunk.strip()
        if not value:
            continue
        validate_proxy_url(value)
        values.append(value)
    return "\n".join(values)


def _validate_runner_proxy(raw: str, proxy_type: str) -> str:
    value = str(raw or "").strip()
    parsed = parse_proxy_url(value)
    normalized_type = str(proxy_type or "socks5").strip().lower() or "socks5"
    if normalized_type == "socks5" and not parsed.is_socks:
        raise ValueError("Steamcmd proxy type=socks5, но URL не socks5://")
    if normalized_type == "http" and not parsed.is_http:
        raise ValueError("Steamcmd proxy type=http, но URL не http:// или https://")
    return value


def _component_log_target(target: str) -> tuple[str, str]:
    normalized = str(target or "").strip().lower()
    if normalized == "parser":
        return "parser", "parser"
    if normalized == "runner":
        return "runner", "runner"
    if normalized == "tun":
        return "runner", "tun-proxy"
    raise web.HTTPNotFound(text="unknown log target")


def _latest_pod_name(namespace: str, name: str, component: str) -> str:
    selector = ",".join(f"{key}={value}" for key, value in common_labels(name, component).items())
    pods = get_kube_clients().core.list_namespaced_pod(namespace, label_selector=selector).items
    if not pods:
        return ""
    pods.sort(
        key=lambda item: (item.metadata.creation_timestamp.isoformat() if item.metadata.creation_timestamp else ""),
        reverse=True,
    )
    return str(pods[0].metadata.name or "")


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
        raise web.HTTPNotFound(text=f"Pod для {name}/{target} пока не найден")
    return {
        "instance": name,
        "target": target,
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


async def healthz(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def dashboard(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    instances = list_instances(settings.namespace)
    flash = request.query.get("flash", "")
    return web.Response(text=_dashboard(settings, instances, flash), content_type="text/html")


async def new_instance_page(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    flash = request.query.get("flash", "")
    return web.Response(text=_form(settings, None, flash), content_type="text/html")


async def edit_instance_page(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    flash = request.query.get("flash", "")
    instance = get_instance(settings.namespace, name)
    return web.Response(text=_form(settings, instance, flash), content_type="text/html")


async def save_instance(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    form = await request.post()
    name = str(form.get("name", "")).strip()
    if not name:
        raise _flash_redirect(settings, "/instances/new", "Имя обязательно")
    original_name = str(form.get("original_name", "")).strip() or name
    instance = None
    existing_password = ""
    try:
        instance = get_instance(settings.namespace, original_name)
        credentials_ref = normalize_instance(instance)["spec"]["credentials"]["secretRef"]
        existing_password = read_secret_value(settings.namespace, credentials_ref, "password")
    except Exception:
        instance = None
    try:
        sync_spec = deep_merge(DEFAULT_SPEC["sync"], _parse_sync_json(str(form.get("sync_json", "{}"))))
        runner_proxy_type = str(form.get("runner_proxy_type", "socks5")).strip() or "socks5"
        runner_proxy_url = _validate_runner_proxy(form.get("runner_proxy_url", ""), runner_proxy_type)
        parser_proxy_pool = _validate_proxy_pool(str(form.get("parser_proxy_pool", "")))
    except Exception as exc:
        body = _form(settings, instance, str(exc))
        return web.Response(text=body, content_type="text/html", status=400)

    credentials_secret = managed_credentials_secret_name(name)
    parser_proxy_secret = managed_parser_proxy_secret_name(name)
    runner_proxy_secret = managed_runner_proxy_secret_name(name)
    password = str(form.get("ow_password", "")).strip() or existing_password
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
                "login": str(form.get("ow_login", "")).strip(),
                "password": password,
            },
        },
    )
    if parser_proxy_pool:
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
                    "proxyPool": parser_proxy_pool,
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
                "proxyUrl": runner_proxy_url,
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
                "steamAppId": _int_from_form(form.get("steam_app_id"), 0),
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
                    "size": str(form.get("parser_storage_size", "")).strip() or "20Gi",
                    "storageClassName": "local-path",
                },
                "runner": {
                    "size": str(form.get("runner_storage_size", "")).strip() or "10Gi",
                    "storageClassName": "local-path",
                },
            },
        },
    }
    replace_or_create_instance(settings.namespace, name, body)
    if original_name != name:
        delete_instance(settings.namespace, original_name)
        for secret_name in _managed_secret_names(original_name):
            delete_secret(settings.namespace, secret_name)
    raise _flash_redirect(settings, "/", f"Инстанс {name} сохранён")


async def sync_now(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    url = parser_service_url(name, settings.namespace) + "/api/v1/sync"
    try:
        response = requests.post(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise _flash_redirect(settings, "/", f"Sync now failed: {exc}")
    raise _flash_redirect(settings, "/", f"Sync now отправлен для {name}")


async def resource_page(request: web.Request) -> web.Response:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    kube = get_kube_clients()
    instance = get_instance(settings.namespace, name)
    status = dict(instance.get("status") or {})
    parser_pod_name = str(status.get("parserPod") or "") or _latest_pod_name(settings.namespace, name, "parser")
    runner_pod_name = str(status.get("runnerPod") or "") or _latest_pod_name(settings.namespace, name, "runner")
    entries: list[tuple[str, str, Any]] = [
        ("MirrorInstance", name, _json_ready(instance)),
    ]
    readers = [
        ("StatefulSet", parser_name(name), lambda: kube.apps.read_namespaced_stateful_set(parser_name(name), settings.namespace)),
        ("StatefulSet", runner_name(name), lambda: kube.apps.read_namespaced_stateful_set(runner_name(name), settings.namespace)),
        ("Service", parser_service_name(name), lambda: kube.core.read_namespaced_service(parser_service_name(name), settings.namespace)),
        ("Service", runner_service_name(name), lambda: kube.core.read_namespaced_service(runner_service_name(name), settings.namespace)),
    ]
    if parser_pod_name:
        readers.append(("Pod", parser_pod_name, lambda: kube.core.read_namespaced_pod(parser_pod_name, settings.namespace)))
    if runner_pod_name:
        readers.append(("Pod", runner_pod_name, lambda: kube.core.read_namespaced_pod(runner_pod_name, settings.namespace)))
    for kind, resource_name, reader in readers:
        try:
            entries.append((kind, resource_name, _json_ready(reader())))
        except Exception as exc:
            entries.append((kind, resource_name, {"error": str(exc)}))
    sections = []
    for kind, resource_name, payload in entries:
        sections.append(
            f"""
            <section class="card">
              <div class="eyebrow">{_escape(kind)}</div>
              <h2>{_escape(resource_name)}</h2>
              <pre>{_escape(json.dumps(_json_ready(payload), ensure_ascii=False, indent=2, sort_keys=True))}</pre>
            </section>
            """
        )
    body = f"""
    <section class="top">
      <div class="eyebrow">Related Resources</div>
      <h1>{_escape(name)}</h1>
      <div class="subtitle">Снимок связанных Kubernetes-ресурсов без показа Secret data.</div>
    </section>
    <div class="actions">
      <a class="button secondary" href="{_url(settings, '/')}">Назад</a>
      <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/logs/parser')}">Parser logs</a>
      <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/logs/runner')}">Runner logs</a>
      <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/logs/tun')}">TUN logs</a>
    </div>
    <div class="grid">
      {''.join(sections)}
    </div>
    """
    return web.Response(text=_layout(settings, body), content_type="text/html")


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
    tail_lines = _tail_lines_from_request(request)
    try:
        snapshot = _pod_log_snapshot(settings, name, target, tail_lines)
        pod_name = str(snapshot.get("podName") or "")
        container = str(snapshot.get("container") or "")
        initial_log_text = str(snapshot.get("logText") or "")
    except web.HTTPNotFound:
        raise _flash_redirect(settings, "/", f"Pod для {name}/{target} пока не найден")
    except Exception as exc:
        component, container = _component_log_target(target)
        pod_name = _latest_pod_name(settings.namespace, name, component)
        initial_log_text = f"Failed to load logs: {exc}"
    api_url = _url(settings, f"/api/instances/{quote(name)}/logs/{quote(target)}")
    escape_instance = json.dumps(name, ensure_ascii=False)
    escape_target = json.dumps(target, ensure_ascii=False)
    body = f"""
    <section class="top">
      <div class="eyebrow">Live Pod Logs</div>
      <h1>{_escape(name)} / {_escape(target)}</h1>
      <div class="subtitle">Живая панель для pod <code id="pod-name">{_escape(pod_name or 'n/a')}</code>, контейнер <code id="container-name">{_escape(container)}</code>. Хвост лога обновляется каждые 2 секунды без ручного рефреша.</div>
    </section>
    <div class="actions">
      <a class="button secondary" href="{_url(settings, '/')}">Назад</a>
      <a class="button secondary" href="{_url(settings, f'/instances/{quote(name)}/resources')}">Ресурсы</a>
      <button type="button" class="secondary" id="toggle-live">Pause</button>
      <button type="button" class="secondary" id="refresh-now">Refresh now</button>
    </div>
    <section class="card">
      <div class="meta" style="margin-top:0;">
        <div>instance: <code>{_escape(name)}</code></div>
        <div>target: <code>{_escape(target)}</code></div>
        <div>tail lines: <strong id="tail-lines">{_escape(tail_lines)}</strong></div>
        <div>last update: <strong id="log-updated">initial</strong></div>
        <div>stream state: <strong id="log-stream-state">connecting</strong></div>
      </div>
      <pre id="log-output">{_escape(initial_log_text or '(empty)')}</pre>
    </section>
    <script>
      (() => {{
        const instanceName = {escape_instance};
        const targetName = {escape_target};
        const apiUrl = {json.dumps(api_url, ensure_ascii=False)};
        const initialTailLines = {tail_lines};
        const output = document.getElementById("log-output");
        const podName = document.getElementById("pod-name");
        const containerName = document.getElementById("container-name");
        const updated = document.getElementById("log-updated");
        const streamState = document.getElementById("log-stream-state");
        const toggleButton = document.getElementById("toggle-live");
        const refreshButton = document.getElementById("refresh-now");
        const tailLines = document.getElementById("tail-lines");
        let paused = false;
        let inFlight = false;
        let lastBody = output.textContent;

        function updateState(text) {{
          streamState.textContent = text;
        }}

        function nearBottom(element) {{
          return element.scrollHeight - element.scrollTop - element.clientHeight < 48;
        }}

        async function refreshLogs(force = false) {{
          if ((!force && paused) || inFlight) {{
            return;
          }}
          inFlight = true;
          updateState("updating");
          const stickToBottom = nearBottom(output);
          try {{
            const response = await fetch(`${{apiUrl}}?tail=${{initialTailLines}}`, {{
              headers: {{ "Accept": "application/json" }},
              cache: "no-store",
            }});
            const payload = await response.json();
            if (!response.ok) {{
              throw new Error(payload.error || `HTTP ${{response.status}}`);
            }}
            podName.textContent = payload.podName || "n/a";
            containerName.textContent = payload.container || "n/a";
            tailLines.textContent = String(payload.tailLines || initialTailLines);
            const text = payload.logText || "(empty)";
            if (text !== lastBody) {{
              output.textContent = text;
              lastBody = text;
              if (stickToBottom) {{
                output.scrollTop = output.scrollHeight;
              }}
            }}
            updated.textContent = new Date().toLocaleTimeString();
            updateState("live");
          }} catch (error) {{
            output.textContent = `Failed to refresh logs for ${{instanceName}}/${{targetName}}: ${{error.message}}`;
            lastBody = null;
            updated.textContent = new Date().toLocaleTimeString();
            updateState("error");
          }} finally {{
            inFlight = false;
          }}
        }}

        toggleButton.addEventListener("click", () => {{
          paused = !paused;
          toggleButton.textContent = paused ? "Resume" : "Pause";
          updateState(paused ? "paused" : "live");
          if (!paused) {{
            refreshLogs();
          }}
        }});
        refreshButton.addEventListener("click", () => refreshLogs(true));
        output.scrollTop = output.scrollHeight;
        refreshLogs();
        window.setInterval(refreshLogs, 2000);
      }})();
    </script>
    """
    return web.Response(text=_layout(settings, body), content_type="text/html")


async def toggle_instance(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    instance = normalize_instance(get_instance(settings.namespace, name))
    enabled = not bool(instance["spec"].get("enabled", True))
    patch_instance(settings.namespace, name, {"spec": {"enabled": enabled}})
    raise _flash_redirect(settings, "/", f"{name}: enabled={enabled}")


async def delete_instance_route(request: web.Request) -> web.StreamResponse:
    settings: UISettings = request.app["settings"]
    name = request.match_info["name"]
    delete_instance(settings.namespace, name)
    for secret_name in _managed_secret_names(name):
        delete_secret(settings.namespace, secret_name)
    raise _flash_redirect(settings, "/", f"{name} удалён")


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
    register("GET", "/instances/new", new_instance_page)
    register("GET", "/instances/{name}/edit", edit_instance_page)
    register("GET", "/instances/{name}/resources", resource_page)
    register("GET", "/api/instances/{name}/logs/{target}", pod_logs_api)
    register("GET", "/instances/{name}/logs/{target}", pod_logs_page)
    register("POST", "/instances/save", save_instance)
    register("POST", "/instances/{name}/sync", sync_now)
    register("POST", "/instances/{name}/toggle", toggle_instance)
    register("POST", "/instances/{name}/delete", delete_instance_route)
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
