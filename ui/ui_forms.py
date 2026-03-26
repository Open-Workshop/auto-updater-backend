from __future__ import annotations

import json
from typing import Any

from core.http_utils import parse_proxy_url, validate_proxy_url
from kube.kube_client import read_secret_value
from kube.mirror_instance import DEFAULT_SPEC, deep_merge, instance_name, normalize_instance
from ui.ui_assets import render_template
from ui.ui_common import UISettings, _bool_from_form, _escape, _float_from_form, _int_from_form, _url


def _parse_sync_json(raw: str) -> dict[str, Any]:
    payload = json.loads(raw or "{}")
    if not isinstance(payload, dict):
        raise ValueError("sync JSON must be an object")
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
    value = (raw or "").strip()
    if not value:
        return ""
    parsed = parse_proxy_url(value)
    normalized_type = str(proxy_type or "socks5").strip().lower() or "socks5"
    if normalized_type == "socks5" and not parsed.is_socks:
        raise ValueError("Runner proxy type is socks5, but URL is not socks5://")
    if normalized_type == "http" and not parsed.is_http:
        raise ValueError("Runner proxy type is http, but URL is not http:// or https://")
    return value


def _input_class(errors: dict[str, str], field_name: str) -> str:
    return "input invalid" if errors.get(field_name) else "input"


def _input_modifier(errors: dict[str, str], field_name: str) -> str:
    return " invalid" if errors.get(field_name) else ""


def _field_error(errors: dict[str, str], field_name: str) -> str:
    message = str(errors.get(field_name) or "").strip()
    if not message:
        return ""
    return f"<div class='field-error'>{_escape(message)}</div>"


def _field_hint(message: str = "") -> str:
    rendered = str(message or "").strip()
    if not rendered:
        return ""
    return f"<div class='field-hint'>{_escape(rendered)}</div>"


def _checked_attr(value: Any) -> str:
    return "checked" if bool(value) else ""


def _selected_attr(value: Any, expected: str) -> str:
    return "selected" if str(value) == expected else ""


def _editor_context(
    settings: UISettings,
    instance: dict[str, Any] | None,
    *,
    form_data: dict[str, Any] | None = None,
    errors: dict[str, str] | None = None,
    sync_patch_value: str = "",
) -> dict[str, Any]:
    errors = errors or {}
    if instance is None:
        normalized = {"spec": deep_merge(DEFAULT_SPEC, {}), "metadata": {"name": ""}}
        login = ""
        parser_proxy_pool = ""
        runner_proxy_url = ""
        existing_password = ""
    else:
        normalized = normalize_instance(instance)
        name = instance_name(instance)
        credentials_secret = normalized["spec"]["credentials"]["secretRef"]
        parser_secret = normalized["spec"]["parser"].get("proxyPoolSecretRef", "")
        runner_secret = normalized["spec"]["steamcmd"]["proxy"].get("secretRef", "")
        login = read_secret_value(settings.namespace, credentials_secret, "login")
        existing_password = read_secret_value(settings.namespace, credentials_secret, "password")
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
        normalized["metadata"]["name"] = name
    spec = normalized["spec"]
    sync_spec = dict(spec["sync"])
    values = {
        "original_name": normalized.get("metadata", {}).get("name", ""),
        "name": normalized.get("metadata", {}).get("name", ""),
        "enabled": bool(spec.get("enabled", True)),
        "steam_app_id": spec["source"].get("steamAppId", 0),
        "ow_game_id": spec["source"].get("owGameId", 0),
        "language": spec["source"].get("language", "english"),
        "parser_storage_size": spec["storage"]["parser"].get("size", "20Gi"),
        "runner_storage_size": spec["storage"]["runner"].get("size", "10Gi"),
        "ow_login": login,
        "ow_password": "",
        "runner_proxy_type": spec["steamcmd"]["proxy"].get("type", "socks5"),
        "runner_proxy_url": runner_proxy_url,
        "parser_proxy_pool": parser_proxy_pool,
        "poll_interval_seconds": sync_spec.get("pollIntervalSeconds", 600),
        "timeout_seconds": sync_spec.get("timeoutSeconds", 60),
        "http_retries": sync_spec.get("httpRetries", 3),
        "http_retry_backoff": sync_spec.get("httpRetryBackoff", 5.0),
        "steam_http_retries": sync_spec.get("steamHttpRetries", 2),
        "steam_http_backoff": sync_spec.get("steamHttpBackoff", 2.0),
        "steam_request_delay": sync_spec.get("steamRequestDelay", 1.0),
        "log_level": sync_spec.get("logLevel", "INFO"),
        "run_once": bool(sync_spec.get("runOnce", False)),
        "sync_tags": bool(sync_spec.get("syncTags", True)),
        "prune_tags": bool(sync_spec.get("pruneTags", True)),
        "sync_dependencies": bool(sync_spec.get("syncDependencies", True)),
        "prune_dependencies": bool(sync_spec.get("pruneDependencies", True)),
        "sync_resources": bool(sync_spec.get("syncResources", True)),
        "prune_resources": bool(sync_spec.get("pruneResources", True)),
        "upload_resource_files": bool(sync_spec.get("uploadResourceFiles", True)),
        "scrape_preview_images": bool(sync_spec.get("scrapePreviewImages", True)),
        "scrape_required_items": bool(sync_spec.get("scrapeRequiredItems", True)),
        "max_screenshots": sync_spec.get("maxScreenshots", 20),
        "sync_json_patch": sync_patch_value or "",
        "return_path": "",
        "existing_password": existing_password,
    }
    if form_data is not None:
        bool_fields = {
            "enabled",
            "run_once",
            "sync_tags",
            "prune_tags",
            "sync_dependencies",
            "prune_dependencies",
            "sync_resources",
            "prune_resources",
            "upload_resource_files",
            "scrape_preview_images",
            "scrape_required_items",
        }
        for key in values:
            if key == "existing_password":
                continue
            if key in bool_fields:
                values[key] = _bool_from_form(form_data.get(key))
            else:
                values[key] = form_data.get(key, values[key])
    return {
        "instance": instance,
        "is_new": instance is None,
        "values": values,
        "errors": errors,
        "raw_sync": sync_spec,
    }


def _build_sync_spec(base_sync: dict[str, Any], form: dict[str, Any]) -> dict[str, Any]:
    sync = deep_merge(base_sync, {})
    sync.update(
        {
            "pollIntervalSeconds": _int_from_form(form.get("poll_interval_seconds"), sync.get("pollIntervalSeconds", 600)),
            "timeoutSeconds": _int_from_form(form.get("timeout_seconds"), sync.get("timeoutSeconds", 60)),
            "httpRetries": _int_from_form(form.get("http_retries"), sync.get("httpRetries", 3)),
            "httpRetryBackoff": _float_from_form(form.get("http_retry_backoff"), sync.get("httpRetryBackoff", 5.0)),
            "steamHttpRetries": _int_from_form(form.get("steam_http_retries"), sync.get("steamHttpRetries", 2)),
            "steamHttpBackoff": _float_from_form(form.get("steam_http_backoff"), sync.get("steamHttpBackoff", 2.0)),
            "steamRequestDelay": _float_from_form(form.get("steam_request_delay"), sync.get("steamRequestDelay", 1.0)),
            "logLevel": str(form.get("log_level", sync.get("logLevel", "INFO"))).strip() or "INFO",
            "runOnce": _bool_from_form(form.get("run_once")),
            "syncTags": _bool_from_form(form.get("sync_tags")),
            "pruneTags": _bool_from_form(form.get("prune_tags")),
            "syncDependencies": _bool_from_form(form.get("sync_dependencies")),
            "pruneDependencies": _bool_from_form(form.get("prune_dependencies")),
            "syncResources": _bool_from_form(form.get("sync_resources")),
            "pruneResources": _bool_from_form(form.get("prune_resources")),
            "uploadResourceFiles": _bool_from_form(form.get("upload_resource_files")),
            "scrapePreviewImages": _bool_from_form(form.get("scrape_preview_images")),
            "scrapeRequiredItems": _bool_from_form(form.get("scrape_required_items")),
            "maxScreenshots": _int_from_form(form.get("max_screenshots"), sync.get("maxScreenshots", 20)),
        }
    )
    raw_patch = _parse_sync_json(str(form.get("sync_json_patch") or form.get("sync_json") or "{}"))
    return deep_merge(sync, raw_patch)


def _validation_errors(
    *,
    name: str,
    steam_app_id: int,
    login: str,
    password: str,
    existing_password: str,
    runner_proxy_url: str,
    parser_proxy_pool: str,
    parser_storage_size: str,
    runner_storage_size: str,
    sync_json_patch: str,
) -> dict[str, str]:
    errors: dict[str, str] = {}
    if not name:
        errors["name"] = "Instance name is required"
    if steam_app_id <= 0:
        errors["steam_app_id"] = "Steam App ID must be greater than zero"
    if not login:
        errors["ow_login"] = "Open Workshop login is required"
    if not password and not existing_password:
        errors["ow_password"] = "Password is required for a new instance"
    if not runner_proxy_url:
        errors["runner_proxy_url"] = "Runner proxy URL is required"
    if not parser_storage_size:
        errors["parser_storage_size"] = "Parser PVC size is required"
    if not runner_storage_size:
        errors["runner_storage_size"] = "Runner PVC size is required"
    if sync_json_patch:
        try:
            _parse_sync_json(sync_json_patch)
        except Exception as exc:
            errors["sync_json_patch"] = str(exc)
    if parser_proxy_pool:
        try:
            _validate_proxy_pool(parser_proxy_pool)
        except Exception as exc:
            errors["parser_proxy_pool"] = str(exc)
    return errors


def _settings_form(
    settings: UISettings,
    context: dict[str, Any],
    *,
    return_path: str,
    embedded: bool,
) -> str:
    values = dict(context["values"])
    errors = dict(context["errors"])
    values["return_path"] = return_path
    title = values["name"] or "New instance"
    panel_title = "Create a new instance" if context["is_new"] else "Settings"
    panel_subtitle = (
        "Safe defaults are visible first. Advanced runtime tuning stays in Expert mode."
        if context["is_new"]
        else "Update the operational settings without digging through raw Kubernetes objects."
    )
    return render_template(
        "settings_form.html",
        shell_class="settings-shell embedded" if embedded else "settings-shell",
        eyebrow=_escape("Create Instance" if context["is_new"] else "Instance Settings"),
        heading=_escape(title if not context["is_new"] else panel_title),
        subtitle=_escape(panel_subtitle),
        action_url=_escape(_url(settings, "/instances/save")),
        original_name=_escape(values["original_name"]),
        return_path=_escape(values["return_path"]),
        name_invalid_class=_input_modifier(errors, "name"),
        name_value=_escape(values["name"]),
        name_error=_field_error(errors, "name"),
        enabled_checked=_checked_attr(values["enabled"]),
        enabled_hint=_field_hint("Disabled instances stay visible but will not sync."),
        enabled_error=_field_error(errors, "enabled"),
        steam_app_id_invalid_class=_input_modifier(errors, "steam_app_id"),
        steam_app_id_value=_escape(values["steam_app_id"]),
        steam_app_id_error=_field_error(errors, "steam_app_id"),
        ow_game_id_invalid_class=_input_modifier(errors, "ow_game_id"),
        ow_game_id_value=_escape(values["ow_game_id"]),
        ow_game_id_hint=_field_hint("Leave 0 to let the parser discover the Open Workshop game."),
        ow_game_id_error=_field_error(errors, "ow_game_id"),
        language_invalid_class=_input_modifier(errors, "language"),
        language_value=_escape(values["language"]),
        language_error=_field_error(errors, "language"),
        language_hint=_field_hint("Used for Steam-facing metadata fetches."),
        ow_login_invalid_class=_input_modifier(errors, "ow_login"),
        ow_login_value=_escape(values["ow_login"]),
        ow_login_error=_field_error(errors, "ow_login"),
        ow_password_invalid_class=_input_modifier(errors, "ow_password"),
        ow_password_error=_field_error(errors, "ow_password"),
        ow_password_hint=_field_hint("Leave empty to keep the current password."),
        runner_proxy_type_invalid_class=_input_modifier(errors, "runner_proxy_type"),
        runner_proxy_type_socks5_selected=_selected_attr(values["runner_proxy_type"], "socks5"),
        runner_proxy_type_http_selected=_selected_attr(values["runner_proxy_type"], "http"),
        runner_proxy_type_error=_field_error(errors, "runner_proxy_type"),
        runner_proxy_url_invalid_class=_input_modifier(errors, "runner_proxy_url"),
        runner_proxy_url_value=_escape(values["runner_proxy_url"]),
        runner_proxy_url_hint=_field_hint("Single upstream proxy used by the steamcmd runner through the TUN sidecar."),
        runner_proxy_url_error=_field_error(errors, "runner_proxy_url"),
        parser_proxy_pool_invalid_class=_input_modifier(errors, "parser_proxy_pool"),
        parser_proxy_pool_value=_escape(values["parser_proxy_pool"]),
        parser_proxy_pool_hint=_field_hint(
            "One proxy URL per line, or comma-separated. This pool is used only by parser HTTP requests."
        ),
        parser_proxy_pool_error=_field_error(errors, "parser_proxy_pool"),
        parser_storage_size_invalid_class=_input_modifier(errors, "parser_storage_size"),
        parser_storage_size_value=_escape(values["parser_storage_size"]),
        parser_storage_size_hint=_field_hint("Recommended: 10Gi to 20Gi for active mirrors."),
        parser_storage_size_error=_field_error(errors, "parser_storage_size"),
        runner_storage_size_invalid_class=_input_modifier(errors, "runner_storage_size"),
        runner_storage_size_value=_escape(values["runner_storage_size"]),
        runner_storage_size_hint=_field_hint("Recommended: 10Gi if workshop archives can grow quickly."),
        runner_storage_size_error=_field_error(errors, "runner_storage_size"),
        poll_interval_seconds_invalid_class=_input_modifier(errors, "poll_interval_seconds"),
        poll_interval_seconds_value=_escape(values["poll_interval_seconds"]),
        poll_interval_seconds_error=_field_error(errors, "poll_interval_seconds"),
        timeout_seconds_invalid_class=_input_modifier(errors, "timeout_seconds"),
        timeout_seconds_value=_escape(values["timeout_seconds"]),
        timeout_seconds_error=_field_error(errors, "timeout_seconds"),
        http_retries_invalid_class=_input_modifier(errors, "http_retries"),
        http_retries_value=_escape(values["http_retries"]),
        http_retries_error=_field_error(errors, "http_retries"),
        http_retry_backoff_invalid_class=_input_modifier(errors, "http_retry_backoff"),
        http_retry_backoff_value=_escape(values["http_retry_backoff"]),
        http_retry_backoff_error=_field_error(errors, "http_retry_backoff"),
        steam_http_retries_invalid_class=_input_modifier(errors, "steam_http_retries"),
        steam_http_retries_value=_escape(values["steam_http_retries"]),
        steam_http_retries_error=_field_error(errors, "steam_http_retries"),
        steam_http_backoff_invalid_class=_input_modifier(errors, "steam_http_backoff"),
        steam_http_backoff_value=_escape(values["steam_http_backoff"]),
        steam_http_backoff_error=_field_error(errors, "steam_http_backoff"),
        steam_request_delay_invalid_class=_input_modifier(errors, "steam_request_delay"),
        steam_request_delay_value=_escape(values["steam_request_delay"]),
        steam_request_delay_error=_field_error(errors, "steam_request_delay"),
        log_level_invalid_class=_input_modifier(errors, "log_level"),
        log_level_debug_selected=_selected_attr(values["log_level"], "DEBUG"),
        log_level_info_selected=_selected_attr(values["log_level"], "INFO"),
        log_level_warning_selected=_selected_attr(values["log_level"], "WARNING"),
        log_level_error_selected=_selected_attr(values["log_level"], "ERROR"),
        log_level_error=_field_error(errors, "log_level"),
        max_screenshots_invalid_class=_input_modifier(errors, "max_screenshots"),
        max_screenshots_value=_escape(values["max_screenshots"]),
        max_screenshots_error=_field_error(errors, "max_screenshots"),
        run_once_checked=_checked_attr(values["run_once"]),
        run_once_error=_field_error(errors, "run_once"),
        sync_tags_checked=_checked_attr(values["sync_tags"]),
        sync_tags_error=_field_error(errors, "sync_tags"),
        prune_tags_checked=_checked_attr(values["prune_tags"]),
        prune_tags_error=_field_error(errors, "prune_tags"),
        sync_dependencies_checked=_checked_attr(values["sync_dependencies"]),
        sync_dependencies_error=_field_error(errors, "sync_dependencies"),
        prune_dependencies_checked=_checked_attr(values["prune_dependencies"]),
        prune_dependencies_error=_field_error(errors, "prune_dependencies"),
        sync_resources_checked=_checked_attr(values["sync_resources"]),
        sync_resources_error=_field_error(errors, "sync_resources"),
        prune_resources_checked=_checked_attr(values["prune_resources"]),
        prune_resources_error=_field_error(errors, "prune_resources"),
        upload_resource_files_checked=_checked_attr(values["upload_resource_files"]),
        upload_resource_files_error=_field_error(errors, "upload_resource_files"),
        scrape_preview_images_checked=_checked_attr(values["scrape_preview_images"]),
        scrape_preview_images_error=_field_error(errors, "scrape_preview_images"),
        scrape_required_items_checked=_checked_attr(values["scrape_required_items"]),
        scrape_required_items_error=_field_error(errors, "scrape_required_items"),
        sync_json_patch_invalid_class=_input_modifier(errors, "sync_json_patch"),
        sync_json_patch_value=_escape(values["sync_json_patch"]),
        sync_json_patch_hint=_field_hint(
            "Optional JSON patch merged on top of the structured controls. Use this for less common sync fields without losing the safe defaults above."
        ),
        sync_json_patch_error=_field_error(errors, "sync_json_patch"),
        back_url=_escape(_url(settings, return_path)),
        back_label=_escape("Back to dashboard" if context["is_new"] else "Cancel"),
    )
