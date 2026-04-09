from __future__ import annotations

import json
from typing import Any

from core.instance_schema import (
    build_sync_spec_from_form,
    default_spec,
    sync_form_minimum,
    sync_form_values,
    validate_sync_form_inputs,
)
from core.http_utils import parse_proxy_url, validate_proxy_url
from kube.kube_client import read_secret_value
from kube.mirror_instance import instance_name, normalize_instance
from ui.ui_assets import render_template
from ui.ui_common import (
    UISettings,
    _bool_from_form,
    _escape,
    _url,
)


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
        normalized = {"spec": default_spec(), "metadata": {"name": ""}}
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
        "parser_storage_size": spec["storage"]["parser"]["size"],
        "runner_storage_size": spec["storage"]["runner"]["size"],
        "ow_login": login,
        "ow_password": "",
        "runner_proxy_type": spec["steamcmd"]["proxy"].get("type", "socks5"),
        "runner_proxy_url": runner_proxy_url,
        "parser_proxy_pool": parser_proxy_pool,
        "sync_json_patch": sync_patch_value or "",
        "return_path": "",
        "existing_password": existing_password,
    }
    values.update(sync_form_values(sync_spec))
    if form_data is not None:
        bool_fields = {
            "enabled",
            "run_once",
            "log_steam_requests",
            "sync_tags",
            "prune_tags",
            "sync_dependencies",
            "prune_dependencies",
            "sync_resources",
            "prune_resources",
            "upload_resource_files",
            "scrape_preview_images",
            "scrape_required_items",
            "without_author",
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
    raw_patch = _parse_sync_json(str(form.get("sync_json_patch") or form.get("sync_json") or "{}"))
    return build_sync_spec_from_form(base_sync, form, raw_patch)


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
    sync_form_data: dict[str, Any],
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
    sync_errors = validate_sync_form_inputs(sync_form_data)
    for field_name, message in sync_errors.items():
        if message:
            errors[field_name] = message
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
        api_base_invalid_class=_input_modifier(errors, "api_base"),
        api_base_value=_escape(values["api_base"]),
        api_base_error=_field_error(errors, "api_base"),
        page_size_min=_escape(sync_form_minimum("page_size")),
        page_size_invalid_class=_input_modifier(errors, "page_size"),
        page_size_value=_escape(values["page_size"]),
        page_size_error=_field_error(errors, "page_size"),
        poll_interval_seconds_min=_escape(sync_form_minimum("poll_interval_seconds")),
        poll_interval_seconds_invalid_class=_input_modifier(errors, "poll_interval_seconds"),
        poll_interval_seconds_value=_escape(values["poll_interval_seconds"]),
        poll_interval_seconds_error=_field_error(errors, "poll_interval_seconds"),
        timeout_seconds_min=_escape(sync_form_minimum("timeout_seconds")),
        timeout_seconds_invalid_class=_input_modifier(errors, "timeout_seconds"),
        timeout_seconds_value=_escape(values["timeout_seconds"]),
        timeout_seconds_error=_field_error(errors, "timeout_seconds"),
        http_retries_min=_escape(sync_form_minimum("http_retries")),
        http_retries_invalid_class=_input_modifier(errors, "http_retries"),
        http_retries_value=_escape(values["http_retries"]),
        http_retries_error=_field_error(errors, "http_retries"),
        http_retry_backoff_min=_escape(sync_form_minimum("http_retry_backoff")),
        http_retry_backoff_invalid_class=_input_modifier(errors, "http_retry_backoff"),
        http_retry_backoff_value=_escape(values["http_retry_backoff"]),
        http_retry_backoff_error=_field_error(errors, "http_retry_backoff"),
        steam_http_retries_min=_escape(sync_form_minimum("steam_http_retries")),
        steam_http_retries_invalid_class=_input_modifier(errors, "steam_http_retries"),
        steam_http_retries_value=_escape(values["steam_http_retries"]),
        steam_http_retries_error=_field_error(errors, "steam_http_retries"),
        steam_http_backoff_min=_escape(sync_form_minimum("steam_http_backoff")),
        steam_http_backoff_invalid_class=_input_modifier(errors, "steam_http_backoff"),
        steam_http_backoff_value=_escape(values["steam_http_backoff"]),
        steam_http_backoff_error=_field_error(errors, "steam_http_backoff"),
        steam_request_delay_min=_escape(sync_form_minimum("steam_request_delay")),
        steam_request_delay_invalid_class=_input_modifier(errors, "steam_request_delay"),
        steam_request_delay_value=_escape(values["steam_request_delay"]),
        steam_request_delay_error=_field_error(errors, "steam_request_delay"),
        steam_max_pages_min=_escape(sync_form_minimum("steam_max_pages")),
        steam_max_pages_invalid_class=_input_modifier(errors, "steam_max_pages"),
        steam_max_pages_value=_escape(values["steam_max_pages"]),
        steam_max_pages_error=_field_error(errors, "steam_max_pages"),
        steam_start_page_min=_escape(sync_form_minimum("steam_start_page")),
        steam_start_page_invalid_class=_input_modifier(errors, "steam_start_page"),
        steam_start_page_value=_escape(values["steam_start_page"]),
        steam_start_page_error=_field_error(errors, "steam_start_page"),
        steam_max_items_min=_escape(sync_form_minimum("steam_max_items")),
        steam_max_items_invalid_class=_input_modifier(errors, "steam_max_items"),
        steam_max_items_value=_escape(values["steam_max_items"]),
        steam_max_items_error=_field_error(errors, "steam_max_items"),
        steam_delay_min=_escape(sync_form_minimum("steam_delay")),
        steam_delay_invalid_class=_input_modifier(errors, "steam_delay"),
        steam_delay_value=_escape(values["steam_delay"]),
        steam_delay_error=_field_error(errors, "steam_delay"),
        log_level_invalid_class=_input_modifier(errors, "log_level"),
        log_level_debug_selected=_selected_attr(values["log_level"], "DEBUG"),
        log_level_info_selected=_selected_attr(values["log_level"], "INFO"),
        log_level_warning_selected=_selected_attr(values["log_level"], "WARNING"),
        log_level_error_selected=_selected_attr(values["log_level"], "ERROR"),
        log_level_error=_field_error(errors, "log_level"),
        public_mode_invalid_class=_input_modifier(errors, "public_mode"),
        public_mode_value=_escape(values["public_mode"]),
        public_mode_error=_field_error(errors, "public_mode"),
        force_required_item_id_invalid_class=_input_modifier(errors, "force_required_item_id"),
        force_required_item_id_value=_escape(values["force_required_item_id"]),
        force_required_item_id_error=_field_error(errors, "force_required_item_id"),
        max_screenshots_min=_escape(sync_form_minimum("max_screenshots")),
        max_screenshots_invalid_class=_input_modifier(errors, "max_screenshots"),
        max_screenshots_value=_escape(values["max_screenshots"]),
        max_screenshots_error=_field_error(errors, "max_screenshots"),
        run_once_checked=_checked_attr(values["run_once"]),
        run_once_error=_field_error(errors, "run_once"),
        log_steam_requests_checked=_checked_attr(values["log_steam_requests"]),
        log_steam_requests_error=_field_error(errors, "log_steam_requests"),
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
        without_author_checked=_checked_attr(values["without_author"]),
        without_author_error=_field_error(errors, "without_author"),
        sync_json_patch_invalid_class=_input_modifier(errors, "sync_json_patch"),
        sync_json_patch_value=_escape(values["sync_json_patch"]),
        sync_json_patch_hint=_field_hint(
            "Optional JSON patch merged on top of the structured controls. Use this for less common sync fields without losing the safe defaults above."
        ),
        sync_json_patch_error=_field_error(errors, "sync_json_patch"),
        back_url=_escape(_url(settings, return_path)),
        back_label=_escape("Back to dashboard" if context["is_new"] else "Cancel"),
    )
