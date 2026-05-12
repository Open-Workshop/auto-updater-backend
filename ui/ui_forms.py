from __future__ import annotations

import json
from typing import Any

from core.instance_schema import (
    MirrorInstanceSpecModel,
    build_sync_spec_from_form,
    default_spec,
    default_parser_type,
    get_parser_contract,
    parser_config_form_values,
    parser_workload_form_values,
    parser_type_options,
    sync_form_values,
    validate_parser_config_form_inputs,
    validate_parser_workload_form_inputs,
)
from core.http_utils import parse_proxy_url, validate_proxy_url
from kubernetes.client.rest import ApiException
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


def _runner_proxy_type_from_form(contract: Any, form: dict[str, Any]) -> str:
    runner_workload = contract.workload_for_mode("runner")
    if runner_workload is not None:
        for field in runner_workload.config_fields:
            if field.form_field in {"runner_proxy_type", "proxy_type"} or field.key == "proxyType":
                rendered = str(form.get(field.form_field) or field.default or "socks5").strip()
                return rendered or "socks5"
    return str(form.get("runner_proxy_type", "socks5")).strip() or "socks5"


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


def _error_summary(errors: dict[str, str]) -> str:
    items = []
    for field_name, message in errors.items():
        rendered = str(message or "").strip()
        if not rendered:
            continue
        items.append(f"<li><strong>{_escape(field_name)}</strong>: {_escape(rendered)}</li>")
    if not items:
        return ""
    return "<section class='flash error'><strong>Save failed.</strong><ul>" + "".join(items) + "</ul></section>"


def _checked_attr(value: Any) -> str:
    return "checked" if bool(value) else ""


def _selected_attr(value: Any, expected: str) -> str:
    return "selected" if str(value) == expected else ""


def _render_text_input(
    *,
    name: str,
    label: str,
    value: Any,
    error: str = "",
    hint: str = "",
    input_type: str = "text",
    required: bool = False,
    minimum: str = "",
    step: str = "",
    options: tuple[tuple[str, str], ...] = (),
) -> str:
    error_html = _field_error({name: error} if error else {}, name)
    hint_html = _field_hint(hint)
    input_class = _input_modifier({name: error} if error else {}, name)
    if options:
        options_html = "".join(
            f"<option value='{_escape(option_value)}' {_selected_attr(value, option_value)}>{_escape(option_label)}</option>"
            for option_value, option_label in options
        )
        return (
            f"<label><span>{_escape(label)}</span>"
            f"<select class=\"input{input_class}\" name=\"{_escape(name)}\""
            f"{' required' if required else ''}>"
            f"{options_html}</select>"
            f"{hint_html}{error_html}</label>"
        )
    attrs = []
    if minimum:
        attrs.append(f'min="{_escape(minimum)}"')
    if step:
        attrs.append(f'step="{_escape(step)}"')
    if required:
        attrs.append("required")
    return (
        f"<label><span>{_escape(label)}</span>"
        f"<input class=\"input{input_class}\" type=\"{_escape(input_type)}\" name=\"{_escape(name)}\" "
        f"value=\"{_escape(value)}\" {' '.join(attrs)}>"
        f"{hint_html}{error_html}</label>"
    )


def _render_textarea_input(
    *,
    name: str,
    label: str,
    value: Any,
    error: str = "",
    hint: str = "",
    required: bool = False,
    rows: int = 4,
) -> str:
    error_html = _field_error({name: error} if error else {}, name)
    hint_html = _field_hint(hint)
    input_class = _input_modifier({name: error} if error else {}, name)
    required_attr = " required" if required else ""
    return (
        f"<label><span>{_escape(label)}</span>"
        f"<textarea class=\"input{input_class}\" name=\"{_escape(name)}\" rows=\"{rows}\"{required_attr}>"
        f"{_escape(value)}</textarea>"
        f"{hint_html}{error_html}</label>"
    )


def _render_toggle_input(
    *,
    name: str,
    label: str,
    value: Any,
    error: str = "",
    hint: str = "",
) -> str:
    error_html = _field_error({name: error} if error else {}, name)
    hint_html = _field_hint(hint)
    return (
        "<label class='toggle-field'>"
        "<span class='toggle'>"
        f"<input type='checkbox' name='{_escape(name)}' {_checked_attr(value)}>"
        f"<span>{_escape(label)}</span>"
        "</span>"
        f"{hint_html}{error_html}</label>"
    )


def _render_config_field(field: Any, value: Any, error: str = "") -> str:
    label = getattr(field, "label", getattr(field, "key", "Field"))
    name = str(getattr(field, "form_field", "") or getattr(field, "key", ""))
    hint = str(getattr(field, "hint", "") or "")
    input_type = str(getattr(field, "value_type", "str") or "str")
    options = tuple(getattr(field, "options", ()) or ())
    if input_type == "bool":
        return _render_toggle_input(name=name, label=label, value=value, error=error, hint=hint)
    if options:
        return _render_text_input(
            name=name,
            label=label,
            value=value,
            error=error,
            hint=hint,
            input_type="text",
            options=options,
        )
    if input_type in {"int", "float"}:
        return _render_text_input(
            name=name,
            label=label,
            value=value,
            error=error,
            hint=hint,
            input_type="number",
            minimum=str(getattr(field, "minimum", "") or ""),
            step=str(getattr(field, "step", "") or ""),
            required=bool(getattr(field, "required", True)),
        )
    return _render_text_input(
        name=name,
        label=label,
        value=value,
        error=error,
        hint=hint,
        required=bool(getattr(field, "required", True)),
    )


def _render_secret_field(spec: Any, value: Any, error: str = "") -> str:
    name = str(getattr(spec, "form_field", "") or "")
    label = str(getattr(spec, "label", name) or name)
    hint = str(getattr(spec, "hint", "") or "")
    input_type = str(getattr(spec, "input_type", "textarea") or "textarea")
    required = bool(getattr(spec, "required", False))
    if input_type == "textarea":
        return _render_textarea_input(
            name=name,
            label=label,
            value=value,
            error=error,
            hint=hint,
            required=required,
            rows=4,
        )
    return _render_text_input(
        name=name,
        label=label,
        value=value,
        error=error,
        hint=hint,
        input_type="text",
        required=required,
    )


def _render_storage_field(workload: Any, value: Any, error: str = "") -> str:
    name = str(getattr(workload, "storage_form_field", "") or "")
    label = str(getattr(workload, "storage_label", "") or name)
    hint = "Storage size is required."
    return _render_text_input(
        name=name,
        label=label,
        value=value,
        error=error,
        hint=hint,
        input_type="text",
        required=True,
    )


def _panel_section(title: str, body_html: str, *, open_attr: str = "", details: bool = False) -> str:
    if details:
        return (
            f"<details class=\"panel-section expert-panel\"{open_attr}>"
            f"<summary>{_escape(title)}</summary>"
            f"{body_html}"
            "</details>"
        )
    return (
        "<section class='panel-section'>"
        f"<div class='section-title'>{_escape(title)}</div>"
        f"{body_html}"
        "</section>"
    )


def _field_grid(fields_html: list[str]) -> str:
    if not fields_html:
        return ""
    return "<div class='field-grid'>" + "".join(fields_html) + "</div>"


def _toggle_grid(fields_html: list[str]) -> str:
    if not fields_html:
        return ""
    return "<div class='toggle-grid'>" + "".join(fields_html) + "</div>"


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
        model = MirrorInstanceSpecModel.from_spec_dict(default_spec())
        login = ""
        existing_password = ""
        secret_values: dict[str, Any] = {}
    else:
        normalized = normalize_instance(instance)
        model = MirrorInstanceSpecModel.from_instance_dict(instance)
        name = instance_name(instance)
        credentials_secret = model.credentials_secret_ref
        try:
            login = read_secret_value(settings.namespace, credentials_secret, "login")
        except (ApiException, KeyError, ValueError):
            login = ""
        try:
            existing_password = read_secret_value(settings.namespace, credentials_secret, "password")
        except (ApiException, KeyError, ValueError):
            existing_password = ""
        secret_values = {}
        normalized["metadata"]["name"] = name
    rendered_parser_type = model.parser_type
    if form_data is not None:
        candidate_parser_type = str(form_data.get("parser_type") or rendered_parser_type).strip()
        if candidate_parser_type:
            rendered_parser_type = candidate_parser_type
    try:
        contract = get_parser_contract(rendered_parser_type)
    except KeyError:
        contract = get_parser_contract(model.parser_type)
        rendered_parser_type = model.parser_type
    if instance is not None:
        for spec in contract.secret_specs:
            secret_ref = str(model.parser_secret_refs.get(spec.key) or "").strip()
            if not secret_ref:
                secret_values[spec.form_field] = ""
                continue
            try:
                secret_values[spec.form_field] = read_secret_value(
                    settings.namespace,
                    secret_ref,
                    spec.secret_data_key,
                )
            except (ApiException, KeyError, ValueError):
                secret_values[spec.form_field] = ""
    else:
        secret_values = {spec.form_field: "" for spec in contract.secret_specs}
    sync_spec = dict(model.sync)
    values = {
        "original_name": normalized.get("metadata", {}).get("name", ""),
        "name": normalized.get("metadata", {}).get("name", ""),
        "enabled": bool(model.enabled),
        "parser_type": rendered_parser_type,
        "ow_login": login,
        "ow_password": "",
        "existing_password": existing_password,
        "sync_json_patch": sync_patch_value or "",
        "return_path": "",
    }
    values.update(parser_config_form_values(rendered_parser_type, model.parser_config))
    if rendered_parser_type == default_parser_type():
        values.update(sync_form_values(sync_spec))
    values.update(secret_values)
    values.update(parser_workload_form_values(rendered_parser_type, model.parser_workloads))
    if form_data is not None:
        bool_fields = {"enabled"}
        for field in contract.config_fields:
            if field.form_field and field.input_type() == "checkbox":
                bool_fields.add(field.form_field)
        for workload in contract.workloads:
            for field in workload.config_fields:
                if field.form_field and field.input_type() == "checkbox":
                    bool_fields.add(field.form_field)
        for key in values:
            if key == "existing_password":
                continue
            if key in bool_fields:
                values[key] = _bool_from_form(form_data.get(key))
            else:
                values[key] = form_data.get(key, values[key])
        values["parser_type"] = rendered_parser_type
    return {
        "instance": instance,
        "is_new": instance is None,
        "contract": contract,
        "values": values,
        "errors": errors,
        "raw_sync": sync_spec,
    }


def _has_expert_errors(contract: Any, errors: dict[str, str]) -> bool:
    if not errors:
        return False
    expert_fields = {
        field.form_field
        for field in contract.config_fields
        if field.form_field and field.ui_section in {"advanced", "toggle"}
    }
    expert_fields.add("sync_json_patch")
    return any(field_name in expert_fields for field_name in errors)


def _build_sync_spec(base_sync: dict[str, Any], form: dict[str, Any]) -> dict[str, Any]:
    raw_patch = _parse_sync_json(str(form.get("sync_json_patch") or form.get("sync_json") or "{}"))
    return build_sync_spec_from_form(base_sync, form, raw_patch)


def _validation_errors(
    *,
    name: str,
    login: str,
    password: str,
    existing_password: str,
    parser_type: str,
    form: dict[str, Any],
    sync_json_patch: str,
) -> dict[str, str]:
    errors: dict[str, str] = {}
    if not name:
        errors["name"] = "Instance name is required"
    if not login:
        errors["ow_login"] = "Open Workshop login is required"
    if not password and not existing_password:
        errors["ow_password"] = "Password is required for a new instance"
    try:
        contract = get_parser_contract(parser_type)
    except KeyError as exc:
        errors["parser_type"] = str(exc)
        return errors
    if sync_json_patch:
        try:
            _parse_sync_json(sync_json_patch)
        except ValueError as exc:
            errors["sync_json_patch"] = str(exc)
    errors.update(validate_parser_config_form_inputs(parser_type, form))
    errors.update(validate_parser_workload_form_inputs(parser_type, form))
    for spec in contract.secret_specs:
        raw_value = str(form.get(spec.form_field) or "").strip()
        if not raw_value:
            if spec.required:
                errors[spec.form_field] = f"{spec.label} is required"
            continue
        if spec.validator == "proxy-pool":
            try:
                _validate_proxy_pool(raw_value)
            except ValueError as exc:
                errors[spec.form_field] = str(exc)
        elif spec.validator == "proxy-url":
            try:
                proxy_type = _runner_proxy_type_from_form(contract, form)
                _validate_runner_proxy(raw_value, proxy_type)
            except ValueError as exc:
                errors[spec.form_field] = str(exc)
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
    contract = context["contract"]
    values["return_path"] = return_path
    title = values["name"] or "New instance"
    panel_title = "Create a new instance" if context["is_new"] else "Settings"
    panel_subtitle = (
        "Safe defaults are visible first. Advanced runtime tuning stays in Expert mode."
        if context["is_new"]
        else "Update the operational settings without digging through raw Kubernetes objects."
    )
    basic_fields = [
        _render_text_input(
            name="name",
            label="Instance name",
            value=values["name"],
            error=errors.get("name", ""),
            required=True,
        ),
        _render_toggle_input(
            name="enabled",
            label="Enabled",
            value=values["enabled"],
            error=errors.get("enabled", ""),
            hint="Disabled instances stay visible but will not sync.",
        ),
        _render_text_input(
            name="parser_type",
            label="Parser type",
            value=values["parser_type"],
            error=errors.get("parser_type", ""),
            required=True,
            options=tuple(parser_type_options()),
        ),
    ]
    for field in contract.config_fields_in_section("basic"):
        if field.form_field is None:
            continue
        basic_fields.append(
            _render_config_field(field, values.get(field.form_field, ""), errors.get(field.form_field, ""))
        )

    connectivity_fields = [
        _render_text_input(
            name="ow_login",
            label="Open Workshop login",
            value=values["ow_login"],
            error=errors.get("ow_login", ""),
            required=True,
        ),
        _render_text_input(
            name="ow_password",
            label="Open Workshop password",
            value="",
            error=errors.get("ow_password", ""),
            input_type="password",
            hint="Leave empty to keep the current password.",
        ),
    ]
    for spec in contract.secret_specs:
        connectivity_fields.append(
            _render_secret_field(spec, values.get(spec.form_field, ""), errors.get(spec.form_field, ""))
        )

    workload_cards: list[str] = []
    for workload in contract.workloads:
        workload_fields: list[str] = []
        if workload.storage_form_field:
            workload_fields.append(
                _render_storage_field(
                    workload,
                    values.get(workload.storage_form_field, ""),
                    errors.get(workload.storage_form_field, ""),
                )
            )
        for field in workload.config_fields:
            if field.form_field is None:
                continue
            workload_fields.append(
                _render_config_field(field, values.get(field.form_field, ""), errors.get(field.form_field, ""))
            )
        workload_body = _field_grid(workload_fields)
        workload_cards.append(_panel_section(workload.display_label, workload_body))
    workloads_body = (
        "<div class='workload-stack'>" + "".join(workload_cards) + "</div>"
        if workload_cards
        else "<div class='empty-state'>No workloads are defined for this parser type.</div>"
    )

    advanced_fields = [
        _render_config_field(field, values.get(field.form_field, ""), errors.get(field.form_field, ""))
        for field in contract.config_fields_in_section("advanced")
        if field.form_field
    ]
    toggle_fields = [
        _render_config_field(field, values.get(field.form_field, ""), errors.get(field.form_field, ""))
        for field in contract.config_fields_in_section("toggle")
        if field.form_field
    ]
    expert_body = []
    if advanced_fields:
        expert_body.append(
            "<div class='section-title'>Structured runtime tuning</div>"
            + _field_grid(advanced_fields)
        )
    if toggle_fields:
        expert_body.append(
            "<div class='section-title'>Feature toggles</div>"
            + _toggle_grid(toggle_fields)
        )
    expert_body.append(
        "<div class='section-title'>Raw sync JSON merge</div>"
        + _render_textarea_input(
            name="sync_json_patch",
            label="Raw sync JSON merge",
            value=values["sync_json_patch"],
            error=errors.get("sync_json_patch", ""),
            hint="Optional JSON patch merged on top of the structured controls. Use this for less common settings without losing the safe defaults above.",
            rows=6,
        )
    )

    sections_html = "".join(
        [
            _panel_section("Basics", _field_grid(basic_fields)),
            _panel_section("Connectivity", _field_grid(connectivity_fields)),
            _panel_section("Workloads", workloads_body),
            _panel_section(
                "Expert mode",
                "<div class='expert-body'>" + "".join(expert_body) + "</div>",
                open_attr=" open" if _has_expert_errors(contract, errors) else "",
                details=True,
            ),
        ]
    )
    return render_template(
        "settings_form.html",
        shell_class="settings-shell embedded" if embedded else "settings-shell",
        eyebrow=_escape("Create Instance" if context["is_new"] else "Instance Settings"),
        heading=_escape(title if not context["is_new"] else panel_title),
        subtitle=_escape(panel_subtitle),
        action_url=_escape(_url(settings, "/instances/save")),
        error_summary_html=_error_summary(errors),
        original_name=_escape(values["original_name"]),
        return_path=_escape(values["return_path"]),
        sections_html=sections_html,
        back_url=_escape(_url(settings, return_path)),
        back_label=_escape("Back to dashboard" if context["is_new"] else "Cancel"),
    )
