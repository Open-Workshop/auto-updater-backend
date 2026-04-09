from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from ui.ui_assets import render_template
from ui.ui_common import UISettings, _escape, _json_dump_default, _json_script, _url
from ui.ui_forms import _settings_form
from ui.ui_shell import _layout


def _component_label(target: str) -> str:
    normalized = str(target or "").strip().lower()
    if normalized == "parser":
        return "Parser"
    if normalized == "runner":
        return "Runner"
    if normalized == "tun":
        return "TUN"
    return normalized.title()


def _summary_metric(label: str, value: Any, tone: str = "muted") -> str:
    return f"""
    <section class="metric-card tone-{_escape(tone)}">
      <div class="metric-label">{_escape(label)}</div>
      <div class="metric-value">{_escape(value)}</div>
    </section>
    """


def _action_form(
    *,
    action: str,
    label: str,
    button_class: str = "",
    confirm: str = "",
    return_path: str = "/",
) -> str:
    classes = f"button {button_class}".strip()
    form_attrs = " data-async='true'" if action else ""
    if confirm:
        form_attrs += f" data-confirm=\"{_escape(confirm)}\""
    return f"""
    <form class="inline-form" method="post" action="{_escape(action)}"{form_attrs}>
      <input type="hidden" name="return_path" value="{_escape(return_path)}">
      <button type="submit" class="{classes}">{_escape(label)}</button>
    </form>
    """


def _instance_actions(settings: UISettings, summary: dict[str, Any], *, return_path: str) -> str:
    name = summary["name"]
    toggle_label = "Pause" if summary["enabled"] else "Resume"
    urls = summary["urls"]
    return "".join(
        [
            f"<a class='button secondary' href='{_escape(urls['detail'])}'>Open</a>",
            f"<a class='button secondary' href='{_escape(urls['logs'])}'>Logs</a>",
            _action_form(
                action=urls["sync"],
                label="Sync now",
                confirm=f"Trigger sync now for {name}?",
                return_path=return_path,
            ),
            _action_form(
                action=urls["toggle"],
                label=toggle_label,
                button_class="secondary",
                confirm=f"{toggle_label} {name}?",
                return_path=return_path,
            ),
            _action_form(
                action=urls["delete"],
                label="Delete",
                button_class="warn",
                confirm=f"Delete {name}? This also removes the managed secrets.",
                return_path=return_path,
            ),
        ]
    )


def _resource_label(resources: dict[str, Any], key: str, fallback: str = "n/a") -> str:
    value = str(resources.get(key) or "").strip()
    return value or fallback


def _resource_cell(item: dict[str, Any]) -> str:
    total = dict(item.get("resources") or {})
    workload_lines = "".join(
        f"<div class='resource-detail'>{_escape(str(workload.get('label') or workload.get('id') or 'Workload'))} · "
        f"{_escape(_resource_label(dict(workload.get('resources') or {}), 'cpuLabel'))} · "
        f"{_escape(_resource_label(dict(workload.get('resources') or {}), 'memoryLabel'))} · "
        f"{_escape(_resource_label(dict(workload.get('resources') or {}), 'diskLabel'))}</div>"
        for workload in list(item.get("workloads") or [])
    )
    return f"""
    <div class="resource-stack">
      <div class="resource-summary">
        <span class="resource-chip">CPU {_escape(_resource_label(total, "cpuLabel"))}</span>
        <span class="resource-chip">RAM {_escape(_resource_label(total, "memoryLabel"))}</span>
        <span class="resource-chip">Disk {_escape(_resource_label(total, "diskLabel"))}</span>
      </div>
      {workload_lines}
    </div>
    """


def _workloads_cell(item: dict[str, Any]) -> str:
    parts = []
    for workload in list(item.get("workloads") or []):
        parts.append(
            f"""
            <div class="workload-line">
              <span class="pill tone-{_escape(workload.get('tone') or 'muted')}">{_escape(workload.get('label') or workload.get('id') or 'Workload')} · {_escape(workload.get('state') or 'Unknown')}</span>
              <div class="cell-subtle">{_escape(workload.get('podName') or 'n/a')}</div>
            </div>
            """
        )
    return "".join(parts) or "<div class='cell-subtle'>n/a</div>"


def _dashboard_rows(settings: UISettings, items: list[dict[str, Any]]) -> str:
    rows = []
    for item in items:
        rows.append(
            f"""
            <tr data-health="{_escape(item['health'])}" data-sync-state="{_escape(item['syncState'])}" data-instance="{_escape(item['name'])}">
              <td>
                <div class="primary-cell">
                  <a class="row-link" href="{_escape(item['urls']['detail'])}">{_escape(item['name'])}</a>
                  <div class="cell-subtle">{_escape(item.get('parserLabel') or '')} · {_escape(item.get('sourceSubtitle') or '')}</div>
                </div>
              </td>
              <td><span class="pill tone-{'healthy' if item['enabled'] else 'muted'}">{'Enabled' if item['enabled'] else 'Paused'}</span></td>
              <td><span class="pill tone-{_escape(item['healthTone'])}">{_escape(item['health'])}</span></td>
              <td><span class="pill tone-{_sync_state_tone(item['syncState'])}">{_escape(item['syncState'])}</span></td>
              <td>{_escape(item['lastSyncLabel'])}</td>
              <td class="error-cell">{_escape(item['errorSummary'])}</td>
              <td>{_workloads_cell(item)}</td>
              <td>{_resource_cell(item)}</td>
              <td class="actions-cell">{_instance_actions(settings, item, return_path='/')}</td>
            </tr>
            """
        )
    return "".join(rows)


def _dashboard_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"All": len(items), "Healthy": 0, "Running": 0, "Degraded": 0, "Error": 0, "Disabled": 0}
    for item in items:
        health = str(item.get("health") or "")
        if health in counts:
            counts[health] += 1
        if str(item.get("syncState") or "") == "Running":
            counts["Running"] += 1
    return counts


def _sync_state_tone(sync_state: str) -> str:
    if sync_state == "Running":
        return "info"
    if sync_state == "Succeeded":
        return "healthy"
    if sync_state == "Failed":
        return "warning"
    return "muted"


def _dashboard(
    settings: UISettings,
    items: list[dict[str, Any]],
    flash: str,
    flash_kind: str,
    resource_totals: dict[str, Any],
) -> str:
    counts = _dashboard_counts(items)
    body = render_template(
        "dashboard.html",
        title=_escape(settings.title),
        subtitle=_escape(
            "Fast operational view of all mirror instances, with filters, live actions, and quick access to logs and investigations."
        ),
        new_instance_url=_escape(_url(settings, "/instances/new")),
        metrics_html="".join(
            [
                _summary_metric("All instances", counts["All"], "muted"),
                _summary_metric("Healthy", counts["Healthy"], "healthy"),
                _summary_metric("Running sync", counts["Running"], "info"),
                _summary_metric("Degraded", counts["Degraded"], "warning"),
                _summary_metric("Error", counts["Error"], "error"),
                _summary_metric("Paused", counts["Disabled"], "muted"),
                _summary_metric("CPU live", _resource_label(resource_totals, "cpuLabel"), "info"),
                _summary_metric("Memory live", _resource_label(resource_totals, "memoryLabel"), "info"),
                _summary_metric("Disk cap / used / req", _resource_label(resource_totals, "diskLabel"), "muted"),
            ]
        ),
        rows_html=_dashboard_rows(settings, items),
        dashboard_payload_json=_json_script({"items": items, "counts": counts, "resources": resource_totals}),
        dashboard_config_json=_json_script({"apiUrl": _url(settings, "/api/instances")}),
        dashboard_js_href=_escape(_url(settings, "/assets/dashboard.js")),
    )
    return _layout(settings, body, flash=flash, flash_kind=flash_kind, page_title=settings.title)


def _tab_link(settings: UISettings, summary: dict[str, Any], tab: str, active_tab: str, label: str, extra_query: str = "") -> str:
    active = "active" if active_tab == tab else ""
    href = summary["urls"]["detail"] + f"?tab={tab}{extra_query}"
    return f"<a class='tab-link {active}' href='{_escape(href)}'>{_escape(label)}</a>"


def _overview_tab(settings: UISettings, summary: dict[str, Any], return_path: str) -> str:
    error_block = (
        f"<section class='notice notice-error'><strong>Last error</strong><div>{_escape(summary['lastError'])}</div></section>"
        if summary["lastError"]
        else ""
    )
    overview_pairs_html = "".join(
        f"<div><span class='meta-label'>{_escape(label)}</span><strong>{_escape(value)}</strong></div>"
        for label, value in list(summary.get("overviewPairs") or [])
    )
    workloads_html = "".join(
        f"""
        <section class="panel-section">
          <div class="section-title">{_escape(workload.get('label') or workload.get('id') or 'Workload')}</div>
          <div class="meta-grid">
            <div><span class="meta-label">Pod</span><strong>{_escape(workload.get('podName') or 'n/a')}</strong></div>
            <div><span class="meta-label">Status</span><span class="pill tone-{_escape(workload.get('tone') or 'muted')}">{_escape(workload.get('state') or 'Unknown')}</span></div>
            <div><span class="meta-label">Image</span><code>{_escape(workload.get('image') or 'n/a')}</code></div>
            <div><span class="meta-label">Service</span><code>{_escape(workload.get('serviceName') or 'n/a')}</code></div>
          </div>
        </section>
        """
        for workload in list(summary.get("workloads") or [])
    )
    return render_template(
        "overview_tab.html",
        health_metric=_summary_metric("Health", summary["health"], summary["healthTone"]),
        sync_metric=_summary_metric("Sync state", summary["syncState"], _sync_state_tone(summary["syncState"])),
        last_sync_metric=_summary_metric("Last sync", summary["lastSyncLabel"], "muted"),
        enabled_metric=_summary_metric("Enabled", "Yes" if summary["enabled"] else "No", "healthy" if summary["enabled"] else "muted"),
        error_block=error_block,
        phase=_escape(summary["phase"]),
        parser_label=_escape(summary.get("parserLabel") or ""),
        parser_type=_escape(summary.get("parserType") or ""),
        overview_pairs_html=overview_pairs_html,
        workloads_html=workloads_html,
        actions_html=_instance_actions(settings, summary, return_path=return_path),
        conditions_json=_escape(json.dumps(summary["conditions"], ensure_ascii=False, indent=2, sort_keys=True)),
    )


def _logs_tab(
    settings: UISettings,
    summary: dict[str, Any],
    target: str,
    log_tag: str,
    tail_lines: int,
) -> str:
    normalized_target = str(target or "parser").strip().lower() or "parser"
    normalized_tag = str(log_tag or "all").strip().lower() or "all"
    initial_target_label = next(
        (
            str(log_target.get("label") or "")
            for workload in list(summary.get("workloads") or [])
            for log_target in list(workload.get("logTargets") or [])
            if str(log_target.get("target") or "").strip().lower() == normalized_target
        ),
        _component_label(normalized_target),
    )
    target_buttons_html = "".join(
        f"<button type='button' class='segmented-button' data-target='{_escape(log_target.get('target') or '')}'>{_escape(log_target.get('label') or _component_label(log_target.get('target') or ''))}</button>"
        for workload in list(summary.get("workloads") or [])
        for log_target in list(workload.get("logTargets") or [])
    )
    return render_template(
        "logs_tab.html",
        tail_200_selected="selected" if tail_lines == 200 else "",
        tail_400_selected="selected" if tail_lines == 400 else "",
        tail_800_selected="selected" if tail_lines == 800 else "",
        tail_1600_selected="selected" if tail_lines == 1600 else "",
        instance_name=_escape(summary["name"]),
        target_label=_escape(initial_target_label),
        target_buttons_html=target_buttons_html,
        logs_config_json=_json_script(
            {
                "apiBase": summary["urls"]["logsApi"],
                "target": normalized_target,
                "tag": normalized_tag,
            }
        ),
        logs_js_href=_escape(_url(settings, "/assets/logs.js")),
    )


def _resources_tab(entries: list[dict[str, Any]]) -> str:
    sections = []
    for index, entry in enumerate(entries):
        summary = f"{entry['kind']} · {entry['name']}"
        if entry["error"]:
            summary += " · unavailable"
        rendered_payload = json.dumps(
            entry["payload"],
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=_json_dump_default,
        )
        sections.append(
            f"""
            <details class="panel-section resource-entry" {'open' if index == 0 else ''}>
              <summary>{_escape(summary)}</summary>
              <pre>{_escape(rendered_payload)}</pre>
            </details>
            """
        )
    return render_template(
        "resources_tab.html",
        sections_html="".join(sections) or "<section class='panel-section empty-state'>No related resources found.</section>",
    )


def _detail_page(
    settings: UISettings,
    summary: dict[str, Any],
    *,
    active_tab: str,
    resources: list[dict[str, Any]] | None = None,
    settings_form: str = "",
    flash: str = "",
    flash_kind: str = "info",
    target: str = "parser",
    log_tag: str = "all",
    tail_lines: int = 400,
) -> str:
    resources = resources or []
    tab = active_tab if active_tab in {"overview", "logs", "resources", "settings"} else "overview"
    return_path = f"/instances/{quote(summary['name'])}?tab={tab}"
    if tab == "logs":
        tab_body = _logs_tab(settings, summary, target, log_tag, tail_lines)
    elif tab == "resources":
        tab_body = _resources_tab(resources)
    elif tab == "settings":
        tab_body = settings_form
    else:
        tab_body = _overview_tab(settings, summary, return_path)
    body = render_template(
        "detail.html",
        name=_escape(summary["name"]),
        health_tone=_escape(summary["healthTone"]),
        health=_escape(summary["health"]),
        sync_state_tone=_sync_state_tone(summary["syncState"]),
        sync_state=_escape(summary["syncState"]),
        last_sync_label=_escape(summary["lastSyncLabel"]),
        dashboard_url=_escape(_url(settings, "/")),
        actions_html=_instance_actions(settings, summary, return_path=return_path),
        tabs_html="".join(
            [
                _tab_link(settings, summary, "overview", tab, "Overview"),
                _tab_link(settings, summary, "logs", tab, "Logs"),
                _tab_link(settings, summary, "resources", tab, "Resources"),
                _tab_link(settings, summary, "settings", tab, "Settings"),
            ]
        ),
        tab_body=tab_body,
    )
    return _layout(settings, body, flash=flash, flash_kind=flash_kind, page_title=summary["name"])


def _new_instance_page(settings: UISettings, context: dict[str, Any], flash: str, flash_kind: str) -> str:
    body = render_template(
        "new_instance.html",
        dashboard_url=_escape(_url(settings, "/")),
        form_html=_settings_form(settings, context, return_path="/", embedded=False),
    )
    return _layout(settings, body, flash=flash, flash_kind=flash_kind, page_title="New instance")
