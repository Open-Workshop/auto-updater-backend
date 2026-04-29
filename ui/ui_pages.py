from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlencode

from core.proxy_stats import PROXY_WINDOW_PRESETS
from ui.ui_assets import render_template
from ui.ui_common import UISettings, _escape, _format_time, _json_dump_default, _json_script, _url
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
        proxy_stats_url=_escape(_url(settings, "/proxy-stats")),
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


def _proxy_latency_label(value_ms: Any) -> str:
    try:
        numeric = float(value_ms)
    except (TypeError, ValueError):
        return "n/a"
    if numeric < 0:
        return "n/a"
    if numeric >= 1000.0:
        return f"{numeric / 1000.0:.2f}s"
    if numeric >= 100.0:
        return f"{numeric:.0f}ms"
    return f"{numeric:.1f}ms"


def _proxy_rate_value_label(value: Any) -> str:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return "0.00"
    if numeric < 0:
        return "0.00"
    if numeric < 1:
        return f"{numeric:.2f}"
    if numeric < 10:
        return f"{numeric:.1f}"
    return f"{numeric:.0f}"


def _proxy_rate_label(rps: Any, rpm: Any) -> str:
    try:
        requests_per_second = float(rps)
    except (TypeError, ValueError):
        requests_per_second = 0.0
    try:
        requests_per_minute = float(rpm)
    except (TypeError, ValueError):
        requests_per_minute = requests_per_second * 60.0

    return f"{_proxy_rate_value_label(requests_per_second)} / {_proxy_rate_value_label(requests_per_minute)}"


def _proxy_percent_label(value: float) -> str:
    return f"{max(0.0, min(100.0, value * 100.0)):.0f}%"


def _proxy_relative_age_label(seconds: float) -> str:
    value = max(0.0, float(seconds))
    if value < 60.0:
        return f"{int(round(value))}s ago"
    if value < 3600.0:
        return f"{int(round(value / 60.0))}m ago"
    if value < 86400.0:
        return f"{int(round(value / 3600.0))}h ago"
    return f"{int(round(value / 86400.0))}d ago"


def _proxy_detail_url(settings: UISettings, proxy_key: str, selected_window: str) -> str:
    query = urlencode({"proxy": proxy_key, "window": selected_window})
    return _url(settings, f"/proxy-stats/detail?{query}")


def _proxy_window_options_html(selected_window: str) -> str:
    selected = str(selected_window or "").strip() or PROXY_WINDOW_PRESETS[1][0]
    return "".join(
        f"<option value='{_escape(spec)}' {'selected' if spec == selected else ''}>{_escape(spec)}</option>"
        for spec, _seconds in PROXY_WINDOW_PRESETS
    )


def _proxy_sort_options_html(selected_sort: str) -> str:
    options = [
        ("bad_first", "Bad first"),
        ("failures_desc", "Most failures"),
        ("latency_desc", "Highest latency"),
        ("pods_desc", "Most pod coverage"),
        ("calls_desc", "Most calls"),
        ("label_asc", "A-Z"),
    ]
    selected = str(selected_sort or "bad_first")
    return "".join(
        f"<option value='{_escape(value)}' {'selected' if value == selected else ''}>{_escape(label)}</option>"
        for value, label in options
    )


def _proxy_status_filters_html(selected_filter: str) -> str:
    filters = ["All", "Healthy", "Degraded", "Broken", "Idle"]
    selected = str(selected_filter or "All")
    return "".join(
        f"<button type='button' class='filter-chip {'active' if label == selected else ''}' data-filter='{_escape(label)}'>{_escape(label)}</button>"
        for label in filters
    )


def _proxy_source_cards_html(sources: list[dict[str, Any]]) -> str:
    if not sources:
        return "<div class='empty-state'>No proxy source detail was captured for this endpoint.</div>"
    cards = []
    for source in sources:
        stats = dict(source.get("stats") or {})
        instance_name = str(source.get("instanceName") or "").strip() or "Unknown instance"
        pod_name = str(source.get("podName") or "").strip() or "n/a"
        success_calls = int(stats.get("successCalls") or 0)
        failure_calls = int(stats.get("failureCalls") or 0)
        total_calls = int(stats.get("totalCalls") or 0)
        top_error = dict(stats.get("topError") or {})
        top_error_label = str(top_error.get("label") or "")
        top_error_count = int(top_error.get("count") or 0)
        cards.append(
            f"""
            <article class="proxy-source-card">
              <div class="proxy-source-title">{_escape(instance_name)}</div>
              <div class="cell-subtle">{_escape(pod_name)}</div>
              <div class="proxy-source-metrics">
                <span><strong>{_escape(success_calls)}</strong> success</span>
                <span><strong>{_escape(failure_calls)}</strong> fail</span>
                <span><strong>{_escape(total_calls)}</strong> total</span>
              </div>
              <div class="proxy-source-footer">
                <span>{_escape(_proxy_latency_label(stats.get("averageResponseMs")))}</span>
                <span>{_escape(f"{_proxy_rate_value_label(stats.get('requestsPerSecond'))} rps")}</span>
                <span>{_escape(f"{top_error_label} × {top_error_count}" if top_error_label else "No error")}</span>
              </div>
            </article>
            """
        )
    return "".join(cards)


def _proxy_anomaly_strip_html(settings: UISettings, items: list[dict[str, Any]], selected_window: str) -> str:
    if not items:
        return "<div class='empty-state'>No proxy anomalies to surface yet.</div>"
    cards = []
    for item in items[:3]:
        stats = dict(item.get("stats") or {})
        proxy_key = str(item.get("proxyKey") or item.get("proxyLabel") or "")
        proxy_label = str(item.get("proxyLabel") or proxy_key)
        status_label = str(item.get("statusLabel") or "Idle")
        status_tone = str(item.get("statusTone") or "muted")
        detail_url = _proxy_detail_url(settings, proxy_key, selected_window)
        top_error = dict(stats.get("topError") or {})
        cards.append(
            f"""
            <a class="proxy-anomaly-card" href="{_escape(detail_url)}">
              <div class="proxy-anomaly-head">
                <span class="pill tone-{_escape(status_tone)}">{_escape(status_label)}</span>
                <span class="proxy-anomaly-link">Open detail</span>
              </div>
              <div class="proxy-anomaly-title">{_escape(proxy_label)}</div>
              <div class="proxy-anomaly-meta">
                <span>{_escape(f"{int(item.get('workingPodCount') or 0)} / {int(item.get('podCount') or 0)} pods")}</span>
                <span>{_escape(f"{int(stats.get('failureCalls') or 0)} failures")}</span>
                <span>{_escape(_proxy_latency_label(stats.get("averageResponseMs")))}</span>
              </div>
              <div class="proxy-anomaly-footer">
                <span>{_escape(top_error.get("label") or "No error")}</span>
                <strong>{_escape(f"× {int(top_error.get('count') or 0)}" if top_error.get("label") else "—")}</strong>
              </div>
            </a>
            """
        )
    return "".join(cards)


def _proxy_board_cards_html(settings: UISettings, items: list[dict[str, Any]], selected_window: str) -> str:
    if not items:
        return "<div class='empty-state'>No proxy telemetry is available yet.</div>"
    cards = []
    for item in items:
        stats = dict(item.get("stats") or {})
        proxy_key = str(item.get("proxyKey") or item.get("proxyLabel") or "")
        proxy_label = str(item.get("proxyLabel") or proxy_key)
        status_label = str(item.get("statusLabel") or "Idle")
        status_tone = str(item.get("statusTone") or "muted")
        detail_url = _proxy_detail_url(settings, proxy_key, selected_window)
        top_error = dict(stats.get("topError") or {})
        cards.append(
            f"""
            <a class="proxy-board-card" href="{_escape(detail_url)}">
              <div class="proxy-board-header">
                <div class="proxy-board-title-wrap">
                  <code class="proxy-endpoint">{_escape(proxy_label)}</code>
                  <div class="cell-subtle">{_escape(f"{int(item.get('workingPodCount') or 0)} pods with success · {int(item.get('podCount') or 0)} pods seen")}</div>
                </div>
                <div class="proxy-board-status">
                  <span class="pill tone-{_escape(status_tone)}">{_escape(status_label)}</span>
                  <span class="proxy-board-error">{_escape(f"{top_error.get('label')} × {int(top_error.get('count') or 0)}" if top_error.get("label") else "No error")}</span>
                </div>
              </div>
              <div class="proxy-board-grid">
                <div class="proxy-board-cell">
                  <span class="meta-label">Coverage</span>
                  <strong>{_escape(f"{int(item.get('workingPodCount') or 0)} / {int(item.get('podCount') or 0)}")}</strong>
                  <span class="cell-subtle">{_escape(f"{int(item.get('sourceCount') or 0)} source pods")}</span>
                </div>
                <div class="proxy-board-cell">
                  <span class="meta-label">Success</span>
                  <strong>{_escape(int(stats.get('successCalls') or 0))}</strong>
                  <span class="cell-subtle">{_escape(f"{int(stats.get('totalCalls') or 0)} total calls")}</span>
                </div>
                <div class="proxy-board-cell">
                  <span class="meta-label">Failures</span>
                  <strong>{_escape(int(stats.get('failureCalls') or 0))}</strong>
                  <span class="cell-subtle">{_escape(_proxy_percent_label(float(stats.get('failureRate') or 0.0)))} failure rate</span>
                </div>
                <div class="proxy-board-cell">
                  <span class="meta-label">Avg latency</span>
                  <strong>{_escape(_proxy_latency_label(stats.get("averageResponseMs")))}</strong>
                  <span class="cell-subtle">{_escape(_proxy_rate_label(stats.get('requestsPerSecond'), stats.get('requestsPerMinute')))} rps / rpm</span>
                </div>
              </div>
            </a>
            """
        )
    return "".join(cards)


def _proxy_chart_legend_html(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "<div class='empty-state'>No proxy calls have been observed yet.</div>"
    return "".join(
        f"""
        <div class="legend-item">
          <span class="legend-swatch" style="background:{_escape(entry['color'])};"></span>
          <span class="legend-label">{_escape(entry['label'])}</span>
          <strong>{_escape(entry['count'])}</strong>
          <span class="legend-share">{_escape(entry.get('shareLabel') or '')}</span>
        </div>
        """
        for entry in entries
        if int(entry.get("count") or 0) > 0
    )


def _proxy_timeline_html(buckets: list[dict[str, Any]]) -> str:
    if not buckets:
        return "<div class='empty-state'>No timeline data is available for this proxy.</div>"
    max_total = max((int(bucket.get("totalCalls") or 0) for bucket in buckets), default=0)
    bars = []
    for bucket in buckets:
        total = int(bucket.get("totalCalls") or 0)
        success = int(bucket.get("successCalls") or 0)
        failure = int(bucket.get("failureCalls") or 0)
        height = 12 if max_total <= 0 else max(12, int(round((total / max_total) * 100)))
        title = (
            f"{bucket.get('label')}: {total} calls, {success} success, {failure} failure"
            if bucket.get("label")
            else f"{total} calls"
        )
        bars.append(
            f"""
            <div class="proxy-timeline-bar-wrap" title="{_escape(title)}">
              <div class="proxy-timeline-bar" style="height:{height}%;"></div>
            </div>
            """
        )
    return f"""
    <div class="proxy-timeline">
      <div class="proxy-timeline-bars">{''.join(bars)}</div>
      <div class="proxy-timeline-axis">
        <span>oldest</span>
        <span>newest</span>
      </div>
    </div>
    """


def _proxy_bucket_cards_html(buckets: list[dict[str, Any]]) -> str:
    if not buckets:
        return "<div class='empty-state'>No bucket data was captured for this proxy.</div>"
    cards = []
    for bucket in buckets:
        top_error = dict(bucket.get("topError") or {})
        cards.append(
            f"""
            <article class="proxy-bucket-card">
              <div class="proxy-bucket-title">{_escape(bucket.get("label") or "Bucket")}</div>
              <div class="proxy-bucket-range">{_escape(bucket.get("rangeLabel") or "")}</div>
              <div class="proxy-bucket-count">{_escape(int(bucket.get("totalCalls") or 0))} calls</div>
              <div class="proxy-bucket-metrics">
                <span><strong>{_escape(int(bucket.get("successCalls") or 0))}</strong> ok</span>
                <span><strong>{_escape(int(bucket.get("failureCalls") or 0))}</strong> fail</span>
                <span>{_escape(_proxy_latency_label(bucket.get("averageResponseMs")))}</span>
              </div>
              <div class="proxy-bucket-footer">
                <span>{_escape(top_error.get("label") or "No error")}</span>
                <strong>{_escape(f"× {int(top_error.get('count') or 0)}" if top_error.get("label") else "—")}</strong>
              </div>
            </article>
            """
        )
    return "".join(cards)


def _proxy_failure_events_html(events: list[dict[str, Any]]) -> str:
    if not events:
        return "<div class='empty-state'>No recent failure events were captured for this proxy.</div>"
    rows = []
    for event in events:
        rows.append(
            f"""
            <article class="proxy-failure-event">
              <div class="proxy-failure-head">
                <strong>{_escape(event.get("errorType") or "UnknownError")}</strong>
                <span>{_escape(_proxy_relative_age_label(float(event.get("ageSeconds") or 0.0)))}</span>
              </div>
              <div class="proxy-failure-meta">
                <span>{_escape(event.get("podName") or "n/a")}</span>
                <span>{_escape(event.get("instanceName") or "n/a")}</span>
                <span>{_escape(_proxy_latency_label(float(event.get("elapsedSeconds") or 0.0) * 1000.0))}</span>
              </div>
            </article>
            """
        )
    return "".join(rows)


def _proxy_table_rows(items: list[dict[str, Any]]) -> str:
    rows = []
    for item in items:
        stats = dict(item.get("stats") or {})
        success_calls = int(stats.get("successCalls") or 0)
        failure_calls = int(stats.get("failureCalls") or 0)
        total_calls = int(stats.get("totalCalls") or 0)
        failure_rate = float(stats.get("failureRate") or (failure_calls / total_calls if total_calls else 0.0))
        pods_seen = list(item.get("podsSeen") or [])
        pods_working = list(item.get("podsWorking") or [])
        proxy_label = str(item.get("proxyLabel") or item.get("proxyKey") or "proxy")
        status_label = str(item.get("statusLabel") or "Idle")
        status_tone = str(item.get("statusTone") or "muted")
        top_error = dict(stats.get("topError") or {})
        top_error_label = str(top_error.get("label") or "")
        top_error_count = int(top_error.get("count") or 0)
        proxy_key = str(item.get("proxyKey") or proxy_label)
        source_cards_html = _proxy_source_cards_html(list(item.get("sources") or []))
        rows.append(
            f"""
            <tr class="proxy-row" data-proxy-key="{_escape(proxy_key)}" data-status="{_escape(status_label)}">
              <td>
                <div class="proxy-primary-cell">
                  <button type="button" class="proxy-expand-button" data-expand-proxy="{_escape(proxy_key)}" aria-expanded="false">Details</button>
                  <div>
                    <code class="proxy-endpoint">{_escape(proxy_label)}</code>
                    <div class="cell-subtle">{_escape(len(pods_working))} pods with success · {_escape(len(pods_seen))} pods seen</div>
                  </div>
                </div>
              </td>
              <td><span class="pill tone-{_escape(status_tone)}">{_escape(status_label)}</span></td>
              <td>
                <div class="proxy-metric-stack">
                  <strong>{_escape(len(pods_working))} / {_escape(len(pods_seen))}</strong>
                  <div class="cell-subtle">{_escape(len(list(item.get("sources") or [])))} sources</div>
                </div>
              </td>
              <td>
                <div class="proxy-metric-stack">
                  <strong>{_escape(success_calls)}</strong>
                  <div class="cell-subtle">{_escape(total_calls)} total</div>
                </div>
              </td>
              <td>
                <div class="proxy-metric-stack">
                  <strong>{_escape(failure_calls)}</strong>
                  <div class="cell-subtle">{_escape(_proxy_percent_label(failure_rate))} failure rate</div>
                </div>
              </td>
              <td>{_escape(_proxy_latency_label(stats.get("averageResponseMs")))}</td>
              <td>{_escape(_proxy_rate_label(stats.get("requestsPerSecond"), stats.get("requestsPerMinute")))}</td>
              <td>{_escape(f"{top_error_label} × {top_error_count}" if top_error_label else "—")}</td>
            </tr>
            <tr class="proxy-detail-row" data-proxy-detail="{_escape(proxy_key)}" hidden>
              <td colspan="8">
                <div class="proxy-detail-shell">
                  <div class="section-title">Proxy sources</div>
                  <div class="proxy-source-grid">{source_cards_html}</div>
                </div>
              </td>
            </tr>
            """
        )
    return "".join(rows) or """
        <tr>
          <td colspan="8">
            <div class="empty-state">No proxy telemetry is available yet.</div>
          </td>
        </tr>
    """


def _proxy_stats_page(
    settings: UISettings,
    payload: dict[str, Any],
    flash: str,
    flash_kind: str,
    *,
    selected_window: str,
) -> str:
    summary = dict(payload.get("summary") or {})
    window = dict(payload.get("window") or {})
    generated_at = str(payload.get("generatedAt") or "")
    generated_at_label = _format_time(generated_at) if generated_at else "just now"
    error_entries = list(payload.get("errorBreakdown") or [])
    proxies = list(payload.get("proxies") or [])
    source_info = dict(payload.get("sources") or {})
    window_label = str(window.get("label") or selected_window or "1h")
    proxy_count = int(summary.get("proxyCount") or len(proxies))
    source_total = int(source_info.get("total") or summary.get("sourcePodsTotal") or 0)
    source_responded = int(source_info.get("responded") or summary.get("sourcePodsResponded") or 0)
    pods_with_success = int(summary.get("podsWithSuccess") or 0)
    broken_proxies = int(summary.get("brokenProxies") or 0)
    degraded_proxies = int(summary.get("degradedProxies") or 0)
    healthy_proxies = int(summary.get("healthyProxies") or 0)
    failure_rate = float(summary.get("failureRate") or 0.0)
    metrics_html = "".join(
        [
            _summary_metric("Broken proxies", broken_proxies, "error" if broken_proxies else "muted"),
            _summary_metric("Degraded proxies", degraded_proxies, "warning" if degraded_proxies else "muted"),
            _summary_metric("Healthy proxies", healthy_proxies, "healthy" if healthy_proxies else "muted"),
            _summary_metric("Pods with traffic", int(summary.get("podsWithTraffic") or 0), "info"),
            _summary_metric("Avg latency", _proxy_latency_label(summary.get("averageResponseMs")), "info"),
            _summary_metric("RPS / RPM", _proxy_rate_label(summary.get("requestsPerSecond"), summary.get("requestsPerMinute")), "muted"),
        ]
    )
    failure_calls = int(summary.get("failureCalls") or 0)
    success_calls = int(summary.get("successCalls") or 0)
    total_calls = int(summary.get("totalCalls") or 0)
    success_rate = (success_calls / total_calls) if total_calls else 0.0
    chart_entries = [
        {
            "label": "Success",
            "count": success_calls,
            "color": "var(--healthy)",
            "shareLabel": _proxy_percent_label(success_rate) if total_calls else "",
        }
    ]
    chart_entries.extend(
        {
            "label": str(entry.get("label") or "Error"),
            "count": int(entry.get("count") or 0),
            "color": f"var({['--warning', '--error', '--info', '--accent', '--muted'][index % 5]})",
            "shareLabel": _proxy_percent_label((int(entry.get("count") or 0) / max(1, total_calls))) if total_calls else "",
        }
        for index, entry in enumerate(error_entries)
        if int(entry.get("count") or 0) > 0
    )
    body = render_template(
        "proxy_stats.html",
        title=_escape("Proxy Health"),
        subtitle=_escape("Proxy triage by normalized endpoint. Broken and degraded proxies rise first, and each card opens a dedicated detail view."),
        dashboard_url=_escape(_url(settings, "/")),
        hero_note=_escape(
            f"{proxy_count} endpoints · {pods_with_success} pods reported successful proxy calls · {source_responded} / {source_total} parser pods responded · window {window_label} · updated {generated_at_label}"
            if source_total
            else f"Waiting for proxy telemetry · window {window_label}"
        ),
        window_options_html=_proxy_window_options_html(selected_window),
        sort_options_html=_proxy_sort_options_html("bad_first"),
        status_filters_html=_proxy_status_filters_html("All"),
        metrics_html=metrics_html,
        top_anomalies_html=_proxy_anomaly_strip_html(settings, proxies, window_label),
        chart_total=_escape(total_calls),
        chart_success_rate=_escape(f"{_proxy_percent_label(success_rate)} success"),
        chart_legend_html=_proxy_chart_legend_html(chart_entries)
        or "<div class='empty-state'>No proxy calls have been observed yet.</div>",
        toolbar_note=_escape(
            f"{source_responded} / {source_total} parser pods responded · updated {generated_at_label}"
            if source_total
            else "Waiting for proxy telemetry..."
        ),
        proxy_board_html=_proxy_board_cards_html(settings, proxies, window_label),
        proxy_stats_payload_json=_json_script(payload),
        proxy_stats_config_json=_json_script(
            {
                "apiUrl": _url(settings, "/api/proxy-stats"),
                "detailBaseUrl": _url(settings, "/proxy-stats/detail"),
                "selectedWindow": selected_window,
                "defaultSort": "bad_first",
            }
        ),
        proxy_stats_js_href=_escape(_url(settings, "/assets/proxy_stats.js")),
    )
    return _layout(settings, body, flash=flash, flash_kind=flash_kind, page_title=settings.title)


def _proxy_detail_metrics_html(summary: dict[str, Any], source_info: dict[str, Any]) -> str:
    pods_seen = int(summary.get("podsWithTraffic") or 0)
    pods_working = int(summary.get("podsWithSuccess") or 0)
    source_responded = int(source_info.get("responded") or 0)
    source_total = int(source_info.get("total") or 0)
    top_error = dict(summary.get("topError") or {})
    top_error_label = str(top_error.get("label") or "")
    top_error_count = int(top_error.get("count") or 0)
    failure_calls = int(summary.get("failureCalls") or 0)
    return "".join(
        [
            _summary_metric("Pod coverage", f"{pods_working} / {pods_seen}", "info"),
            _summary_metric("Parser pods", f"{source_responded} / {source_total}", "muted"),
            _summary_metric("Success calls", int(summary.get("successCalls") or 0), "healthy"),
            _summary_metric("Failure calls", failure_calls, "error" if failure_calls else "muted"),
            _summary_metric("Avg latency", _proxy_latency_label(summary.get("averageResponseMs")), "info"),
            _summary_metric("Top error", f"{top_error_label} × {top_error_count}" if top_error_label else "—", "warning" if top_error_label else "muted"),
        ]
    )


def _proxy_stats_detail_page(
    settings: UISettings,
    payload: dict[str, Any],
    flash: str,
    flash_kind: str,
    *,
    selected_window: str,
) -> str:
    summary = dict(payload.get("summary") or {})
    window = dict(payload.get("window") or {})
    proxy = dict(payload.get("proxy") or {})
    sources = dict(payload.get("sources") or {})
    generated_at = str(payload.get("generatedAt") or "")
    generated_at_label = _format_time(generated_at) if generated_at else "just now"
    proxy_key = str(proxy.get("key") or "")
    proxy_label = str(proxy.get("label") or proxy_key or "Proxy detail")
    window_label = str(window.get("label") or selected_window or "1h")
    back_url = _url(settings, f"/proxy-stats?{urlencode({'window': window_label})}")
    body = render_template(
        "proxy_detail.html",
        title=_escape(proxy_label),
        subtitle=_escape("Normalized endpoint detail across parser pods. Use the timeline to see how this proxy behaved over the selected window."),
        hero_note=_escape(
            f"{int(summary.get('podsWithTraffic') or 0)} pods saw traffic · {int(summary.get('podsWithSuccess') or 0)} pods had success · {int(sources.get('responded') or 0)} / {int(sources.get('total') or 0)} parser pods responded · updated {generated_at_label}"
            if sources.get("total")
            else f"Waiting for proxy detail · window {window_label}"
        ),
        dashboard_url=_escape(back_url),
        detail_base_url=_escape(_url(settings, "/proxy-stats/detail")),
        proxy_key=_escape(proxy_key),
        window_options_html=_proxy_window_options_html(window_label),
        metrics_html=_proxy_detail_metrics_html(summary, sources),
        timeline_html=_proxy_timeline_html(list(payload.get("buckets") or [])),
        bucket_cards_html=_proxy_bucket_cards_html(list(payload.get("buckets") or [])),
        recent_failures_html=_proxy_failure_events_html(list(payload.get("recentFailures") or [])),
        source_cards_html=_proxy_source_cards_html(list(payload.get("sourceEntries") or [])),
        detail_payload_json=_json_script(payload),
        detail_config_json=_json_script(
            {
                "proxyKey": proxy_key,
                "window": window_label,
                "detailBaseUrl": _url(settings, "/proxy-stats/detail"),
            }
        ),
        proxy_detail_js_href=_escape(_url(settings, "/assets/proxy_detail.js")),
    )
    return _layout(settings, body, flash=flash, flash_kind=flash_kind, page_title=proxy_label)


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
