(() => {
  const metricsRoot = document.getElementById("proxy-metrics");
  const syncState = document.getElementById("proxy-sync-state");
  const refreshButton = document.getElementById("proxy-refresh");
  const payloadNode = document.getElementById("proxy-payload");
  const configNode = document.getElementById("proxy-config");
  const chartTotalNode = document.getElementById("proxy-chart-total");
  const chartSuccessNode = document.getElementById("proxy-chart-success");
  const chartNode = document.getElementById("proxy-pie-chart");
  const legendRoot = document.getElementById("proxy-chart-legend");
  const podsRoot = document.getElementById("proxy-pods-body");

  if (!metricsRoot || !payloadNode || !configNode || !chartNode || !legendRoot || !podsRoot) {
    return;
  }

  const config = JSON.parse(configNode.textContent || "{}");
  const apiUrl = config.apiUrl || "";
  const payload = JSON.parse(payloadNode.textContent || "{}");

  const palette = [
    "var(--healthy)",
    "var(--warning)",
    "var(--error)",
    "var(--info)",
    "var(--accent)",
    "var(--muted)",
  ];

  let current = normalizePayload(payload);

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatCount(value) {
    const numeric = Number(value ?? 0);
    if (!Number.isFinite(numeric)) return "0";
    return new Intl.NumberFormat().format(Math.max(0, Math.round(numeric)));
  }

  function formatLatency(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric < 0) {
      return "n/a";
    }
    if (numeric >= 1000) {
      return `${(numeric / 1000).toFixed(2)}s`;
    }
    if (numeric >= 100) {
      return `${numeric.toFixed(0)}ms`;
    }
    return `${numeric.toFixed(1)}ms`;
  }

  function formatRate(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
      return "0.0";
    }
    return numeric.toFixed(1);
  }

  function normalizeStats(stats) {
    const totalCalls = Number(stats.totalCalls || 0);
    const successCalls = Number(stats.successCalls || 0);
    const failureCalls = Number(stats.failureCalls || 0);
    const totalElapsedSeconds = Number(stats.totalElapsedSeconds || 0);
    const averageResponseMs = stats.averageResponseMs === null || stats.averageResponseMs === undefined
      ? null
      : Number(stats.averageResponseMs);
    const recentRequests = Number(stats.recentRequests || 0);
    const recentWindowSeconds = Number(stats.recentWindowSeconds || 60) || 60;
    const requestsPerSecond = Number(stats.requestsPerSecond || recentRequests / recentWindowSeconds);
    const requestsPerMinute = Number(stats.requestsPerMinute || requestsPerSecond * 60);
    const errorCounts = stats.errorCounts && typeof stats.errorCounts === "object"
      ? stats.errorCounts
      : {};
    const topError = stats.topError && typeof stats.topError === "object"
      ? stats.topError
      : { label: "", count: 0 };
    return {
      totalCalls,
      successCalls,
      failureCalls,
      totalElapsedSeconds,
      averageResponseMs,
      recentRequests,
      recentWindowSeconds,
      requestsPerSecond,
      requestsPerMinute,
      errorCounts,
      topError: {
        label: String(topError.label || ""),
        count: Number(topError.count || 0),
      },
    };
  }

  function normalizePayload(raw) {
    const summary = raw.summary || {};
    const items = Array.isArray(raw.pods) ? raw.pods : [];
    return {
      generatedAt: raw.generatedAt || "",
      summary: {
        podsTotal: Number(summary.podsTotal || items.length || 0),
        podsReachable: Number(summary.podsReachable || 0),
        podsConfigured: Number(summary.podsConfigured || 0),
        podsWorking: Number(summary.podsWorking || 0),
        totalCalls: Number(summary.totalCalls || 0),
        successCalls: Number(summary.successCalls || 0),
        failureCalls: Number(summary.failureCalls || 0),
        averageResponseMs: summary.averageResponseMs === null || summary.averageResponseMs === undefined
          ? null
          : Number(summary.averageResponseMs),
        recentRequests: Number(summary.recentRequests || 0),
        recentWindowSeconds: Number(summary.recentWindowSeconds || 60) || 60,
        requestsPerSecond: Number(summary.requestsPerSecond || 0),
        requestsPerMinute: Number(summary.requestsPerMinute || 0),
      },
      items: items.map((item) => ({
        ...item,
        stats: normalizeStats(item.stats || {}),
      })),
      errorBreakdown: Array.isArray(raw.errorBreakdown) ? raw.errorBreakdown : [],
    };
  }

  function cardHtml(label, value, tone) {
    return `
      <section class="metric-card tone-${escapeHtml(tone)}">
        <div class="metric-label">${escapeHtml(label)}</div>
        <div class="metric-value">${escapeHtml(value)}</div>
      </section>
    `;
  }

  function renderMetrics(summary) {
    const workingTone = !summary.podsTotal
      ? "muted"
      : summary.podsWorking >= summary.podsTotal
        ? "healthy"
        : summary.podsWorking > 0
          ? "warning"
          : "error";
    metricsRoot.innerHTML = [
      cardHtml("Pods with working proxy", `${summary.podsWorking} / ${summary.podsTotal}`, workingTone),
      cardHtml("Success calls", formatCount(summary.successCalls), "healthy"),
      cardHtml("Failures", formatCount(summary.failureCalls), "error"),
      cardHtml("Avg response", formatLatency(summary.averageResponseMs), "info"),
      cardHtml("RPS / RPM", `${formatRate(summary.requestsPerSecond)} / ${formatCount(summary.requestsPerMinute)}`, "muted"),
    ].join("");
  }

  function buildSegments(summary, errorBreakdown) {
    const segments = [];
    if (summary.successCalls > 0) {
      segments.push({
        label: "Success",
        count: Number(summary.successCalls || 0),
        color: palette[0],
      });
    }
    for (let index = 0; index < errorBreakdown.length; index += 1) {
      const entry = errorBreakdown[index] || {};
      const count = Number(entry.count || 0);
      if (count <= 0) continue;
      segments.push({
        label: String(entry.label || "Error"),
        count,
        color: palette[(index + 1) % palette.length],
      });
    }
    return segments;
  }

  function renderChart(summary, errorBreakdown) {
    const segments = buildSegments(summary, errorBreakdown);
    const total = segments.reduce((acc, segment) => acc + segment.count, 0);
    chartTotalNode.textContent = formatCount(total);
    if (chartSuccessNode) {
      chartSuccessNode.textContent = formatCount(summary.successCalls);
    }
    if (!segments.length || total <= 0) {
      chartNode.style.background = "radial-gradient(circle at center, rgba(255, 255, 255, 0.98), rgba(255, 255, 255, 0.82))";
      legendRoot.innerHTML = "<div class=\"empty-state\">No proxy calls yet.</div>";
      return;
    }

    let cursor = 0;
    const slices = segments.map((segment) => {
      const start = cursor;
      const size = (segment.count / total) * 100;
      cursor += size;
      return `${segment.color} ${start.toFixed(3)}% ${cursor.toFixed(3)}%`;
    });
    chartNode.style.background = `conic-gradient(${slices.join(", ")})`;
    legendRoot.innerHTML = segments
      .map((segment) => `
        <div class="legend-item">
          <span class="legend-swatch" style="background:${segment.color};"></span>
          <span class="legend-label">${escapeHtml(segment.label)}</span>
          <strong>${formatCount(segment.count)}</strong>
        </div>
      `)
      .join("");
  }

  function podStatusClass(statusTone) {
    if (statusTone === "healthy") return "healthy";
    if (statusTone === "warning") return "warning";
    if (statusTone === "error") return "error";
    if (statusTone === "info") return "info";
    return "muted";
  }

  function podRowHtml(item) {
    const stats = item.stats || normalizeStats({});
    const topError = stats.topError && stats.topError.label ? `${stats.topError.label} × ${formatCount(stats.topError.count)}` : "—";
    const statusLabel = item.statusLabel || "Unknown";
    const proxyScope = item.proxyScope || "n/a";
    const proxyPoolSize = Number(item.proxyPoolSize || 0);
    const detail = proxyPoolSize > 0 ? `${proxyScope} · ${proxyPoolSize} proxies` : proxyScope;
    const totalCalls = stats.totalCalls || (stats.successCalls + stats.failureCalls);
    const failRate = totalCalls > 0 ? `${Math.round((stats.failureCalls / totalCalls) * 100)}%` : "0%";
    return `
      <tr data-proxy-status="${escapeHtml(statusLabel)}" data-instance="${escapeHtml(item.name || "")}">
        <td>
          <div class="primary-cell">
            <a class="row-link" href="${escapeHtml(item.urls && item.urls.detail ? item.urls.detail : "#")}">${escapeHtml(item.name || "")}</a>
            <div class="cell-subtle">${escapeHtml(item.parserPod || "n/a")} · ${escapeHtml(detail)}</div>
          </div>
        </td>
        <td><span class="pill tone-${podStatusClass(item.statusTone)}">${escapeHtml(statusLabel)}</span></td>
        <td>
          <div class="proxy-metric-stack">
            <strong>${formatCount(stats.successCalls)}</strong>
            <div class="cell-subtle">${formatCount(totalCalls)} total</div>
          </div>
        </td>
        <td>
          <div class="proxy-metric-stack">
            <strong>${formatCount(stats.failureCalls)}</strong>
            <div class="cell-subtle">${escapeHtml(failRate)}</div>
          </div>
        </td>
        <td>${escapeHtml(formatLatency(stats.averageResponseMs))}</td>
        <td>${escapeHtml(`${formatRate(stats.requestsPerSecond)} / ${formatCount(stats.requestsPerMinute)}`)}</td>
        <td>${escapeHtml(topError)}</td>
      </tr>
    `;
  }

  function renderPods(items) {
    podsRoot.innerHTML = items.length
      ? items.map(podRowHtml).join("")
      : `
        <tr>
          <td colspan="7">
            <div class="empty-state">No proxy telemetry is available yet.</div>
          </td>
        </tr>
      `;
  }

  function renderAll() {
    renderMetrics(current.summary);
    renderChart(current.summary, current.errorBreakdown);
    renderPods(current.items);
    if (syncState) {
      const updatedAt = new Date().toLocaleTimeString();
      syncState.textContent = current.summary.podsTotal
        ? `${current.summary.podsReachable} / ${current.summary.podsTotal} pods responded · updated ${updatedAt}`
        : `Waiting for proxy telemetry · updated ${updatedAt}`;
    }
  }

  async function refreshData() {
    if (syncState) {
      syncState.textContent = "Refreshing...";
    }
    try {
      const response = await fetch(apiUrl, {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || data.message || `HTTP ${response.status}`);
      }
      current = normalizePayload(data);
      renderAll();
    } catch (error) {
      if (syncState) {
        syncState.textContent = "Auto-refresh failed";
      }
      if (window.autoUpdater && typeof window.autoUpdater.showToast === "function") {
        window.autoUpdater.showToast(`Proxy stats refresh failed: ${error.message}`, "error");
      }
    }
  }

  if (refreshButton) {
    refreshButton.addEventListener("click", refreshData);
  }

  renderAll();
  if (window.autoUpdater && typeof window.autoUpdater.bindActionForms === "function") {
    window.autoUpdater.bindActionForms(document, refreshData);
  }
  window.setInterval(refreshData, 10000);
})();
