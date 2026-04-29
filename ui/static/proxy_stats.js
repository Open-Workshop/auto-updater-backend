(() => {
  const anomaliesRoot = document.getElementById("proxy-anomalies");
  const boardRoot = document.getElementById("proxy-board");
  const searchInput = document.getElementById("proxy-search");
  const sortSelect = document.getElementById("proxy-sort");
  const statusFilterRoot = document.getElementById("proxy-status-filters");
  const refreshButton = document.getElementById("proxy-refresh");
  const windowSelect = document.getElementById("proxy-window-select");
  const syncState = document.getElementById("proxy-sync-state");
  const payloadNode = document.getElementById("proxy-payload");
  const configNode = document.getElementById("proxy-config");
  const chartTotalNode = document.getElementById("proxy-chart-total");
  const chartSuccessRateNode = document.getElementById("proxy-chart-success-rate");
  const chartNode = document.getElementById("proxy-pie-chart");
  const legendRoot = document.getElementById("proxy-chart-legend");
  const metricsRoot = document.getElementById("proxy-metrics");

  if (
    !anomaliesRoot
    || !boardRoot
    || !searchInput
    || !sortSelect
    || !statusFilterRoot
    || !refreshButton
    || !windowSelect
    || !syncState
    || !payloadNode
    || !configNode
    || !chartTotalNode
    || !chartSuccessRateNode
    || !chartNode
    || !legendRoot
    || !metricsRoot
  ) {
    return;
  }

  const config = JSON.parse(configNode.textContent || "{}");
  const apiUrl = config.apiUrl || "";
  const detailBaseUrl = config.detailBaseUrl || "";
  const defaultSort = config.defaultSort || "bad_first";
  const defaultWindow = config.selectedWindow || "1h";
  const palette = [
    "var(--healthy)",
    "var(--warning)",
    "var(--error)",
    "var(--info)",
    "var(--accent)",
    "var(--muted)",
  ];

  let payload = normalizePayload(JSON.parse(payloadNode.textContent || "{}"));
  let searchTerm = "";
  let activeFilter = "All";
  let sortKey = defaultSort;
  let selectedWindow = payload.window.spec || defaultWindow;

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
    if (!Number.isFinite(numeric) || numeric < 0) return "n/a";
    if (numeric >= 1000) return `${(numeric / 1000).toFixed(2)}s`;
    if (numeric >= 100) return `${numeric.toFixed(0)}ms`;
    return `${numeric.toFixed(1)}ms`;
  }

  function formatRate(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric < 0) return "0.00";
    if (numeric < 1) return numeric.toFixed(2);
    if (numeric < 10) return numeric.toFixed(1);
    return numeric.toFixed(0);
  }

  function formatPercent(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return "0%";
    return `${Math.max(0, Math.min(100, Math.round(numeric * 100)))}%`;
  }

  function severityForStatus(status) {
    if (status === "Broken") return 40;
    if (status === "Degraded") return 30;
    if (status === "Idle") return 20;
    return 10;
  }

  function toneForStatus(status) {
    if (status === "Broken") return "error";
    if (status === "Degraded") return "warning";
    if (status === "Healthy") return "healthy";
    if (status === "Idle") return "muted";
    return "muted";
  }

  function normalizeErrorCounts(errorCounts) {
    const entries = Object.entries(errorCounts && typeof errorCounts === "object" ? errorCounts : {});
    entries.sort((left, right) => {
      const countDelta = Number(right[1] || 0) - Number(left[1] || 0);
      if (countDelta !== 0) return countDelta;
      return String(left[0] || "").localeCompare(String(right[0] || ""));
    });
    return Object.fromEntries(entries.map(([label, count]) => [String(label), Number(count || 0)]));
  }

  function normalizeStats(stats, windowSeconds, windowLabel) {
    const totalCalls = Number(stats.totalCalls ?? stats.recentRequests ?? 0);
    const successCalls = Number(stats.successCalls ?? 0);
    const failureCalls = Number(stats.failureCalls ?? 0);
    const totalElapsedSeconds = Number(stats.totalElapsedSeconds ?? 0);
    const averageResponseMs = stats.averageResponseMs === null || stats.averageResponseMs === undefined
      ? null
      : Number(stats.averageResponseMs);
    const requestsPerSecond = Number(stats.requestsPerSecond ?? (windowSeconds > 0 ? totalCalls / windowSeconds : 0));
    const requestsPerMinute = Number(stats.requestsPerMinute ?? (requestsPerSecond * 60));
    const errorCounts = normalizeErrorCounts(stats.errorCounts);
    const topError = stats.topError && typeof stats.topError === "object"
      ? {
          label: String(stats.topError.label || ""),
          count: Number(stats.topError.count || 0),
        }
      : {
          label: "",
          count: 0,
        };
    const failureRate = totalCalls > 0 ? failureCalls / totalCalls : 0;
    return {
      totalCalls,
      successCalls,
      failureCalls,
      totalElapsedSeconds,
      averageResponseMs,
      recentRequests: Number(stats.recentRequests ?? totalCalls),
      recentWindowSeconds: Number(stats.recentWindowSeconds ?? windowSeconds),
      windowSeconds: Number(stats.windowSeconds ?? windowSeconds),
      windowLabel: String(stats.windowLabel || windowLabel || "1h"),
      requestsPerSecond,
      requestsPerMinute,
      errorCounts,
      failureRate,
      topError,
    };
  }

  function normalizeSource(source, windowSeconds, windowLabel) {
    const stats = normalizeStats(source.stats || {}, windowSeconds, windowLabel);
    return {
      instanceName: String(source.instanceName || ""),
      podName: String(source.podName || ""),
      windowSeconds: Number(source.windowSeconds ?? windowSeconds),
      windowLabel: String(source.windowLabel || windowLabel || "1h"),
      stats,
    };
  }

  function normalizeProxy(item, windowSeconds, windowLabel) {
    const stats = normalizeStats(item.stats || {}, windowSeconds, windowLabel);
    const podsSeen = Array.isArray(item.podsSeen) ? item.podsSeen.map((value) => String(value || "")).filter(Boolean) : [];
    const podsWorking = Array.isArray(item.podsWorking) ? item.podsWorking.map((value) => String(value || "")).filter(Boolean) : [];
    const sources = Array.isArray(item.sources)
      ? item.sources.map((source) => normalizeSource(source, windowSeconds, windowLabel))
      : [];
    const statusLabel = String(item.statusLabel || (stats.totalCalls > 0 ? (stats.failureCalls > 0 ? (stats.successCalls > 0 ? "Degraded" : "Broken") : "Healthy") : "Idle"));
    const statusTone = String(item.statusTone || toneForStatus(statusLabel));
    const statusSeverity = Number(item.statusSeverity ?? severityForStatus(statusLabel));
    const proxyKey = String(item.proxyKey || item.proxyLabel || "");
    const proxyLabel = String(item.proxyLabel || proxyKey || "proxy");
    const topErrorLabel = stats.topError.label;
    const searchText = [
      proxyKey,
      proxyLabel,
      statusLabel,
      ...podsSeen,
      ...podsWorking,
      ...sources.flatMap((source) => [
        source.instanceName,
        source.podName,
        source.stats.topError.label,
      ]),
      topErrorLabel,
    ]
      .join(" ")
      .toLowerCase();

    return {
      proxyKey,
      proxyLabel,
      statusLabel,
      statusTone,
      statusSeverity,
      podsSeen,
      podsWorking,
      podCount: podsSeen.length,
      workingPodCount: podsWorking.length,
      sourceCount: sources.length,
      sources,
      stats,
      searchText,
    };
  }

  function normalizePayload(raw) {
    const windowInfo = raw.window || {};
    const summary = raw.summary || {};
    const windowSeconds = Number(windowInfo.seconds ?? summary.recentWindowSeconds ?? 3600);
    const windowLabel = String(windowInfo.label || windowInfo.spec || summary.windowLabel || "1h");
    const proxies = (Array.isArray(raw.proxies) ? raw.proxies : [])
      .map((item) => normalizeProxy(item, windowSeconds, windowLabel));
    const sourceInfo = raw.sources || {};
    const podsWithSuccess = summary.podsWithSuccess !== undefined
      ? Number(summary.podsWithSuccess)
      : new Set(proxies.flatMap((proxy) => proxy.podsWorking)).size;
    const podsWithTraffic = summary.podsWithTraffic !== undefined
      ? Number(summary.podsWithTraffic)
      : new Set(proxies.flatMap((proxy) => proxy.podsSeen)).size;
    const healthyProxies = summary.healthyProxies !== undefined
      ? Number(summary.healthyProxies)
      : proxies.filter((proxy) => proxy.statusLabel === "Healthy").length;
    const degradedProxies = summary.degradedProxies !== undefined
      ? Number(summary.degradedProxies)
      : proxies.filter((proxy) => proxy.statusLabel === "Degraded").length;
    const brokenProxies = summary.brokenProxies !== undefined
      ? Number(summary.brokenProxies)
      : proxies.filter((proxy) => proxy.statusLabel === "Broken").length;
    const totalCalls = Number(summary.totalCalls ?? proxies.reduce((acc, proxy) => acc + proxy.stats.totalCalls, 0));
    const successCalls = Number(summary.successCalls ?? proxies.reduce((acc, proxy) => acc + proxy.stats.successCalls, 0));
    const failureCalls = Number(summary.failureCalls ?? proxies.reduce((acc, proxy) => acc + proxy.stats.failureCalls, 0));
    const totalElapsedSeconds = Number(summary.totalElapsedSeconds ?? proxies.reduce((acc, proxy) => acc + proxy.stats.totalElapsedSeconds, 0));
    const averageResponseMs = summary.averageResponseMs === null || summary.averageResponseMs === undefined
      ? (totalCalls > 0 ? (totalElapsedSeconds / totalCalls) * 1000 : null)
      : Number(summary.averageResponseMs);
    const requestsPerSecond = Number(summary.requestsPerSecond ?? (windowSeconds > 0 ? totalCalls / windowSeconds : 0));
    const requestsPerMinute = Number(summary.requestsPerMinute ?? requestsPerSecond * 60);
    const errorCounts = normalizeErrorCounts(summary.errorCounts || proxies.reduce((acc, proxy) => {
      for (const [label, count] of Object.entries(proxy.stats.errorCounts || {})) {
        acc[label] = (acc[label] || 0) + Number(count || 0);
      }
      return acc;
    }, {}));

    return {
      generatedAt: String(raw.generatedAt || ""),
      window: {
        spec: String(windowInfo.spec || windowLabel || "1h"),
        label: String(windowInfo.label || windowLabel || "1h"),
        seconds: windowSeconds,
      },
      summary: {
        proxyCount: Number(summary.proxyCount ?? proxies.length),
        sourcePodsTotal: Number(summary.sourcePodsTotal ?? sourceInfo.total ?? 0),
        sourcePodsResponded: Number(summary.sourcePodsResponded ?? sourceInfo.responded ?? 0),
        sourcePodsMissing: Number(summary.sourcePodsMissing ?? sourceInfo.missing ?? 0),
        healthyProxies,
        degradedProxies,
        brokenProxies,
        podsWithSuccess,
        podsWithTraffic,
        totalCalls,
        successCalls,
        failureCalls,
        failureRate: totalCalls > 0 ? failureCalls / totalCalls : 0,
        averageResponseMs,
        recentRequests: Number(summary.recentRequests ?? totalCalls),
        recentWindowSeconds: Number(summary.recentWindowSeconds ?? windowSeconds),
        requestsPerSecond,
        requestsPerMinute,
        errorCounts,
      },
      proxies,
      errorBreakdown: Array.isArray(raw.errorBreakdown) ? raw.errorBreakdown : [],
      sources: {
        total: Number(sourceInfo.total ?? summary.sourcePodsTotal ?? 0),
        responded: Number(sourceInfo.responded ?? summary.sourcePodsResponded ?? 0),
        missing: Number(sourceInfo.missing ?? summary.sourcePodsMissing ?? 0),
      },
    };
  }

  function metricHtml(label, value, tone) {
    return `
      <section class="metric-card tone-${escapeHtml(tone)}">
        <div class="metric-label">${escapeHtml(label)}</div>
        <div class="metric-value">${escapeHtml(value)}</div>
      </section>
    `;
  }

  function renderMetrics(summary) {
    metricsRoot.innerHTML = [
      metricHtml("Broken proxies", formatCount(summary.brokenProxies), summary.brokenProxies ? "error" : "muted"),
      metricHtml("Degraded proxies", formatCount(summary.degradedProxies), summary.degradedProxies ? "warning" : "muted"),
      metricHtml("Healthy proxies", formatCount(summary.healthyProxies), summary.healthyProxies ? "healthy" : "muted"),
      metricHtml("Pods with traffic", formatCount(summary.podsWithTraffic), "info"),
      metricHtml("Avg latency", formatLatency(summary.averageResponseMs), "info"),
      metricHtml("RPS / RPM", `${formatRate(summary.requestsPerSecond)} / ${formatRate(summary.requestsPerMinute)}`, "muted"),
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
    chartSuccessRateNode.textContent = total > 0 ? `${formatPercent(summary.successCalls / total)} success` : "No proxy calls yet";
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
      .map((segment) => {
        const share = segment.count / total;
        return `
          <div class="legend-item">
            <span class="legend-swatch" style="background:${segment.color};"></span>
            <span class="legend-label">${escapeHtml(segment.label)}</span>
            <strong>${formatCount(segment.count)}</strong>
            <span class="legend-share">${formatPercent(share)}</span>
          </div>
        `;
      })
      .join("");
  }

  function compareNumberDesc(a, b, selector) {
    const diff = Number(selector(b) || 0) - Number(selector(a) || 0);
    if (diff !== 0) return diff;
    return 0;
  }

  function sortProxies(proxies, key = sortKey) {
    const list = [...proxies];
    const byLabel = (left, right) => String(left.proxyLabel || "").localeCompare(String(right.proxyLabel || ""));
    const bySeverity = (left, right) => Number(right.statusSeverity || 0) - Number(left.statusSeverity || 0);
    const comparators = {
      bad_first(left, right) {
        return (
          bySeverity(left, right)
          || compareNumberDesc(left, right, (item) => item.stats.failureRate)
          || compareNumberDesc(left, right, (item) => item.stats.failureCalls)
          || compareNumberDesc(left, right, (item) => item.stats.totalCalls)
          || byLabel(left, right)
        );
      },
      failures_desc(left, right) {
        return (
          compareNumberDesc(left, right, (item) => item.stats.failureCalls)
          || compareNumberDesc(left, right, (item) => item.stats.failureRate)
          || bySeverity(left, right)
          || compareNumberDesc(left, right, (item) => item.stats.totalCalls)
          || byLabel(left, right)
        );
      },
      latency_desc(left, right) {
        return (
          compareNumberDesc(left, right, (item) => item.stats.averageResponseMs || 0)
          || compareNumberDesc(left, right, (item) => item.stats.failureRate)
          || compareNumberDesc(left, right, (item) => item.stats.totalCalls)
          || byLabel(left, right)
        );
      },
      pods_desc(left, right) {
        return (
          compareNumberDesc(left, right, (item) => item.workingPodCount)
          || compareNumberDesc(left, right, (item) => item.podCount)
          || compareNumberDesc(left, right, (item) => item.stats.failureRate)
          || byLabel(left, right)
        );
      },
      calls_desc(left, right) {
        return (
          compareNumberDesc(left, right, (item) => item.stats.totalCalls)
          || compareNumberDesc(left, right, (item) => item.stats.failureCalls)
          || compareNumberDesc(left, right, (item) => item.stats.failureRate)
          || byLabel(left, right)
        );
      },
      label_asc(left, right) {
        return byLabel(left, right);
      },
    };
    const comparator = comparators[key] || comparators.bad_first;
    list.sort(comparator);
    return list;
  }

  function matchesFilter(proxy) {
    if (activeFilter === "All") return true;
    return proxy.statusLabel === activeFilter;
  }

  function matchesSearch(proxy) {
    const needle = searchTerm.trim().toLowerCase();
    if (!needle) return true;
    return proxy.searchText.includes(needle);
  }

  function detailUrlFor(proxyKey) {
    const url = new URL(detailBaseUrl || window.location.href, window.location.href);
    url.searchParams.set("proxy", proxyKey);
    url.searchParams.set("window", selectedWindow);
    return url.toString();
  }

  function proxyAnomalyHtml(proxy) {
    const topError = proxy.stats.topError || { label: "", count: 0 };
    const errorLabel = topError.label ? `${topError.label} × ${formatCount(topError.count)}` : "—";
    return `
      <a class="proxy-anomaly-card" href="${escapeHtml(detailUrlFor(proxy.proxyKey))}">
        <div class="proxy-anomaly-head">
          <span class="pill tone-${escapeHtml(proxy.statusTone)}">${escapeHtml(proxy.statusLabel)}</span>
          <span class="proxy-anomaly-link">Open detail</span>
        </div>
        <div class="proxy-anomaly-title">${escapeHtml(proxy.proxyLabel)}</div>
        <div class="proxy-anomaly-meta">
          <span>${formatCount(proxy.workingPodCount)} / ${formatCount(proxy.podCount)} pods</span>
          <span>${formatCount(proxy.stats.failureCalls)} failures</span>
          <span>${escapeHtml(formatLatency(proxy.stats.averageResponseMs))}</span>
        </div>
        <div class="proxy-anomaly-footer">
          <span>${escapeHtml(topError.label || "No error")}</span>
          <strong>${escapeHtml(errorLabel)}</strong>
        </div>
      </a>
    `;
  }

  function proxyCardHtml(proxy) {
    const topError = proxy.stats.topError || { label: "", count: 0 };
    const errorLabel = topError.label ? `${topError.label} × ${formatCount(topError.count)}` : "No error";
    return `
      <a class="proxy-board-card" href="${escapeHtml(detailUrlFor(proxy.proxyKey))}">
        <div class="proxy-board-header">
          <div class="proxy-board-title-wrap">
            <code class="proxy-endpoint">${escapeHtml(proxy.proxyLabel)}</code>
            <div class="cell-subtle">${formatCount(proxy.workingPodCount)} pods with success · ${formatCount(proxy.podCount)} pods seen</div>
          </div>
          <div class="proxy-board-status">
            <span class="pill tone-${escapeHtml(proxy.statusTone)}">${escapeHtml(proxy.statusLabel)}</span>
            <span class="proxy-board-error">${escapeHtml(errorLabel)}</span>
          </div>
        </div>
        <div class="proxy-board-grid">
          <div class="proxy-board-cell">
            <span class="meta-label">Coverage</span>
            <strong>${formatCount(proxy.workingPodCount)} / ${formatCount(proxy.podCount)}</strong>
            <span class="cell-subtle">${formatCount(proxy.sourceCount)} source pods</span>
          </div>
          <div class="proxy-board-cell">
            <span class="meta-label">Success</span>
            <strong>${formatCount(proxy.stats.successCalls)}</strong>
            <span class="cell-subtle">${formatCount(proxy.stats.totalCalls)} total calls</span>
          </div>
          <div class="proxy-board-cell">
            <span class="meta-label">Failures</span>
            <strong>${formatCount(proxy.stats.failureCalls)}</strong>
            <span class="cell-subtle">${formatPercent(proxy.stats.failureRate)} failure rate</span>
          </div>
          <div class="proxy-board-cell">
            <span class="meta-label">Avg latency</span>
            <strong>${escapeHtml(formatLatency(proxy.stats.averageResponseMs))}</strong>
            <span class="cell-subtle">${escapeHtml(`${formatRate(proxy.stats.requestsPerSecond)} / ${formatRate(proxy.stats.requestsPerMinute)}`)} rps / rpm</span>
          </div>
        </div>
      </a>
    `;
  }

  function renderAnomalies() {
    const filtered = sortProxies(
      payload.proxies.filter((proxy) => matchesFilter(proxy) && matchesSearch(proxy)),
      "bad_first",
    ).slice(0, 3);
    anomaliesRoot.innerHTML = filtered.length
      ? filtered.map(proxyAnomalyHtml).join("")
      : "<div class=\"empty-state\">No proxy anomalies match the current filters.</div>";
  }

  function renderBoard() {
    const filtered = sortProxies(
      payload.proxies.filter((proxy) => matchesFilter(proxy) && matchesSearch(proxy)),
      sortKey,
    );
    boardRoot.innerHTML = filtered.length
      ? filtered.map(proxyCardHtml).join("")
      : "<div class=\"empty-state\">No proxies match the current filters.</div>";
  }

  function updateSyncState() {
    const updatedAt = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (!payload.summary.proxyCount) {
      syncState.textContent = `Waiting for proxy telemetry · window ${payload.window.label || selectedWindow} · updated ${updatedAt}`;
      return;
    }
    syncState.textContent = `${formatCount(payload.summary.podsWithSuccess)} pods reported successful proxy calls · ${payload.sources.responded} / ${payload.sources.total} parser pods responded · window ${payload.window.label || selectedWindow} · updated ${updatedAt}`;
  }

  function renderAll() {
    renderMetrics(payload.summary);
    renderChart(payload.summary, payload.errorBreakdown);
    renderAnomalies();
    renderBoard();
    updateSyncState();
  }

  function updateWindowUrl(value) {
    const url = new URL(window.location.href);
    if (value && value !== defaultWindow) {
      url.searchParams.set("window", value);
    } else {
      url.searchParams.delete("window");
    }
    window.history.replaceState({}, "", url.toString());
  }

  async function refreshData() {
    syncState.textContent = "Refreshing proxy telemetry...";
    try {
      const url = new URL(apiUrl, window.location.href);
      url.searchParams.set("window", selectedWindow);
      const response = await fetch(url.toString(), {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || data.message || `HTTP ${response.status}`);
      }
      payload = normalizePayload(data);
      selectedWindow = payload.window.spec || selectedWindow;
      windowSelect.value = selectedWindow;
      updateWindowUrl(selectedWindow);
      renderAll();
    } catch (error) {
      syncState.textContent = "Auto-refresh failed";
      if (window.autoUpdater && typeof window.autoUpdater.showToast === "function") {
        window.autoUpdater.showToast(`Proxy dashboard refresh failed: ${error.message}`, "error");
      }
    }
  }

  function setFilter(value) {
    activeFilter = value || "All";
    Array.from(statusFilterRoot.querySelectorAll("[data-filter]")).forEach((button) => {
      button.classList.toggle("active", (button.dataset.filter || "All") === activeFilter);
    });
    renderAnomalies();
    renderBoard();
  }

  function setSort(value) {
    sortKey = value || defaultSort;
    renderBoard();
  }

  function setWindow(value) {
    selectedWindow = value || defaultWindow;
    windowSelect.value = selectedWindow;
    updateWindowUrl(selectedWindow);
    refreshData();
  }

  statusFilterRoot.addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter]");
    if (!button) return;
    setFilter(button.dataset.filter || "All");
  });

  searchInput.addEventListener("input", () => {
    searchTerm = searchInput.value || "";
    renderAnomalies();
    renderBoard();
  });

  sortSelect.addEventListener("change", () => {
    setSort(sortSelect.value || defaultSort);
  });

  windowSelect.addEventListener("change", () => {
    setWindow(windowSelect.value || defaultWindow);
  });

  refreshButton.addEventListener("click", () => {
    refreshData();
  });

  updateWindowUrl(selectedWindow);
  renderAll();
  window.setInterval(refreshData, 15000);
})();
