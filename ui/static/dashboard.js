(() => {
  const root = document.getElementById("instance-table-body");
  const searchInput = document.getElementById("instance-search");
  const filterButtons = Array.from(document.querySelectorAll("#instance-filters [data-filter]"));
  const refreshButton = document.getElementById("dashboard-refresh");
  const syncState = document.getElementById("dashboard-sync-state");
  const metricsRoot = document.getElementById("dashboard-metrics");
  const payloadNode = document.getElementById("dashboard-payload");
  const configNode = document.getElementById("dashboard-config");

  if (!root || !payloadNode || !configNode) {
    return;
  }

  const config = JSON.parse(configNode.textContent || "{}");
  const apiUrl = config.apiUrl || "";
  let activeFilter = "All";
  let searchTerm = "";
  let items = JSON.parse(payloadNode.textContent || "{}").items || [];

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function toneForSync(value) {
    if (value === "Running") return "info";
    if (value === "Failed") return "warning";
    if (value === "Succeeded") return "healthy";
    return "muted";
  }

  function countItems(list) {
    const counts = { All: list.length, Healthy: 0, Syncing: 0, Degraded: 0, Error: 0, Disabled: 0 };
    for (const item of list) {
      if (counts[item.health] !== undefined) counts[item.health] += 1;
    }
    return counts;
  }

  function metricHtml(label, value, tone) {
    return `
      <section class="metric-card tone-${tone}">
        <div class="metric-label">${escapeHtml(label)}</div>
        <div class="metric-value">${escapeHtml(value)}</div>
      </section>
    `;
  }

  function rowHtml(item) {
    const toggleLabel = item.enabled ? "Pause" : "Resume";
    return `
      <tr data-health="${escapeHtml(item.health)}" data-instance="${escapeHtml(item.name)}">
        <td>
          <div class="primary-cell">
            <a class="row-link" href="${escapeHtml(item.urls.detail)}">${escapeHtml(item.name)}</a>
            <div class="cell-subtle">Steam ${escapeHtml(item.source.steamAppId)} · OW ${escapeHtml(item.source.owGameId)}</div>
          </div>
        </td>
        <td><span class="pill tone-${item.enabled ? "healthy" : "muted"}">${item.enabled ? "Enabled" : "Paused"}</span></td>
        <td><span class="pill tone-${escapeHtml(item.healthTone)}">${escapeHtml(item.health)}</span></td>
        <td><span class="pill tone-${toneForSync(item.syncState)}">${escapeHtml(item.syncState)}</span></td>
        <td>${escapeHtml(item.lastSyncLabel)}</td>
        <td class="error-cell">${escapeHtml(item.errorSummary || "—")}</td>
        <td>
          <span class="pill tone-${escapeHtml(item.parser.tone)}">${escapeHtml(item.parser.state)}</span>
          <div class="cell-subtle">${escapeHtml(item.parser.podName || "n/a")}</div>
        </td>
        <td>
          <span class="pill tone-${escapeHtml(item.runner.tone)}">${escapeHtml(item.runner.state)}</span>
          <div class="cell-subtle">${escapeHtml(item.runner.podName || "n/a")}</div>
        </td>
        <td class="actions-cell">
          <a class="button secondary" href="${escapeHtml(item.urls.detail)}">Open</a>
          <a class="button secondary" href="${escapeHtml(item.urls.logs)}">Logs</a>
          <form class="inline-form" method="post" action="${escapeHtml(item.urls.sync)}" data-async="true" data-confirm="Trigger sync now for ${escapeHtml(item.name)}?">
            <input type="hidden" name="return_path" value="/">
            <button type="submit" class="button">Sync now</button>
          </form>
          <form class="inline-form" method="post" action="${escapeHtml(item.urls.toggle)}" data-async="true" data-confirm="${toggleLabel} ${escapeHtml(item.name)}?">
            <input type="hidden" name="return_path" value="/">
            <button type="submit" class="button secondary">${toggleLabel}</button>
          </form>
          <form class="inline-form" method="post" action="${escapeHtml(item.urls.delete)}" data-async="true" data-confirm="Delete ${escapeHtml(item.name)}? This also removes the managed secrets.">
            <input type="hidden" name="return_path" value="/">
            <button type="submit" class="button warn">Delete</button>
          </form>
        </td>
      </tr>
    `;
  }

  function renderMetrics(counts) {
    metricsRoot.innerHTML = [
      metricHtml("All instances", counts.All, "muted"),
      metricHtml("Healthy", counts.Healthy, "healthy"),
      metricHtml("Syncing", counts.Syncing, "info"),
      metricHtml("Degraded", counts.Degraded, "warning"),
      metricHtml("Error", counts.Error, "error"),
      metricHtml("Paused", counts.Disabled, "muted"),
    ].join("");
  }

  function renderTable() {
    const filtered = items.filter((item) => {
      const matchesFilter = activeFilter === "All" || item.health === activeFilter;
      const needle = searchTerm.trim().toLowerCase();
      if (!needle) return matchesFilter;
      const haystack = [
        item.name,
        item.source.steamAppId,
        item.source.owGameId,
        item.errorSummary,
        item.parser.podName,
        item.runner.podName,
      ].join(" ").toLowerCase();
      return matchesFilter && haystack.includes(needle);
    });
    root.innerHTML = filtered.map(rowHtml).join("") || `
      <tr>
        <td colspan="9">
          <div class="empty-state">No instances match the current filters.</div>
        </td>
      </tr>
    `;
    window.autoUpdater.bindActionForms(root, refreshData);
  }

  function renderAll() {
    renderMetrics(countItems(items));
    renderTable();
  }

  async function refreshData() {
    syncState.textContent = "Refreshing...";
    try {
      const response = await fetch(apiUrl, { headers: { Accept: "application/json" }, cache: "no-store" });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || `HTTP ${response.status}`);
      }
      items = payload.items || [];
      renderAll();
      syncState.textContent = `Auto-refresh every 10s · updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
      syncState.textContent = "Auto-refresh failed";
      window.autoUpdater.showToast(`Dashboard refresh failed: ${error.message}`, "error");
    }
  }

  filterButtons.forEach((button) => {
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter || "All";
      filterButtons.forEach((node) => node.classList.toggle("active", node === button));
      renderTable();
    });
  });
  searchInput.addEventListener("input", () => {
    searchTerm = searchInput.value || "";
    renderTable();
  });
  refreshButton.addEventListener("click", refreshData);
  renderAll();
  window.autoUpdater.bindActionForms(document, refreshData);
  window.setInterval(refreshData, 10000);
})();
