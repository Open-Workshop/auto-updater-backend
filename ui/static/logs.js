(() => {
  const configNode = document.getElementById("logs-config");
  const targetButtons = Array.from(document.querySelectorAll("#log-targets [data-target]"));
  const tagFilters = document.getElementById("log-tag-filters");
  const tailSelect = document.getElementById("log-tail");
  const pauseButton = document.getElementById("log-pause");
  const refreshButton = document.getElementById("log-refresh");
  const copyButton = document.getElementById("log-copy");
  const output = document.getElementById("log-output");
  const logState = document.getElementById("log-state");
  const logTargetLabel = document.getElementById("log-target-label");
  const podName = document.getElementById("log-pod-name");
  const containerName = document.getElementById("log-container-name");
  const updated = document.getElementById("log-updated");
  const networkRx = document.getElementById("log-network-rx");
  const networkTx = document.getElementById("log-network-tx");

  if (!configNode || !tailSelect || !pauseButton || !refreshButton || !copyButton || !output || !logState || !logTargetLabel || !podName || !containerName || !updated) {
    return;
  }

  const config = JSON.parse(configNode.textContent || "{}");
  const apiBase = config.apiBase || "";
  const ALL_TAG_OPTION = [
    { value: "all", label: "All" },
    { value: "steam", label: "Steam" },
    { value: "ow", label: "OW" },
    { value: "parser", label: "Parser" },
  ];
  const STATUS_TONES = {
    TRACE: "muted",
    DEBUG: "muted",
    INFO: "info",
    NOTICE: "info",
    SUCCESS: "healthy",
    WARN: "warning",
    WARNING: "warning",
    ERROR: "error",
    ERR: "error",
    CRITICAL: "error",
    FATAL: "error",
  };
  const ANSI_ESCAPE_RE = /\u001B\[[0-?]*[ -/]*[@-~]/g;
  const ANSI_C1_RE = /\u009B[0-?]*[ -/]*[@-~]/g;
  const TIMESTAMP_PREFIX_RE = /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?\s+)(.*)$/;
  const ACCESS_LOG_TIMESTAMP_RE = /\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]/g;
  let currentTarget = config.target || "parser";
  let parserTag = config.tag || "all";
  let availableTagOptions = ALL_TAG_OPTION.slice();
  let paused = false;
  let inFlight = false;
  let queuedForcedRefresh = false;
  let lastBody = "";
  let lastRxBytes = null;
  let lastTxBytes = null;
  let lastMetricsTime = null;
  let lastRxSpeed = null;
  let lastTxSpeed = null;
  let firstRxBytes = null;
  let firstTxBytes = null;
  let firstMetricsTime = null;

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function stripAnsi(value) {
    return String(value ?? "")
      .replace(ANSI_ESCAPE_RE, "")
      .replace(ANSI_C1_RE, "");
  }

  function normalizeLogText(text) {
    return stripAnsi(text)
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n");
  }

  function splitTimestamp(line) {
    const match = TIMESTAMP_PREFIX_RE.exec(line);
    if (!match) {
      return { timestamp: "", body: line };
    }
    return {
      timestamp: match[1].trim(),
      body: match[2],
    };
  }

  function parseTimestampMs(timestamp) {
    const match = /^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:,(\d{1,3}))?$/.exec(timestamp || "");
    if (!match) {
      return null;
    }
    const [, year, month, day, hour, minute, second, millis = "0"] = match;
    return Date.UTC(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
      Number(millis.padEnd(3, "0")),
    );
  }

  function formatRangeDuration(firstTimestamp, lastTimestamp) {
    const firstMs = parseTimestampMs(firstTimestamp);
    const lastMs = parseTimestampMs(lastTimestamp);
    if (firstMs == null || lastMs == null || lastMs <= firstMs) {
      return "";
    }
    return `${Math.round((lastMs - firstMs) / 1000)}s`;
  }

  function formatBytesToBits(bytesPerSecond) {
    if (bytesPerSecond == null || bytesPerSecond === 0) {
      return "0 bps";
    }
    const bitsPerSecond = bytesPerSecond * 8;
    if (bitsPerSecond >= 1e9) {
      return `${(bitsPerSecond / 1e9).toFixed(2)} Gbps`;
    } else if (bitsPerSecond >= 1e6) {
      return `${(bitsPerSecond / 1e6).toFixed(2)} Mbps`;
    } else if (bitsPerSecond >= 1e3) {
      return `${(bitsPerSecond / 1e3).toFixed(2)} Kbps`;
    } else {
      return `${bitsPerSecond} bps`;
    }
  }

  function calculateNetworkSpeed(currentBytes, firstBytes, currentTime, firstTime) {
    if (currentBytes == null || firstBytes == null || currentTime == null || firstTime == null) {
      return null;
    }
    const deltaBytes = currentBytes - firstBytes;
    const deltaTime = (currentTime - firstTime) / 1000; // Convert to seconds
    if (deltaTime <= 0 || deltaBytes < 0) {
      return null;
    }
    return deltaBytes / deltaTime;
  }

  function canonicalLogLine(line) {
    const { body } = splitTimestamp(line);
    return (body || line)
      .replace(ACCESS_LOG_TIMESTAMP_RE, "")
      .replace(/\s{2,}/g, " ")
      .trim();
  }

  function renderLogLine(line) {
    const sanitized = stripAnsi(line);
    let prefix = "";
    let token = "";
    let suffix = "";
    const { timestamp, body } = splitTimestamp(sanitized);
    if (timestamp) {
      const leveled = /^([A-Z]+)(.*)$/.exec(body);
      if (!leveled) {
        return escapeHtml(sanitized);
      }
      prefix = `${timestamp} `;
      [, token, suffix] = leveled;
    } else {
      const leveled = /^([A-Z]+)(\[\d+\].*)$/.exec(sanitized)
        || /^([A-Z]+)(\s+.*)$/.exec(sanitized);
      if (!leveled) {
        return escapeHtml(sanitized);
      }
      [, token, suffix] = leveled;
    }
    if (!token) {
      return escapeHtml(sanitized);
    }
    const tone = STATUS_TONES[token.toUpperCase()];
    if (!tone) {
      return escapeHtml(sanitized);
    }
    return `${escapeHtml(prefix)}<span class="log-status tone-${tone}">${escapeHtml(token)}</span>${escapeHtml(suffix)}`;
  }

  function renderLogEntry(line) {
    return `<span class="log-line">${renderLogLine(line)}</span>`;
  }

  function buildLogGroups(lines) {
    const groups = [];
    lines.forEach((line) => {
      const { timestamp, body } = splitTimestamp(line);
      const signature = canonicalLogLine(line);
      const previous = groups[groups.length - 1];
      if (previous && previous.signature === signature) {
        previous.lines.push(line);
        if (timestamp) {
          previous.lastTimestamp = timestamp;
        }
        return;
      }
      groups.push({
        signature,
        summaryLine: signature || body || line,
        lines: [line],
        firstTimestamp: timestamp,
        lastTimestamp: timestamp,
      });
    });
    return groups;
  }

  function stripTimestampMillis(timestamp) {
    return (timestamp || "").replace(/,\d{1,3}$/, "");
  }

  function renderLogGroup(group) {
    const countLabel = `${group.lines.length} repeated lines`;
    const durationText = formatRangeDuration(group.firstTimestamp, group.lastTimestamp);
    const firstTimestampClean = stripTimestampMillis(group.firstTimestamp);
    const lastTimestampClean = stripTimestampMillis(group.lastTimestamp);
    const rangeText = group.firstTimestamp && group.lastTimestamp
      ? group.firstTimestamp === group.lastTimestamp
        ? firstTimestampClean
        : `${firstTimestampClean} -> ${lastTimestampClean}${durationText ? ` (${durationText})` : ""}`
      : "";
    const summaryLine = group.summaryLine || "(blank line)";
    return `<details class="log-group"><summary class="log-group-summary"><span class="log-group-count">${escapeHtml(countLabel)}</span><span class="log-group-message">${renderLogLine(summaryLine)}</span>${rangeText ? `<span class="log-group-range">${escapeHtml(rangeText)}</span>` : ""}</summary><div class="log-group-body">${group.lines.map((line) => renderLogEntry(line)).join("")}</div></details>`;
  }

  function renderLogBody(text) {
    const normalized = normalizeLogText(text);
    const lines = normalized.split("\n");
    if (lines.length > 1 && lines[lines.length - 1] === "") {
      lines.pop();
    }
    return buildLogGroups(lines)
      .map((group) => (group.lines.length > 1 ? renderLogGroup(group) : renderLogEntry(group.lines[0])))
      .join("");
  }

  function updateHistory() {
    const url = new URL(window.location.href);
    url.searchParams.set("tab", "logs");
    url.searchParams.set("target", currentTarget);
    url.searchParams.set("tail", tailSelect.value);
    if (parserTag && parserTag !== "all" && currentTarget === "parser") {
      url.searchParams.set("tag", parserTag);
    } else {
      url.searchParams.delete("tag");
    }
    window.history.replaceState({}, "", url.toString());
  }

  function buildRawPayload(rawText, requestTarget, requestTail, requestTag) {
    return {
      target: requestTarget,
      tailLines: Number(requestTail) || 0,
      selectedTag: requestTag,
      availableTags: [],
      tagOptions: availableTagOptions,
      logText: rawText,
      podName: podName.textContent || "n/a",
      container: containerName.textContent || "n/a",
      rxBytes: null,
      txBytes: null,
    };
  }

  async function parseLogResponse(response, requestTarget, requestTail, requestTag) {
    const rawText = await response.text();
    const contentType = response.headers.get("content-type") || "";
    const trimmed = rawText.trim();
    const maybeJson = contentType.includes("application/json")
      || trimmed.startsWith("{")
      || trimmed.startsWith("[");
    if (maybeJson && trimmed) {
      try {
        return JSON.parse(rawText);
      } catch (_error) {
        // Show the raw upstream response in the log console instead of surfacing a JSON parse error.
      }
    }
    return buildRawPayload(rawText, requestTarget, requestTail, requestTag);
  }

  function setActiveTarget() {
    targetButtons.forEach((button) => {
      button.classList.toggle("active", button.dataset.target === currentTarget);
    });
    logTargetLabel.textContent = currentTarget === "tun" ? "TUN" : currentTarget.charAt(0).toUpperCase() + currentTarget.slice(1);
  }

  function renderTagFilters() {
    if (!tagFilters) {
      return;
    }
    const visible = currentTarget === "parser";
    tagFilters.hidden = !visible;
    if (!visible) {
      tagFilters.innerHTML = "";
      return;
    }
    tagFilters.innerHTML = availableTagOptions.map((option) => {
      const value = String(option.value || "all");
      const label = String(option.label || value.toUpperCase());
      const active = value === parserTag ? " active" : "";
      return `<button type="button" class="filter-chip${active}" data-log-tag="${escapeHtml(value)}">${escapeHtml(label)}</button>`;
    }).join("");
    Array.from(tagFilters.querySelectorAll("[data-log-tag]")).forEach((button) => {
      button.addEventListener("click", () => {
        parserTag = button.dataset.logTag || "all";
        renderTagFilters();
        refreshLogs(true);
      });
    });
  }

  function setTagOptions(options, preserveSelection = false) {
    if (!Array.isArray(options) || options.length === 0) {
      availableTagOptions = ALL_TAG_OPTION.slice();
    } else {
      availableTagOptions = options.map((option) => ({
        value: String((option && option.value) || "all"),
        label: String((option && option.label) || "All"),
      }));
    }
    if (!preserveSelection && !availableTagOptions.some((option) => option.value === parserTag)) {
      parserTag = "all";
    }
    renderTagFilters();
  }

  function nearBottom(element) {
    return element.scrollHeight - element.scrollTop - element.clientHeight < 48;
  }

  async function refreshLogs(force = false) {
    if ((!force && paused) || inFlight) {
      if (force) {
        queuedForcedRefresh = true;
      }
      return;
    }
    inFlight = true;
    logState.textContent = paused ? "Paused" : "Refreshing...";
    const stickToBottom = nearBottom(output);
    const requestTarget = currentTarget;
    const requestTail = tailSelect.value;
    const requestTag = requestTarget === "parser" ? parserTag : "all";
    try {
      const response = await fetch(`${apiBase}/${requestTarget}?tail=${requestTail}&tag=${encodeURIComponent(requestTag)}`, {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      const payload = await parseLogResponse(response, requestTarget, requestTail, requestTag);
      if (!response.ok && !payload.logText) {
        throw new Error(payload.error || `HTTP ${response.status}`);
      }
      const staleResponse = requestTarget !== currentTarget
        || requestTail !== tailSelect.value
        || (requestTarget === "parser" && requestTag !== parserTag);
      if (staleResponse) {
        return;
      }
      if (currentTarget === "parser") {
        parserTag = payload.selectedTag || parserTag || "all";
      }
      setTagOptions(payload.tagOptions, currentTarget !== "parser");
      let text = normalizeLogText(payload.logText || "");
      if (!text) {
        text = payload.selectedTag && payload.selectedTag !== "all"
          ? `(no ${payload.selectedTag} log lines in current tail)`
          : "(empty)";
      }
      if (text !== lastBody) {
        output.innerHTML = renderLogBody(text);
        lastBody = text;
        if (stickToBottom) {
          output.scrollTop = output.scrollHeight;
        }
      }
      podName.textContent = payload.podName || "n/a";
      containerName.textContent = payload.container || "n/a";
      const currentTime = Date.now();
      
      // Initialize first values if not set
      if (firstRxBytes === null && payload.rxBytes !== null) {
        firstRxBytes = payload.rxBytes;
        firstMetricsTime = currentTime;
      }
      if (firstTxBytes === null && payload.txBytes !== null) {
        firstTxBytes = payload.txBytes;
        if (firstMetricsTime === null) {
          firstMetricsTime = currentTime;
        }
      }
      
      // Calculate speed only when values change
      let rxSpeed = null;
      let txSpeed = null;
      
      if (payload.rxBytes !== null && firstRxBytes !== null && payload.rxBytes !== firstRxBytes) {
        rxSpeed = calculateNetworkSpeed(payload.rxBytes, firstRxBytes, currentTime, firstMetricsTime);
        if (rxSpeed !== null) {
          lastRxSpeed = rxSpeed;
          firstRxBytes = payload.rxBytes;
          firstMetricsTime = currentTime;
        }
      }
      
      if (payload.txBytes !== null && firstTxBytes !== null && payload.txBytes !== firstTxBytes) {
        txSpeed = calculateNetworkSpeed(payload.txBytes, firstTxBytes, currentTime, firstMetricsTime);
        if (txSpeed !== null) {
          lastTxSpeed = txSpeed;
          firstTxBytes = payload.txBytes;
          firstMetricsTime = currentTime;
        }
      }
      
      if (networkRx) {
        if (rxSpeed !== null) {
          networkRx.textContent = formatBytesToBits(rxSpeed);
        } else if (lastRxSpeed !== null) {
          // Show last known speed while waiting for metrics to update
          networkRx.textContent = formatBytesToBits(lastRxSpeed);
        } else if (payload.rxBytes !== null) {
          // First request: show total bytes instead of speed
          networkRx.textContent = `${(payload.rxBytes / 1024 / 1024).toFixed(2)} MB`;
        } else {
          networkRx.textContent = "n/a";
        }
      }
      if (networkTx) {
        if (txSpeed !== null) {
          networkTx.textContent = formatBytesToBits(txSpeed);
        } else if (lastTxSpeed !== null) {
          // Show last known speed while waiting for metrics to update
          networkTx.textContent = formatBytesToBits(lastTxSpeed);
        } else if (payload.txBytes !== null) {
          // First request: show total bytes instead of speed
          networkTx.textContent = `${(payload.txBytes / 1024 / 1024).toFixed(2)} MB`;
        } else {
          networkTx.textContent = "n/a";
        }
      }
      
      lastRxBytes = payload.rxBytes;
      lastTxBytes = payload.txBytes;
      lastMetricsTime = currentTime;
      updated.textContent = new Date().toLocaleTimeString();
      logState.textContent = paused ? "Paused" : "Live";
      updateHistory();
    } catch (error) {
      lastBody = normalizeLogText(`Failed to refresh logs: ${error.message}`);
      output.innerHTML = renderLogBody(lastBody);
      updated.textContent = new Date().toLocaleTimeString();
      logState.textContent = "Error";
      window.autoUpdater.showToast(`Log refresh failed: ${error.message}`, "error");
    } finally {
      inFlight = false;
      if (queuedForcedRefresh) {
        queuedForcedRefresh = false;
        refreshLogs(true);
      }
    }
  }

  targetButtons.forEach((button) => {
    button.addEventListener("click", () => {
      currentTarget = button.dataset.target || "parser";
      setActiveTarget();
      renderTagFilters();
      refreshLogs(true);
    });
  });

  tailSelect.addEventListener("change", () => refreshLogs(true));
  pauseButton.addEventListener("click", () => {
    paused = !paused;
    pauseButton.textContent = paused ? "Resume" : "Pause";
    logState.textContent = paused ? "Paused" : "Live";
    if (!paused) {
      refreshLogs(true);
    }
  });
  refreshButton.addEventListener("click", () => refreshLogs(true));
  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(lastBody || output.textContent || "");
      window.autoUpdater.showToast("Logs copied to clipboard", "success");
    } catch (error) {
      window.autoUpdater.showToast(`Copy failed: ${error.message}`, "error");
    }
  });

  setActiveTarget();
  renderTagFilters();
  refreshLogs(true);
  window.setInterval(() => refreshLogs(false), 2000);
})();
