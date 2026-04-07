(() => {
  const configNode = document.getElementById("logs-config");
  const targetButtons = Array.from(document.querySelectorAll("#log-targets [data-target]"));
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
  let paused = false;
  let inFlight = false;
  let lastBody = "";

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

  function formatBytesToBits(bytes) {
    if (bytes == null || bytes === 0) {
      return "0 bps";
    }
    const bits = bytes * 8;
    if (bits >= 1e9) {
      return `${(bits / 1e9).toFixed(2)} Gbps`;
    } else if (bits >= 1e6) {
      return `${(bits / 1e6).toFixed(2)} Mbps`;
    } else if (bits >= 1e3) {
      return `${(bits / 1e3).toFixed(2)} Kbps`;
    } else {
      return `${bits} bps`;
    }
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
    window.history.replaceState({}, "", url.toString());
  }

  function setActiveTarget() {
    targetButtons.forEach((button) => {
      button.classList.toggle("active", button.dataset.target === currentTarget);
    });
    logTargetLabel.textContent = currentTarget === "tun" ? "TUN" : currentTarget.charAt(0).toUpperCase() + currentTarget.slice(1);
  }

  function nearBottom(element) {
    return element.scrollHeight - element.scrollTop - element.clientHeight < 48;
  }

  async function refreshLogs(force = false) {
    if ((!force && paused) || inFlight) {
      return;
    }
    inFlight = true;
    logState.textContent = paused ? "Paused" : "Refreshing...";
    const stickToBottom = nearBottom(output);
    try {
      const response = await fetch(`${apiBase}/${currentTarget}?tail=${tailSelect.value}`, {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || `HTTP ${response.status}`);
      }
      const text = normalizeLogText(payload.logText || "(empty)");
      if (text !== lastBody) {
        output.innerHTML = renderLogBody(text);
        lastBody = text;
        if (stickToBottom) {
          output.scrollTop = output.scrollHeight;
        }
      }
      podName.textContent = payload.podName || "n/a";
      containerName.textContent = payload.container || "n/a";
      if (networkRx) {
        networkRx.textContent = formatBytesToBits(payload.rxBytes);
      }
      if (networkTx) {
        networkTx.textContent = formatBytesToBits(payload.txBytes);
      }
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
    }
  }

  targetButtons.forEach((button) => {
    button.addEventListener("click", () => {
      currentTarget = button.dataset.target || "parser";
      setActiveTarget();
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
  refreshLogs(true);
  window.setInterval(() => refreshLogs(false), 2000);
})();
