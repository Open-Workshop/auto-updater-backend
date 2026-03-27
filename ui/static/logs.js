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

  function renderLogLine(line) {
    const match = /^(\S+\s+\S+\s+)(\S+)(.*)$/.exec(line);
    if (!match) {
      return escapeHtml(line);
    }
    const [, prefix, token, suffix] = match;
    const tone = STATUS_TONES[token.toUpperCase()];
    if (!tone) {
      return escapeHtml(line);
    }
    return `${escapeHtml(prefix)}<span class="log-status tone-${tone}">${escapeHtml(token)}</span>${escapeHtml(suffix)}`;
  }

  function renderLogBody(text) {
    return String(text ?? "")
      .split("\n")
      .map((line) => `<span class="log-line">${renderLogLine(line)}</span>`)
      .join("\n");
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
      const text = payload.logText || "(empty)";
      if (text !== lastBody) {
        output.innerHTML = renderLogBody(text);
        lastBody = text;
        if (stickToBottom) {
          output.scrollTop = output.scrollHeight;
        }
      }
      podName.textContent = payload.podName || "n/a";
      containerName.textContent = payload.container || "n/a";
      updated.textContent = new Date().toLocaleTimeString();
      logState.textContent = paused ? "Paused" : "Live";
      updateHistory();
    } catch (error) {
      output.innerHTML = renderLogBody(`Failed to refresh logs: ${error.message}`);
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
      await navigator.clipboard.writeText(output.textContent || "");
      window.autoUpdater.showToast("Logs copied to clipboard", "success");
    } catch (error) {
      window.autoUpdater.showToast(`Copy failed: ${error.message}`, "error");
    }
  });

  setActiveTarget();
  refreshLogs(true);
  window.setInterval(() => refreshLogs(false), 2000);
})();
