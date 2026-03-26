(() => {
  const root = document.getElementById("toast-root");

  function showToast(message, kind = "info") {
    if (!root) return;
    const toast = document.createElement("section");
    toast.className = `toast ${kind}`;
    const body = document.createElement("div");
    body.className = "toast-body";
    body.textContent = String(message || "");
    const close = document.createElement("button");
    close.type = "button";
    close.className = "toast-close";
    close.setAttribute("aria-label", "Dismiss");
    close.textContent = "x";
    close.addEventListener("click", () => toast.remove());
    toast.appendChild(body);
    toast.appendChild(close);
    root.appendChild(toast);
    window.setTimeout(() => toast.remove(), kind === "error" ? 7000 : 4500);
  }

  async function parseResponse(response) {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return response.json();
    }
    return { message: await response.text() };
  }

  function bindActionForms(scope = document, onSuccess = null) {
    const forms = Array.from(scope.querySelectorAll("form[data-async='true']"));
    for (const form of forms) {
      if (form.dataset.bound === "true") {
        continue;
      }
      form.dataset.bound = "true";
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const confirmText = form.dataset.confirm || "";
        if (confirmText && !window.confirm(confirmText)) {
          return;
        }
        const button = form.querySelector("button[type='submit']");
        const previousLabel = button ? button.textContent : "";
        if (button) {
          button.disabled = true;
          button.textContent = "Working...";
        }
        try {
          const response = await fetch(form.action, {
            method: form.method || "POST",
            headers: { Accept: "application/json" },
            body: new FormData(form),
          });
          const payload = await parseResponse(response);
          if (!response.ok) {
            throw new Error(payload.error || payload.message || `HTTP ${response.status}`);
          }
          showToast(payload.message || "Done", payload.kind || "success");
          if (payload.redirectUrl && payload.redirectUrl !== window.location.pathname + window.location.search) {
            window.location.href = payload.redirectUrl;
            return;
          }
          if (typeof onSuccess === "function") {
            onSuccess(payload);
          }
        } catch (error) {
          showToast(error.message || "Action failed", "error");
        } finally {
          if (button) {
            button.disabled = false;
            button.textContent = previousLabel;
          }
        }
      });
    }
  }

  window.autoUpdater = { showToast, bindActionForms };
  if (window.__initialToast) {
    showToast(window.__initialToast.message, window.__initialToast.kind || "info");
  }
})();
