(() => {
  const form = document.getElementById("proxy-detail-window-form");
  const windowSelect = document.getElementById("proxy-detail-window-select");
  if (!form || !windowSelect) {
    return;
  }

  windowSelect.addEventListener("change", () => {
    form.submit();
  });
})();
