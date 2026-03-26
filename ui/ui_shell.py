from __future__ import annotations

from ui.ui_assets import render_template
from ui.ui_common import UISettings, _escape, _json_script, _toast_kind_from_message, _url


def _layout(settings: UISettings, body: str, *, flash: str = "", flash_kind: str = "info", page_title: str = "") -> str:
    initial_toast = ""
    if flash:
        initial_toast = f"""
        <script>
          window.__initialToast = {{
            message: {_json_script(flash)},
            kind: {_json_script(_toast_kind_from_message(flash, flash_kind))}
          }};
        </script>
        """
    title = page_title or settings.title
    return render_template(
        "layout.html",
        title=_escape(title),
        body=body,
        initial_toast=initial_toast,
        stylesheet_href=_escape(_url(settings, "/assets/app.css")),
        app_js_href=_escape(_url(settings, "/assets/app.js")),
    )
