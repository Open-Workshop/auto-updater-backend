from __future__ import annotations

import html
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass
class UISettings:
    namespace: str
    host: str
    port: int
    title: str
    base_path: str
    username: str
    password: str


def _normalize_base_path(value: str) -> str:
    raw = (value or "").strip()
    if not raw or raw == "/":
        return ""
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw.rstrip("/")


def load_ui_settings() -> UISettings:
    try:
        port = int(os.environ.get("OW_UI_PORT", "8080"))
    except ValueError:
        port = 8080
    return UISettings(
        namespace=os.environ.get("AUTO_UPDATER_NAMESPACE", "auto-updater").strip() or "auto-updater",
        host=os.environ.get("OW_UI_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=port,
        title=os.environ.get("OW_UI_TITLE", "Auto Updater Control Plane").strip()
        or "Auto Updater Control Plane",
        base_path=_normalize_base_path(os.environ.get("OW_UI_BASE_PATH", "")),
        username=os.environ.get("OW_UI_USERNAME", "").strip(),
        password=os.environ.get("OW_UI_PASSWORD", ""),
    )


def _escape(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _json_script(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False).replace("</", "<\\/")


def _json_dump_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _bool_from_form(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "on", "yes"}


def _int_from_form(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _float_from_form(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _url(settings: UISettings, path: str) -> str:
    normalized_path = path if path.startswith("/") else f"/{path}"
    if not settings.base_path:
        return normalized_path
    if normalized_path == "/":
        return settings.base_path + "/"
    return settings.base_path + normalized_path


def _toast_kind_from_message(message: str, kind: str = "") -> str:
    normalized = str(kind or "").strip().lower()
    if normalized in {"success", "error", "warning", "info"}:
        return normalized
    lowered = str(message or "").lower()
    if "failed" in lowered or "error" in lowered:
        return "error"
    if "deleted" in lowered:
        return "warning"
    return "success"


def _iso_to_datetime(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        rendered = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(rendered)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _format_time(value: Any) -> str:
    parsed = _iso_to_datetime(value)
    if not parsed:
        return "n/a"
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _truncate(value: Any, limit: int = 88) -> str:
    rendered = str(value or "").strip()
    if len(rendered) <= limit:
        return rendered
    return rendered[: limit - 1].rstrip() + "…"
