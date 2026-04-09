"""Shared HTTP helpers for UI route handlers."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from aiohttp import web

from ui.ui_common import UISettings, _url


def _flash_redirect(
    settings: UISettings,
    path: str,
    message: str,
    kind: str = "info",
) -> web.HTTPFound:
    """Create a redirect response with flash message."""
    target = _url(settings, path)
    separator = "&" if "?" in path else "?"
    query = urlencode({"flash": message, "flashKind": kind})
    return web.HTTPFound(f"{target}{separator}{query}")


def _flash_from_request(request: web.Request) -> tuple[str, str]:
    """Extract flash message from request."""
    message = str(request.query.get("flash", "")).strip()
    kind = str(request.query.get("flashKind", "info")).strip().lower() or "info"
    return message, kind


def _wants_json(request: web.Request) -> bool:
    """Check if request wants JSON response."""
    accept = request.headers.get("Accept", "")
    return (
        "application/json" in accept
        or request.path.startswith("/api/")
        or "/api/" in request.path
    )


def _json_response(
    message: str,
    *,
    kind: str = "success",
    status: int = 200,
    **extra: Any,
) -> web.Response:
    """Create JSON response."""
    payload = {"message": message, "kind": kind}
    payload.update(extra)
    return web.json_response(payload, status=status)


def _action_response(
    request: web.Request,
    settings: UISettings,
    *,
    message: str,
    redirect_path: str,
    kind: str = "success",
    status: int = 200,
    extra: dict[str, Any] | None = None,
) -> web.StreamResponse:
    """Create JSON or redirect response for mutating actions."""
    extra = extra or {}
    if _wants_json(request):
        return _json_response(
            message,
            kind=kind,
            status=status,
            redirectUrl=_url(settings, redirect_path),
            **extra,
        )
    raise _flash_redirect(settings, redirect_path, message, kind)
