import logging
import os
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

_OTEL_READY = False
_OTEL_ENABLED = False


class _NoopSpan:
    def set_attribute(self, _key: str, _value: Any) -> None:
        return

    def record_exception(self, _exc: BaseException) -> None:
        return


@contextmanager
def start_span(name: str, attributes: dict[str, Any] | None = None) -> Iterator[Any]:
    trace = _load_trace_module()
    if trace is None:
        yield _NoopSpan()
        return

    tracer = trace.get_tracer("auto-updater-backend")
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for key, value in attributes.items():
                if value is not None:
                    span.set_attribute(key, value)
        yield span


def init_telemetry(
    service_name: str = "auto-updater-backend",
    service_version: str = "",
    deployment_environment: str = "",
) -> bool:
    global _OTEL_READY, _OTEL_ENABLED

    if _OTEL_READY:
        return _OTEL_ENABLED

    _OTEL_READY = True
    dsn = os.environ.get("UPTRACE_DSN", "").strip()
    if not dsn:
        logging.info("UPTRACE_DSN is not set, OpenTelemetry is disabled")
        _OTEL_ENABLED = False
        return False

    service_name = os.environ.get("OTEL_SERVICE_NAME", service_name).strip()
    service_version = os.environ.get("OTEL_SERVICE_VERSION", service_version).strip()
    deployment_environment = os.environ.get(
        "OTEL_DEPLOYMENT_ENVIRONMENT", deployment_environment
    ).strip()

    try:
        import uptrace

        uptrace.configure_opentelemetry(
            dsn=dsn,
            service_name=service_name,
            service_version=service_version,
            deployment_environment=deployment_environment,
        )
        _instrument_http_clients()
        _OTEL_ENABLED = True
        logging.info("OpenTelemetry is enabled and exporting to Uptrace")
        return True
    except Exception:
        logging.exception("Failed to initialize OpenTelemetry")
        _OTEL_ENABLED = False
        return False


def shutdown_telemetry() -> None:
    if not _OTEL_ENABLED:
        return

    try:
        import uptrace

        uptrace.shutdown()
    except Exception:
        logging.exception("Failed to shutdown OpenTelemetry cleanly")


def _instrument_http_clients() -> None:
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor

        RequestsInstrumentor().instrument(request_hook=_requests_request_hook)
    except Exception as exc:
        logging.warning("Requests instrumentation is unavailable: %s", exc)

    try:
        from opentelemetry.instrumentation.aiohttp_client import (
            AioHttpClientInstrumentor,
        )

        AioHttpClientInstrumentor().instrument(request_hook=_aiohttp_request_hook)
    except Exception as exc:
        logging.warning("aiohttp instrumentation is unavailable: %s", exc)


def _load_trace_module():
    try:
        from opentelemetry import trace

        return trace
    except Exception:
        return None


def _requests_request_hook(span: Any, request_obj: Any) -> None:
    method = getattr(request_obj, "method", "")
    url = getattr(request_obj, "url", "")
    _apply_client_span_metadata(span, method, url)


def _aiohttp_request_hook(span: Any, params: Any) -> None:
    method = getattr(params, "method", "")
    url = str(getattr(params, "url", "") or "")
    _apply_client_span_metadata(span, method, url)


def _apply_client_span_metadata(span: Any, method: str, url: str) -> None:
    if span is None:
        return
    is_recording = getattr(span, "is_recording", None)
    if callable(is_recording) and not is_recording():
        return

    parsed = urlparse(url or "")
    route = _normalize_route(parsed.path)
    host = parsed.netloc or parsed.hostname or ""

    if host:
        span_name = f"{(method or 'HTTP').upper()} {host}{route}"
    else:
        span_name = f"{(method or 'HTTP').upper()} {route}"

    try:
        span.update_name(span_name)
    except Exception:
        pass

    _set_span_attribute(span, "http.route", route)


def _set_span_attribute(span: Any, key: str, value: Any) -> None:
    try:
        span.set_attribute(key, value)
    except Exception:
        pass


def _normalize_route(path: str) -> str:
    if not path:
        return "/"

    normalized_parts: list[str] = []
    for part in path.split("/"):
        if not part:
            continue
        if part.isdigit():
            normalized_parts.append("{id}")
            continue
        normalized_parts.append(part)

    if not normalized_parts:
        return "/"
    return "/" + "/".join(normalized_parts)
