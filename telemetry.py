import logging
import os
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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
    except (ImportError, RuntimeError, ValueError, TypeError, AttributeError):
        logging.exception("Failed to initialize OpenTelemetry")
        _OTEL_ENABLED = False
        return False


def shutdown_telemetry() -> None:
    if not _OTEL_ENABLED:
        return

    try:
        import uptrace

        uptrace.shutdown()
    except (ImportError, RuntimeError, ValueError, TypeError, AttributeError):
        logging.exception("Failed to shutdown OpenTelemetry cleanly")


def _instrument_http_clients() -> None:
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor

        RequestsInstrumentor().instrument(
            request_hook=_requests_request_hook,
            response_hook=_requests_response_hook,
        )
    except (ImportError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
        logging.warning("Requests instrumentation is unavailable: %s", exc)

    try:
        from opentelemetry.instrumentation.aiohttp_client import (
            AioHttpClientInstrumentor,
        )

        AioHttpClientInstrumentor().instrument(
            request_hook=_aiohttp_request_hook,
            response_hook=_aiohttp_response_hook,
        )
    except (ImportError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
        logging.warning("aiohttp instrumentation is unavailable: %s", exc)


def _load_trace_module():
    try:
        from opentelemetry import trace

        return trace
    except ImportError:
        return None


def _requests_request_hook(span: Any, request_obj: Any) -> None:
    method = getattr(request_obj, "method", "")
    url = getattr(request_obj, "url", "")
    _apply_client_span_metadata(span, method, url)
    _apply_request_debug_metadata(
        span,
        url=str(url or ""),
        headers=getattr(request_obj, "headers", None),
    )


def _requests_response_hook(span: Any, _request_obj: Any, response_obj: Any) -> None:
    _apply_response_debug_metadata(
        span,
        status_code=getattr(response_obj, "status_code", None),
        reason=getattr(response_obj, "reason", ""),
        headers=getattr(response_obj, "headers", None),
    )


def _aiohttp_request_hook(span: Any, params: Any) -> None:
    method = getattr(params, "method", "")
    url = str(getattr(params, "url", "") or "")
    _apply_client_span_metadata(span, method, url)
    _apply_request_debug_metadata(
        span,
        url=url,
        headers=getattr(params, "headers", None),
    )


def _aiohttp_response_hook(span: Any, params: Any) -> None:
    response = getattr(params, "response", None)
    _apply_response_debug_metadata(
        span,
        status_code=getattr(response, "status", None),
        reason=getattr(response, "reason", ""),
        headers=getattr(response, "headers", None),
    )


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
    except (AttributeError, RuntimeError, ValueError, TypeError):
        pass

    _set_span_attribute(span, "http.route", route)


def _set_span_attribute(span: Any, key: str, value: Any) -> None:
    try:
        span.set_attribute(key, value)
    except (AttributeError, RuntimeError, ValueError, TypeError):
        pass


def _apply_request_debug_metadata(span: Any, url: str, headers: Any) -> None:
    if span is None:
        return

    sanitized_url, query_keys = _sanitize_url(url)
    if sanitized_url:
        _set_span_attribute(span, "http.url", sanitized_url)
        _set_span_attribute(span, "url.full", sanitized_url)
    if query_keys:
        _set_span_attribute(span, "http.query_keys", ",".join(query_keys))

    request_size = _parse_int_header(headers, "Content-Length")
    if request_size is not None:
        _set_span_attribute(span, "http.request.body.size", request_size)

    request_type = _get_header(headers, "Content-Type")
    if request_type:
        _set_span_attribute(span, "http.request.content_type", _clip_text(request_type))

    upload_file_name = _get_header(headers, "X-File-Name")
    if upload_file_name:
        _set_span_attribute(span, "ow.upload.file_name", _clip_text(upload_file_name))


def _apply_response_debug_metadata(
    span: Any,
    status_code: Any,
    reason: Any,
    headers: Any,
) -> None:
    if span is None:
        return

    try:
        status_int = int(status_code)
    except (TypeError, ValueError):
        status_int = None
    if status_int is not None:
        _set_span_attribute(span, "http.response.status_code", status_int)

    reason_text = str(reason or "").strip()
    if reason_text:
        _set_span_attribute(span, "http.response.reason", _clip_text(reason_text))

    response_size = _parse_int_header(headers, "Content-Length")
    if response_size is not None:
        _set_span_attribute(span, "http.response.body.size", response_size)

    response_type = _get_header(headers, "Content-Type")
    if response_type:
        _set_span_attribute(span, "http.response.content_type", _clip_text(response_type))

    retry_after = _get_header(headers, "Retry-After")
    if retry_after:
        _set_span_attribute(span, "http.response.retry_after", _clip_text(retry_after))

    request_id = _get_header(
        headers,
        "X-Request-ID",
        "X-Correlation-ID",
        "Request-ID",
        "X-Amzn-RequestId",
        "X-Amz-Request-Id",
    )
    if request_id:
        _set_span_attribute(span, "http.response.request_id", _clip_text(request_id))

    location = _get_header(headers, "Location")
    if location:
        _set_span_attribute(
            span,
            "http.response.location",
            _clip_text(_strip_query(location), max_len=512),
        )


def _strip_query(url: str) -> str:
    try:
        parsed = urlparse(url or "")
    except ValueError:
        return str(url or "")
    if not parsed.query:
        return str(url or "")
    return urlunparse(parsed._replace(query=""))


def _sanitize_url(url: str) -> tuple[str, list[str]]:
    try:
        parsed = urlparse(url or "")
    except ValueError:
        return str(url or ""), []
    if not parsed.query:
        return str(url or ""), []

    safe_pairs: list[tuple[str, str]] = []
    query_keys: list[str] = []
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        safe_key = _clip_text(str(key or ""), max_len=64)
        safe_pairs.append((safe_key, "redacted"))
        if safe_key and safe_key not in query_keys and len(query_keys) < 20:
            query_keys.append(safe_key)
    if not safe_pairs:
        return str(url or ""), []

    safe_query = urlencode(safe_pairs, doseq=True)
    return urlunparse(parsed._replace(query=safe_query)), query_keys


def _parse_int_header(headers: Any, *names: str) -> int | None:
    raw = _get_header(headers, *names)
    if not raw:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return value


def _get_header(headers: Any, *names: str) -> str:
    if headers is None:
        return ""

    getter = getattr(headers, "get", None)
    for name in names:
        value = None
        if callable(getter):
            value = getter(name)
            if value is None:
                value = getter(name.lower())
        elif isinstance(headers, dict):
            value = headers.get(name) or headers.get(name.lower())

        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text

    return ""


def _clip_text(value: str, max_len: int = 256) -> str:
    text = str(value or "")
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


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
