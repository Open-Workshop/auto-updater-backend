import logging
import os
from contextlib import contextmanager
from typing import Any, Iterator

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

        RequestsInstrumentor().instrument()
    except Exception as exc:
        logging.warning("Requests instrumentation is unavailable: %s", exc)

    try:
        from opentelemetry.instrumentation.aiohttp_client import (
            AioHttpClientInstrumentor,
        )

        AioHttpClientInstrumentor().instrument()
    except Exception as exc:
        logging.warning("aiohttp instrumentation is unavailable: %s", exc)


def _load_trace_module():
    try:
        from opentelemetry import trace

        return trace
    except Exception:
        return None
