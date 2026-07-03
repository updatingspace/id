"""
OpenTelemetry setup for UpdSpace ID.

Tracing is disabled by default and becomes active only when OTEL_ENABLED=true.
The exporter target is intentionally configured through standard OTEL env vars.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from django.conf import settings
from django.http import HttpRequest

logger = logging.getLogger(__name__)

_configured = False


def configure_telemetry() -> None:
    """Configure OpenTelemetry instrumentation when explicitly enabled."""
    global _configured
    if _configured or not getattr(settings, "OTEL_ENABLED", False):
        return

    service_name = str(
        getattr(
            settings,
            "OTEL_SERVICE_NAME",
            getattr(settings, "MONIUM_SERVICE_NAME", "updspace-id"),
        )
    )
    cluster = str(getattr(settings, "MONIUM_CLUSTER", "default") or "default")
    endpoint = str(getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", "") or "")
    project = str(getattr(settings, "MONIUM_PROJECT", "") or "")
    api_key = str(getattr(settings, "MONIUM_API_KEY", "") or "")
    headers = _build_otlp_headers(
        endpoint=endpoint,
        explicit_headers=str(getattr(settings, "OTEL_EXPORTER_OTLP_HEADERS", "") or ""),
        project=project,
        api_key=api_key,
        cluster=cluster,
        service_name=service_name,
    )
    if _is_monium_endpoint(endpoint) and headers is None:
        logger.warning(
            "OpenTelemetry tracing is enabled but Monium credentials are incomplete"
        )
        return

    try:
        os.environ.setdefault(
            "OTEL_SERVICE_NAME",
            service_name,
        )
        os.environ.setdefault(
            "OTEL_TRACES_SAMPLER",
            str(getattr(settings, "OTEL_TRACES_SAMPLER", "parentbased_traceidratio")),
        )
        os.environ.setdefault(
            "OTEL_TRACES_SAMPLER_ARG",
            str(getattr(settings, "OTEL_TRACES_SAMPLER_ARG", "0.1")),
        )
        if endpoint:
            os.environ.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", str(endpoint))
        if headers:
            os.environ.setdefault(
                "OTEL_EXPORTER_OTLP_HEADERS",
                ",".join(f"{key}={value}" for key, value in headers),
            )

        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.django import DjangoInstrumentor
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception:
        logger.exception("OpenTelemetry dependencies are unavailable")
        return

    resource = Resource.create({SERVICE_NAME: service_name, "cluster": cluster})
    provider = TracerProvider(resource=resource)
    exporter_kwargs: dict[str, object] = {}
    if endpoint:
        exporter_kwargs["endpoint"] = endpoint
    if headers:
        exporter_kwargs["headers"] = headers
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(**exporter_kwargs)))
    trace.set_tracer_provider(provider)

    DjangoInstrumentor().instrument()
    RequestsInstrumentor().instrument()
    _configured = True
    logger.info("OpenTelemetry tracing configured")


def _is_monium_endpoint(endpoint: str) -> bool:
    host = urlparse(endpoint if "://" in endpoint else f"//{endpoint}").hostname or ""
    return host.endswith("monium.yandex.cloud")


def _build_otlp_headers(
    *,
    endpoint: str,
    explicit_headers: str,
    project: str,
    api_key: str,
    cluster: str,
    service_name: str,
) -> tuple[tuple[str, str], ...] | None:
    if explicit_headers:
        return tuple(
            tuple(part.strip() for part in item.split("=", 1))  # type: ignore[misc]
            for item in explicit_headers.split(",")
            if "=" in item
        )
    if not _is_monium_endpoint(endpoint):
        return ()
    if not project or not api_key:
        return None
    return (
        ("authorization", f"Api-Key {api_key}"),
        ("x-monium-project", project),
        ("x-monium-cluster", cluster),
        ("x-monium-service", service_name),
    )


def annotate_current_span(
    request: HttpRequest,
    *,
    route: str,
    status_code: int,
) -> None:
    """Attach safe request metadata to the active span."""
    try:
        from opentelemetry import trace
    except Exception:
        return

    span = trace.get_current_span()
    if not span or not span.is_recording():
        return

    attrs: dict[str, str | int] = {
        "http.route": route,
        "http.request_id": str(getattr(request, "request_id", "") or ""),
        "http.response.status_code": status_code,
    }
    tenant_id = getattr(request, "tenant_id", None)
    if tenant_id:
        attrs["enduser.tenant.id"] = str(tenant_id)
    try:
        user = getattr(request, "user", None)
        if user is not None and getattr(user, "is_authenticated", False):
            attrs["enduser.id"] = str(getattr(user, "pk", ""))
    except Exception:
        pass

    for key, value in attrs.items():
        if value != "":
            span.set_attribute(key, value)
