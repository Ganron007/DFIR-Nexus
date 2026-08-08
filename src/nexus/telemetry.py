"""Optional OpenTelemetry tracing for MCP tool calls.

Usage:
    pip install opentelemetry-api opentelemetry-sdk

Then set NEXUS_OTEL_ENABLED=true to activate tracing.
Each MCP tool call creates a span with the tool name and audit_id attribute.
"""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

_OTEL_ENABLED = os.environ.get("NEXUS_OTEL_ENABLED", "").lower() in ("1", "true", "yes")
_tracer = None

if _OTEL_ENABLED:
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        provider = TracerProvider()
        exporter = ConsoleSpanExporter()
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("dfir-nexus")
        logger.info("OpenTelemetry tracing enabled")
    except ImportError:
        logger.info("OpenTelemetry not installed. pip install opentelemetry-api opentelemetry-sdk")
        _OTEL_ENABLED = False


@contextmanager
def trace_tool_call(tool_name: str, audit_id: str | None = None, **attributes: Any) -> Generator:
    """Context manager that creates an OpenTelemetry span for a tool call.

    Usage:
        with trace_tool_call("run_command", audit_id=audit_id, host="DC-01"):
            result = execute_command()
    """
    if not _OTEL_ENABLED or _tracer is None:
        yield
        return

    attrs = {"tool.name": tool_name}
    if audit_id:
        attrs["audit_id"] = audit_id
    attrs.update(attributes)

    with _tracer.start_as_current_span(tool_name, attributes=attrs) as span:
        try:
            yield
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.status.Status(trace.status.StatusCode.ERROR, str(e)))
            raise
        else:
            span.set_status(trace.status.Status(trace.status.StatusCode.OK))
