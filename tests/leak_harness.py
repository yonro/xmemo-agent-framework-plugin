"""P1-S2 surfaces, using the same capture-core canary detector."""
from xmemo_agent_framework.capture import Finding, fragments, scan, redact

SURFACES = ("session_state", "injected_messages", "tool_arguments_results", "context_metadata",
            "application_exceptions", "http_debug", "otel_spans", "retry_timeout")
