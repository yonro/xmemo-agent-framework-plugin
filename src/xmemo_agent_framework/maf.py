"""Optional pinned MAF 1.21 ContextProvider integration."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import uuid
try:
    from agent_framework import ContextProvider, Message
except ImportError as exc:
    raise ImportError(
        "Microsoft Agent Framework is required to use xmemo_agent_framework.maf. "
        "Install the package with the 'maf' extra: pip install 'xmemo-agent-framework[maf]'"
    ) from exc
from .connection import XMemoError
from .capture import CaptureDispatchError, CaptureRejected, RunProvenance


class XMemoContextProvider(ContextProvider):
    def __init__(self, provider, *, source_id="xmemo", capture=None):
        super().__init__(source_id)
        self.provider = provider
        self.capture = capture

    async def before_run(self, *, agent, session, context, state):
        query = "\n".join(message.text for message in context.input_messages if message.role == "user")
        try:
            result = await self.provider.before_run(query, session_id=context.session_id)
        except XMemoError as exc:
            context.metadata[self.source_id] = {"audit": asdict(exc.audit)}
            raise
        context.metadata[self.source_id] = asdict(result)
        context.extend_messages(self, [Message("user", [item.render()],
            additional_properties={"xmemo_provenance": asdict(item.provenance)}) for item in result.items])

    @staticmethod
    def _response_text(context):
        response = context.response
        if response is None:
            return ""
        return "\n".join(message.text for message in (response.messages or ())
                           if getattr(message, "text", None))

    @staticmethod
    def _capture_metadata(context, **fields):
        metadata = context.metadata.setdefault("xmemo", {})
        metadata.setdefault("capture", {}).update(fields)

    async def after_run(self, *, agent, session, context, state):
        if self.capture is None:
            return None
        content = self._response_text(context)
        session_id = context.session_id or getattr(session, "session_id", None) or "unknown-session"
        receipt = context.metadata.get(self.source_id, {}).get("audit", {})
        request_id = receipt.get("request_id")
        source_ids = (request_id,) if request_id else (str(uuid.uuid4()),)
        run_id = hashlib.sha256((session_id + ":" + source_ids[0]).encode()).hexdigest()[:32]
        provenance = RunProvenance(run_id, session_id, source_ids,
            datetime.now(timezone.utc).isoformat())
        try:
            candidate = await self.capture.after_run(content, provenance=provenance)
            write = await self.capture.dispatch(candidate)
        except CaptureRejected as exc:
            self._capture_metadata(context, outcome="rejected", gate=exc.gate,
                error_code="capture_rejected", reason=getattr(exc, "reason", None))
        except CaptureDispatchError as exc:
            self._capture_metadata(context, outcome="dispatch_error", error_code=exc.code,
                status=exc.status)
        except Exception as exc:
            self._capture_metadata(context, outcome="error", error_code=type(exc).__name__)
        else:
            self._capture_metadata(context, outcome="server_acknowledged", memory_id=write.memory_id,
                status=write.status, idempotency_key=write.idempotency_key,
                audit_request_id=write.audit_request_id)
        return None
