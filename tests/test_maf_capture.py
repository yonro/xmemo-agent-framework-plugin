import asyncio
import json
from dataclasses import dataclass
import pytest
from agent_framework import AgentResponse, Message, SessionContext
from xmemo_agent_framework.capture import Behavior, CaptureDispatchError, CaptureRejected, Target
from xmemo_agent_framework.maf import XMemoContextProvider


@dataclass
class Candidate:
    content: str
    provenance: object
    idempotency_key: str = "key"


class RecordingCapture:
    def __init__(self, *, target=Target.REMEMBER, failure=None):
        self.policy = type("Policy", (), {"target": target})()
        self.failure = failure
        self.prepared = []
        self.dispatched = []

    async def after_run(self, content, *, provenance):
        if self.failure == "reject":
            raise CaptureRejected(4)
        self.prepared.append((content, provenance))
        return Candidate(content, provenance, "idempotency:" + provenance.run_id)

    async def dispatch(self, candidate):
        if self.failure == "dispatch":
            raise CaptureDispatchError(503, "permission_denied")
        self.dispatched.append(candidate)
        return type("Receipt", (), {"memory_id": "00000000-0000-4000-8000-000000000001",
            "status": 201, "idempotency_key": candidate.idempotency_key,
            "audit_request_id": "00000000-0000-4000-8000-000000000002"})()


def context(session_id, text="saved marker"):
    c = SessionContext(session_id=session_id, input_messages=[Message("user", ["q"])])
    c.metadata["xmemo"] = {"audit": {"request_id": "00000000-0000-4000-8000-000000000003"}}
    c._response = AgentResponse(messages=[Message("assistant", [text])])
    return c


class RecordingContextProvider(XMemoContextProvider):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_context = None

    async def after_run(self, *, agent, session, context, state):
        await super().after_run(agent=agent, session=session, context=context, state=state)
        self.last_context = context


@pytest.mark.asyncio
async def test_default_off_after_run_makes_zero_capture_calls():
    capture = RecordingCapture()
    provider = XMemoContextProvider(object(), capture=None)
    c = context("s-off")
    await provider.after_run(agent=None, session=None, context=c, state={})
    assert capture.prepared == [] and capture.dispatched == []


@pytest.mark.asyncio
async def test_enabled_after_run_dispatches_exactly_once_with_bound_provenance():
    capture = RecordingCapture()
    provider = XMemoContextProvider(object(), capture=capture)
    c = context("s-on", "marker: 45_days")
    await provider.after_run(agent=None, session=None, context=c, state={})
    assert len(capture.prepared) == len(capture.dispatched) == 1
    content, provenance = capture.prepared[0]
    assert content == "marker: 45_days"
    assert provenance.session_id == "s-on"
    assert provenance.source_ids == ("00000000-0000-4000-8000-000000000003",)
    assert c.metadata["xmemo"]["capture"]["outcome"] == "server_acknowledged"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["reject", "dispatch"])
async def test_failure_does_not_escape_or_write(failure):
    capture = RecordingCapture(failure=failure)
    provider = XMemoContextProvider(object(), capture=capture)
    c = context("s-fail", "safe marker")
    await provider.after_run(agent=None, session=None, context=c, state={})
    assert not capture.dispatched
    assert c.metadata["xmemo"]["capture"]["outcome"] in {"rejected", "dispatch_error"}


@pytest.mark.asyncio
async def test_state_and_event_are_forwarded_to_capture_contract():
    for target in (Target.STATE, Target.EVENT):
        capture = RecordingCapture(target=target)
        provider = XMemoContextProvider(object(), capture=capture)
        c = context("s-target")
        await provider.after_run(agent=None, session=None, context=c, state={})
        assert len(capture.prepared) == len(capture.dispatched) == 1
        assert c.metadata["xmemo"]["capture"]["outcome"] == "server_acknowledged"


@pytest.mark.asyncio
async def test_concurrent_sessions_keep_provenance_separate():
    capture = RecordingCapture()
    provider = XMemoContextProvider(object(), capture=capture)
    await asyncio.gather(*(provider.after_run(agent=None, session=None,
        context=context(name, name + " reply"), state={}) for name in ("session-a", "session-b")))
    assert {item[1].session_id for item in capture.prepared} == {"session-a", "session-b"}
    assert len({item[1].run_id for item in capture.prepared}) == 2

@pytest.mark.asyncio
async def test_real_agent_run_uses_real_capture_provider_and_one_mock_remember_post():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from test_capture import responses
    from agent_framework import Agent, BaseChatClient, ChatResponse
    from xmemo_agent_framework import Connection
    from xmemo_agent_framework.capture import CapturePolicy, CaptureProvider, ResolvedIdentity
    from xmemo_agent_framework.maf import XMemoContextProvider
    import httpx

    calls = []
    def handle(request):
        calls.append(request)
        if request.url.path == "/api/v1/remember":
            return httpx.Response(201, request=request,
                headers={"X-XMemo-Audit-ID": "00000000-0000-4000-8000-000000000004"},
                json={"id": "00000000-0000-4000-8000-000000000005"})
        return httpx.Response(200, request=request, json={"results": []})

    class FakeClient(BaseChatClient):
        async def _inner_get_response(self, *, messages, stream, options, **kwargs):
            return ChatResponse(messages=[Message("assistant", ["agent marker"])], response_id="fake")

    class ReadStub:
        async def before_run(self, query, *, session_id):
            from xmemo_agent_framework.provenance import ContextResult, AuditEnvelope
            from datetime import datetime, timezone
            return ContextResult((), AuditEnvelope("00000000-0000-4000-8000-000000000003", session_id, None, None,
                "recall", None, None, "test", datetime.now(timezone.utc).isoformat(), "no_content", ()))

    connection = Connection("https://server.test", "mos_test:abcdefghijklmnopqrstuvwxyz0123456789-secret",
        transport=httpx.MockTransport(handle))
    identity = ResolvedIdentity.from_server_responses(connection, *responses(connection))
    capture = CaptureProvider(connection, CapturePolicy(enabled=True, target=Target.REMEMBER,
        behavior=Behavior.SEMANTIC_KEY_SAME_CONTENT_NOOP, canaries=(connection._client.headers["Authorization"],)), identity=identity)
    provider = RecordingContextProvider(ReadStub(), capture=capture)
    agent = Agent(FakeClient(), context_providers=[provider])
    await agent.run("question", session=agent.create_session())
    remember = [r for r in calls if r.url.path == "/api/v1/remember"]
    assert len(remember) == 1
    assert json.loads(remember[0].content)["content"] == "agent marker"
    await connection.aclose()


@pytest.mark.asyncio
async def test_real_agent_run_reply_containing_secret_makes_zero_remember_posts():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from test_capture import CANARY, responses
    from agent_framework import Agent, BaseChatClient, ChatResponse
    from xmemo_agent_framework import Connection
    from xmemo_agent_framework.capture import Behavior, CapturePolicy, CaptureProvider, ResolvedIdentity, Target
    from xmemo_agent_framework.maf import XMemoContextProvider
    import httpx

    calls = []
    def handle(request):
        calls.append(request)
        if request.url.path == "/api/v1/remember":
            return httpx.Response(201, request=request,
                headers={"X-XMemo-Audit-ID": "00000000-0000-4000-8000-000000000004"},
                json={"id": "00000000-0000-4000-8000-000000000005"})
        return httpx.Response(200, request=request, json={"results": []})

    class SecretClient(BaseChatClient):
        async def _inner_get_response(self, *, messages, stream, options, **kwargs):
            return ChatResponse(messages=[Message("assistant", ["-----BEGIN RSA PRIVATE KEY-----\nsensitive_token_bytes"])], response_id="fake-secret")

    class ReadStub:
        async def before_run(self, query, *, session_id):
            from xmemo_agent_framework.provenance import ContextResult, AuditEnvelope
            from datetime import datetime, timezone
            return ContextResult((), AuditEnvelope("00000000-0000-4000-8000-000000000003", session_id, None, None,
                "recall", None, None, "test", datetime.now(timezone.utc).isoformat(), "no_content", ()))

    connection = Connection("https://server.test", CANARY, transport=httpx.MockTransport(handle))
    identity = ResolvedIdentity.from_server_responses(connection, *responses(connection))
    capture = CaptureProvider(connection, CapturePolicy(enabled=True, target=Target.REMEMBER,
        behavior=Behavior.SEMANTIC_KEY_SAME_CONTENT_NOOP, canaries=(CANARY,)), identity=identity)
    provider = RecordingContextProvider(ReadStub(), capture=capture)
    agent = Agent(SecretClient(), context_providers=[provider])
    await agent.run("question", session=agent.create_session())
    remember = [r for r in calls if r.url.path == "/api/v1/remember"]
    assert len(remember) == 0
    assert provider.last_context is not None
    cap_meta = provider.last_context.metadata["xmemo"]["capture"]
    assert cap_meta["outcome"] == "rejected"
    assert cap_meta["gate"] == 4
    import json
    meta_text = json.dumps(cap_meta)
    assert "PRIVATE KEY" not in meta_text
    assert "sensitive_token_bytes" not in meta_text
    await connection.aclose()


@pytest.mark.asyncio
async def test_real_agent_run_capture_none_with_real_read_provider_makes_zero_remember_posts():
    from agent_framework import Agent, BaseChatClient, ChatResponse
    from xmemo_agent_framework import Connection, Policy, Provider, ReadRoute
    from xmemo_agent_framework.maf import XMemoContextProvider
    import httpx

    calls = []
    def handle(request):
        calls.append(request)
        if request.url.path == "/v1/recall/context":
            return httpx.Response(200, request=request,
                headers={"X-XMemo-Audit-ID": "00000000-0000-4000-8000-000000000006"},
                json={"results": [{"id": "m-1", "content": "saved context"}]})
        return httpx.Response(200, request=request, json={"results": []})

    class FakeClient(BaseChatClient):
        async def _inner_get_response(self, *, messages, stream, options, **kwargs):
            return ChatResponse(messages=[Message("assistant", ["safe marker without capture"])], response_id="fake-no-cap")

    connection = Connection("https://server.test", "mos_test:abcdefghijklmnopqrstuvwxyz0123456789-secret",
        transport=httpx.MockTransport(handle))
    read_provider = Provider(connection, Policy(recall_enabled=True, route=ReadRoute.RECALL,
        max_items=5, max_tokens=1000))
    provider = XMemoContextProvider(read_provider, capture=None)
    agent = Agent(FakeClient(), context_providers=[provider])
    await agent.run("question to recall", session=agent.create_session())
    recall = [r for r in calls if r.url.path == "/v1/recall/context"]
    remember = [r for r in calls if r.url.path == "/api/v1/remember"]
    assert len(recall) == 1
    assert len(remember) == 0
    await connection.aclose()


def _target_policy(target, *, state_key=None, event_type=None):
    from xmemo_agent_framework.capture import CapturePolicy

    behavior = Behavior.STATE_VERSIONED_UPSERT if target is Target.STATE else Behavior.EVENT_APPEND_NO_DEDUPE
    return CapturePolicy(enabled=True, target=target, behavior=behavior,
        canaries=("mos_test:abcdefghijklmnopqrstuvwxyz0123456789-secret",),
        state_key=state_key, event_type=event_type)


def _agent_capture_fixture(target, *, state_key=None, event_type=None, response_text="target marker", status=200,
                           behavior=None):
    import httpx
    from tests.test_capture import responses
    from agent_framework import Agent, BaseChatClient, ChatResponse
    from xmemo_agent_framework import Connection
    from xmemo_agent_framework.capture import CaptureProvider, ResolvedIdentity
    from xmemo_agent_framework.maf import XMemoContextProvider

    calls = []
    audit_id = "00000000-0000-4000-8000-000000000010"
    memory_id = "00000000-0000-4000-8000-000000000011"

    def handle(request):
        calls.append(request)
        if request.url.path in {"/api/v1/update_state", "/api/v1/timeline/events", "/api/v1/remember"}:
            if status == "timeout":
                raise httpx.ReadTimeout("private transport detail", request=request)
            return httpx.Response(status, request=request,
                headers={"X-XMemo-Audit-ID": audit_id},
                json={"id": memory_id} if 200 <= status < 300 else {"detail": "private server detail"})
        return httpx.Response(200, request=request, json={"results": []})

    class FakeClient(BaseChatClient):
        async def _inner_get_response(self, *, messages, stream, options, **kwargs):
            return ChatResponse(messages=[Message("assistant", [response_text])], response_id="fake-target")

    class ReadStub:
        async def before_run(self, query, *, session_id):
            from xmemo_agent_framework.provenance import ContextResult, AuditEnvelope
            from datetime import datetime, timezone
            return ContextResult((), AuditEnvelope("00000000-0000-4000-8000-000000000012", session_id, None, None,
                "recall", None, None, "test", datetime.now(timezone.utc).isoformat(), "no_content", ()))

    connection = Connection("https://server.test", "mos_test:abcdefghijklmnopqrstuvwxyz0123456789-secret",
        transport=httpx.MockTransport(handle))
    identity = ResolvedIdentity.from_server_responses(connection, *responses(connection))
    policy = _target_policy(target, state_key=state_key, event_type=event_type)
    if behavior is not None:
        from dataclasses import replace
        policy = replace(policy, behavior=behavior)
    capture = CaptureProvider(connection, policy, identity=identity)

    provider = RecordingContextProvider(ReadStub(), capture=capture)
    agent = Agent(FakeClient(), context_providers=[provider])
    return agent, connection, calls, provider, audit_id


@pytest.mark.asyncio
@pytest.mark.parametrize("target,kwargs,path", [
    (Target.STATE, {"state_key": "project-handoff"}, "/api/v1/update_state"),
    (Target.EVENT, {"event_type": "decision"}, "/api/v1/timeline/events"),
])
async def test_real_agent_run_state_and_event_dispatch_exact_route_and_body(target, kwargs, path):
    agent, connection, calls, provider, audit_id = _agent_capture_fixture(target, **kwargs)
    await agent.run("question", session=agent.create_session())
    writes = [request for request in calls if request.url.path in {
        "/api/v1/update_state", "/api/v1/timeline/events", "/api/v1/remember"}]
    assert len(writes) == 1 and writes[0].url.path == path
    body = json.loads(writes[0].content)
    assert body["content"] == "target marker"
    assert body["bucket"] == "work" and body["scope"] == "tenant:project:project"
    assert body["source"] == "agent" and body["metadata"]["capture"]["idempotency_key"]
    if target is Target.STATE:
        assert body["state_key"] == "project-handoff"
    else:
        assert body["event_type"] == "decision"
        assert body["session_id"]
        assert body["occurred_at"] == body["metadata"]["capture"]["occurred_at"]
    assert provider.last_context.metadata["xmemo"]["capture"]["outcome"] == "server_acknowledged"
    assert provider.last_context.metadata["xmemo"]["capture"]["audit_request_id"] == audit_id
    await connection.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("target,kwargs", [
    (Target.STATE, {}),
    (Target.EVENT, {}),
])
async def test_real_agent_run_missing_target_field_makes_zero_posts(target, kwargs):
    agent, connection, calls, provider, _ = _agent_capture_fixture(target, **kwargs)
    await agent.run("question", session=agent.create_session())
    assert not [request for request in calls if request.url.path in {
        "/api/v1/update_state", "/api/v1/timeline/events", "/api/v1/remember"}]
    assert provider.last_context.metadata["xmemo"]["capture"]["outcome"] == "rejected"
    assert provider.last_context.metadata["xmemo"]["capture"]["gate"] == 9
    await connection.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("target,kwargs,behavior", [
    (Target.STATE, {"state_key": "project-handoff"}, Behavior.EVENT_APPEND_NO_DEDUPE),
    (Target.EVENT, {"event_type": "decision"}, Behavior.STATE_VERSIONED_UPSERT),
])
async def test_real_agent_run_behavior_mismatch_makes_zero_posts(target, kwargs, behavior):
    agent, connection, calls, provider, _ = _agent_capture_fixture(
        target, behavior=behavior, **kwargs)
    await agent.run("question", session=agent.create_session())
    assert not [request for request in calls if request.url.path in {
        "/api/v1/update_state", "/api/v1/timeline/events", "/api/v1/remember"}]
    capture_metadata = provider.last_context.metadata["xmemo"]["capture"]
    assert capture_metadata["outcome"] == "rejected"
    assert capture_metadata["gate"] == 7
    assert capture_metadata["reason"] == f"behavior does not match target {target.value}"
    await connection.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("target,kwargs", [
    (Target.STATE, {"state_key": "project-handoff"}),
    (Target.EVENT, {"event_type": "decision"}),
])
async def test_real_agent_run_secret_target_reply_makes_zero_posts(target, kwargs):
    secret = "-----BEGIN RSA PRIVATE KEY-----\nsensitive_token_bytes\n-----END RSA PRIVATE KEY-----"
    agent, connection, calls, provider, _ = _agent_capture_fixture(target, response_text=secret, **kwargs)
    await agent.run("question", session=agent.create_session())
    assert not [request for request in calls if request.url.path in {
        "/api/v1/update_state", "/api/v1/timeline/events", "/api/v1/remember"}]
    assert provider.last_context.metadata["xmemo"]["capture"]["outcome"] == "rejected"
    assert provider.last_context.metadata["xmemo"]["capture"]["gate"] == 4
    await connection.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("target,kwargs,status", [
    (Target.STATE, {"state_key": "project-handoff"}, 401),
    (Target.EVENT, {"event_type": "decision"}, 503),
    (Target.STATE, {"state_key": "project-handoff"}, "timeout"),
])
async def test_real_agent_run_target_failure_has_one_attempt_and_safe_metadata(target, kwargs, status):
    agent, connection, calls, provider, _ = _agent_capture_fixture(target, status=status, **kwargs)
    await agent.run("question", session=agent.create_session())
    writes = [request for request in calls if request.url.path in {
        "/api/v1/update_state", "/api/v1/timeline/events", "/api/v1/remember"}]
    assert len(writes) == 1
    capture_metadata = provider.last_context.metadata["xmemo"]["capture"]
    assert capture_metadata["outcome"] == "dispatch_error"
    if status == "timeout":
        assert capture_metadata["error_code"] == "write_outcome_unknown"
    else:
        assert capture_metadata["status"] == status
    await connection.aclose()
