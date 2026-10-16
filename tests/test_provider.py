import ast
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import httpx
import pytest
from xmemo_agent_framework import Connection, Policy, Provider, ReadRoute, XMemoError


class RecordingTransport:
    def __init__(self, status=200, data=None):
        self.calls = []
        self.status = status
        self.data = data if data is not None else {"results": [{"id": "m-1", "content": "saved context"}]}

    def handle(self, request):
        self.calls.append(request)
        return httpx.Response(self.status, json=self.data)

    def connection(self):
        return Connection("https://local.invalid", "one-time-test-secret", transport=httpx.MockTransport(self.handle))


async def test_opt_in_and_after_run_never_make_requests():
    transport = RecordingTransport()
    connection = transport.connection()
    provider = Provider(connection)
    result = await provider.before_run("query", session_id="s")
    assert result.items == () and result.audit.outcome == "disabled"
    await provider.after_run("response worth saving")
    assert transport.calls == []
    await connection.aclose()


def test_capture_and_invalid_references_rejected():
    with pytest.raises(ValueError):
        Policy(capture_enabled=True)
    with pytest.raises(ValueError):
        Policy(route=ReadRoute.PROJECT, project_id="../remember")
    with pytest.raises(ValueError):
        Policy(max_tokens=0)
    with pytest.raises(ValueError):
        Policy(recall_enabled="false")


@pytest.mark.parametrize("status,code", [(401,"authentication_required"),(403,"permission_denied"),
    (422,"invalid_request"),(503,"authorization_unavailable"),(302,"unexpected_response")])
async def test_error_mapping_never_injects_raw_server_details(status, code):
    transport = RecordingTransport(status, {"detail": "one-time-test-secret"})
    connection = transport.connection()
    with pytest.raises(XMemoError) as caught:
        await Provider(connection, Policy(recall_enabled=True)).before_run("q")
    assert caught.value.status == status and caught.value.code == code
    assert "one-time-test-secret" not in str(caught.value)
    assert len(transport.calls) == 1
    assert caught.value.audit.outcome == code
    await connection.aclose()


@pytest.mark.parametrize("route,path,method,data", [
    (ReadRoute.SEARCH,"/v1/memories/search","GET", {"results":[{"id":"memory-1","content":"canary text"}]}),
    (ReadRoute.RECALL,"/v1/recall/context","POST", {"items":[{"id":"memory-1"}],"context_text":"canary text"}),
    (ReadRoute.PROJECT,"/v1/projects/project-1/context","POST", {"project_scope":{"scope_key":"tenant:project:project-1"},"recent_memories":[{"id":"memory-1","content":"canary text"}]}),
])
async def test_frozen_requests_provenance_and_host_audit(route,path,method,data):
    transport = RecordingTransport(data=data)
    connection = transport.connection()
    policy = Policy(recall_enabled=True, route=route, project_id="project-1", scope="requested", max_tokens=4000)
    result = await Provider(connection, policy, agent_id="agent-1", agent_instance_id="instance-1").before_run("q",session_id="session-1")
    request = transport.calls[0]
    assert request.url.path == path and request.method == method
    assert request.headers["x-request-id"] == result.audit.request_id
    assert result.audit.session_id == "session-1" and result.audit.agent_id == "agent-1"
    assert result.audit.agent_instance_id == "instance-1" and result.audit.timestamp
    assert result.audit.requested_scope == ("tenant:project:project-1" if route is ReadRoute.PROJECT else "requested")
    assert result.audit.outcome == "injected"
    assert "canary text" in result.items[0].text
    assert result.items[0].provenance.memory_ids == ("memory-1",)
    assert result.items[0].provenance.source_ids == ("memory-1",)
    assert result.items[0].provenance.source == "xmemo:"+path
    with pytest.raises(FrozenInstanceError):
        result.items[0].provenance.source = "forged"
    await connection.aclose()


async def test_unicode_budget_counts_provenance_and_reports_truncation():
    data = {"results":[{"id":"m-1","content":"界"*2000},{"id":"m-2","content":"second"}]}
    transport = RecordingTransport(data=data)
    connection = transport.connection()
    result = await Provider(connection, Policy(recall_enabled=True,route=ReadRoute.SEARCH,max_items=1,max_tokens=500)).before_run("q")
    assert len(result.items) == 1 and result.items[0].truncated
    assert result.dropped_items == 1 and result.truncated
    assert sum(len(item.render().encode()) for item in result.items) == result.budget_bytes <= 500
    assert json.loads(result.items[0].render())["provenance"]["memory_ids"] == ["m-1"]
    await connection.aclose()


async def test_no_source_id_or_tiny_budget_injects_nothing():
    transport = RecordingTransport(data={"items":[],"context_text":"unattributed query echo"})
    connection = transport.connection()
    assert not (await Provider(connection,Policy(recall_enabled=True)).before_run("q")).items
    transport.data = {"results":[{"id":"m-1","content":"saved"}]}
    result = await Provider(connection,Policy(recall_enabled=True,route=ReadRoute.SEARCH,max_tokens=1)).before_run("q")
    assert not result.items and result.truncated
    await connection.aclose()


async def test_timeout_and_invalid_success_shape():
    def timeout(request):
        raise httpx.ReadTimeout("credential detail", request=request)
    connection = Connection("https://local.invalid","secret",transport=httpx.MockTransport(timeout))
    with pytest.raises(XMemoError, match="timeout"):
        await Provider(connection,Policy(recall_enabled=True)).before_run("q")
    await connection.aclose()
    transport = RecordingTransport(data=["wrong schema"])
    connection = transport.connection()
    with pytest.raises(XMemoError, match="invalid_response"):
        await Provider(connection,Policy(recall_enabled=True)).before_run("q")
    await connection.aclose()


def test_connection_rejects_remote_http_and_embedded_credentials():
    for url in ["http://example.com","https://user:secret@example.com","https://example.com/remember"]:
        with pytest.raises(ValueError):
            Connection(url,"secret")


def test_static_boundary_and_route_allowlist():
    source = Path(__file__).parents[1]/"src"/"xmemo_agent_framework"
    for path in source.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            modules = [node.module or ""] if isinstance(node,ast.ImportFrom) else [a.name for a in node.names] if isinstance(node,ast.Import) else []
            assert all(not any(part in module.split(".") for part in ("memory_manager","server","server_imports","database","db","asyncpg","psycopg","psycopg2","sqlalchemy")) for module in modules)
            if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value.startswith("/v1/"):
                assert node.value in ("/v1/recall/context","/v1/memories/search","/v1/projects/",r"/v1/projects/[A-Za-z0-9_-]{1,128}/context")
    routes = set()
    for route in ReadRoute:
        routes.add(Policy(route=route,project_id="p").request("q")[:2])
    assert routes == {("POST","/v1/recall/context"),("POST","/v1/projects/p/context"),("GET","/v1/memories/search")}


async def test_local_item_limit_rejects_oversized_composite_pack():
    transport = RecordingTransport(data={"items":[{"id":"a"},{"id":"b"}],"context_text":"both records"})
    connection=transport.connection()
    result=await Provider(connection,Policy(recall_enabled=True,max_items=1)).before_run("q")
    assert not result.items and result.truncated and result.dropped_items==2
    await connection.aclose()


async def test_runtime_allowlist_rejects_even_a_forged_policy():
    class WritePolicy:
        def request(self, query):
            return "POST", "/v1/remember", {"content":query}
    transport=RecordingTransport()
    connection=transport.connection()
    with pytest.raises(ValueError,match="read-only"):
        await connection.read(WritePolicy(),"q","request")
    assert transport.calls==[]
    await connection.aclose()


def test_error_propagates_through_generator_context_without_masking_status():
    from contextlib import contextmanager
    @contextmanager
    def enclosing_scope():
        yield
    with pytest.raises(XMemoError) as caught:
        with enclosing_scope():
            raise XMemoError(500,'unexpected_response')
    assert caught.value.status==500
    assert caught.value.code=='unexpected_response'


async def test_audit_envelope_retains_injected_provenance_and_requested_team():
    transport=RecordingTransport()
    connection=transport.connection()
    result=await Provider(connection,Policy(recall_enabled=True,route=ReadRoute.SEARCH,team_id="requested-team")).before_run("q",session_id="host-session")
    assert result.audit.requested_team_id=="requested-team"
    assert result.audit.provenance==(result.items[0].provenance,)
    assert result.audit.provenance_na_reason is None
    await connection.aclose()


async def test_denial_audit_has_explicit_no_injection_provenance_reason():
    transport=RecordingTransport(403)
    connection=transport.connection()
    with pytest.raises(XMemoError) as caught:
        await Provider(connection,Policy(recall_enabled=True)).before_run("q")
    assert caught.value.audit.provenance==()
    assert caught.value.audit.provenance_na_reason=="Read failed before content injection"
    await connection.aclose()


@pytest.mark.parametrize('status',[200,403])
async def test_audit_request_id_uses_valid_server_response_id(status):
    server_id='73b6bdb8-b94f-4b6b-bf20-ed7f965db5a6'
    seen=[]
    async def respond(request):
        seen.append(request.headers['X-Request-ID'])
        return httpx.Response(status,json={'results':[{'id':'m-1','content':'saved'}]},headers={'X-XMemo-Audit-ID':server_id})
    connection=Connection('https://local.invalid','synthetic-token',transport=httpx.MockTransport(respond))
    provider=Provider(connection,Policy(recall_enabled=True,route=ReadRoute.SEARCH))
    if status==200:
        result=await provider.before_run('q');receipt=result.audit
        assert result.items[0].provenance.request_id==server_id
    else:
        with pytest.raises(XMemoError) as caught:await provider.before_run('q')
        receipt=caught.value.audit
    assert receipt.request_id==server_id and seen[0]!=server_id
    await connection.aclose()


async def test_malformed_server_response_id_is_not_retained():
    async def respond(request):return httpx.Response(200,json={'results':[]},headers={'X-XMemo-Audit-ID':'opaque-secret-details'})
    connection=Connection('https://local.invalid','synthetic-token',transport=httpx.MockTransport(respond))
    result=await Provider(connection,Policy(recall_enabled=True,route=ReadRoute.SEARCH)).before_run('q')
    assert result.audit.request_id!='opaque-secret-details'
    await connection.aclose()


def test_package_version_and_exports():
    import xmemo_agent_framework
    assert xmemo_agent_framework.__version__ == "0.2.0"
    assert "Connection" in xmemo_agent_framework.__all__
    assert "Provider" in xmemo_agent_framework.__all__
    assert "__version__" in xmemo_agent_framework.__all__


def test_maf_hook_clear_error_without_agent_framework(monkeypatch):
    import sys
    import importlib
    monkeypatch.setitem(sys.modules, "agent_framework", None)
    with pytest.raises(ImportError, match="Microsoft Agent Framework is required to use xmemo_agent_framework.maf"):
        if "xmemo_agent_framework.maf" in sys.modules:
            importlib.reload(sys.modules["xmemo_agent_framework.maf"])
        else:
            import xmemo_agent_framework.maf
    # Reload maf back cleanly for subsequent tests
    monkeypatch.undo()
    importlib.reload(sys.modules["xmemo_agent_framework.maf"])

