import httpx
import pytest
from xmemo_agent_framework import Connection, Policy, Provider, ReadRoute


async def test_real_maf_session_context_injection_and_after_run_no_write():
    framework = pytest.importorskip("agent_framework")
    from xmemo_agent_framework.maf import XMemoContextProvider
    calls=[]
    def handle(request):
        calls.append(request)
        return httpx.Response(200,json={"results":[{"id":"m-1","content":"own saved context"}]})
    connection=Connection("https://local.invalid","secret",transport=httpx.MockTransport(handle))
    provider=XMemoContextProvider(Provider(connection,Policy(recall_enabled=True,route=ReadRoute.SEARCH)))
    context=framework.SessionContext(session_id="host-session",input_messages=[framework.Message("user",["q"])])
    await provider.before_run(agent=None,session=None,context=context,state={})
    assert len(context.context_messages["xmemo"])==1
    assert "own saved context" in context.context_messages["xmemo"][0].text
    assert context.metadata["xmemo"]["audit"]["session_id"]=="host-session"
    await provider.after_run(agent=None,session=None,context=context,state={})
    assert len(calls)==1
    await connection.aclose()
