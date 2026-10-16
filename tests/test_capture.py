import ast
from dataclasses import replace
import json
from pathlib import Path
import uuid
import httpx
import pytest
from xmemo_agent_framework import Connection, Policy, Provider
from xmemo_agent_framework.capture import (
    Behavior, CapturePolicy, CaptureProvider, CaptureRejected, ResolvedIdentity,
    RunProvenance, Target, fragments, scan,
)

CANARY='mos_test:abcdefghijklmnopqrstuvwxyz0123456789-secret'
SOURCE='11111111-1111-4111-8111-111111111111'


def responses(connection, scopes='memory:read, memory:write'):
    headers={'Authorization':connection._client.headers['Authorization']}
    identity=httpx.Response(200,request=httpx.Request('POST','https://server.test/mcp',headers=headers,
        json={'method':'tools/call','params':{'name':'get_mcp_identity'}}),
        headers={'X-XMemo-Audit-ID':str(uuid.uuid4())},json={'result':{'content':[{'type':'text','text':
        'Owner ID: owner\nAgent ID: agent\nScopes: '+scopes+'\nTenant: '+json.dumps({'organization_id':'org','workspace_id':'ws','project_id':'project'})}]}})
    project=httpx.Response(200,request=httpx.Request('POST','https://server.test/v1/projects/project/context',headers=headers),
        headers={'X-XMemo-Audit-ID':str(uuid.uuid4())},json={'project_scope':{'owner_id':'owner','organization_id':'org',
            'workspace_id':'ws','project_id':'project','scope_key':'tenant:project:project','team_id':None}})
    return identity,project


@pytest.fixture
async def fixture():
    calls=[]
    async def transport(request):calls.append(request);return httpx.Response(500)
    connection=Connection('https://server.test',CANARY,transport=httpx.MockTransport(transport))
    identity=ResolvedIdentity.from_server_responses(connection,*responses(connection))
    policy=CapturePolicy(enabled=True,target=Target.REMEMBER,behavior=Behavior.SEMANTIC_KEY_SAME_CONTENT_NOOP,canaries=(CANARY,))
    provenance=RunProvenance('run','session',(SOURCE,),'2026-10-13T00:00:00+09:00')
    yield connection,identity,policy,provenance,calls
    await connection.aclose()


@pytest.mark.parametrize('gate',range(1,9))
async def test_every_capture_gate_fails_closed_with_zero_requests(fixture,gate):
    connection,identity,policy,provenance,calls=fixture
    content='Saved project result'
    if gate==1:policy=replace(policy,enabled=False)
    elif gate==2:identity=ResolvedIdentity.from_server_responses(connection,*responses(connection,scopes='memory:read'))
    elif gate==3:identity={'owner':'model-owner','scopes':['memory:write']}
    elif gate==4:content='x'*65537
    elif gate==5:provenance=replace(provenance,source_ids=())
    elif gate==6:provenance=replace(provenance,run_id='')
    elif gate==7:policy=replace(policy,behavior=Behavior.UNKNOWN)
    elif gate==8:policy=replace(policy,target='invented-write')
    with pytest.raises(CaptureRejected) as exc:
        await CaptureProvider(connection,policy,identity=identity).after_run(content,provenance=provenance)
    assert exc.value.gate==gate and calls==[]
    assert content not in str(exc.value)


async def test_valid_candidate_builds_exact_remember_request_without_sending(fixture):
    connection,identity,policy,provenance,calls=fixture
    provider=CaptureProvider(connection,policy,identity=identity)
    one=await provider.after_run('Saved result',provenance=provenance)
    two=await provider.after_run('Saved result',provenance=provenance)
    assert one==two and calls==[]
    assert one.method=='POST' and one.path=='/api/v1/remember'
    assert json.loads(one.body_json)=={'content':'Saved result','path':'capture/project','bucket':'work','scope':'tenant:project:project','source':'agent',
        'semantic_key':'maf-capture:'+one.idempotency_key,'dedupe':True,'metadata':{'capture':{'run_id':'run',
        'session_id':'session','source_ids':[SOURCE],'occurred_at':provenance.occurred_at,
        'server_receipts':list(identity.receipts),'idempotency_key':one.idempotency_key}}}
    assert len(one.idempotency_key)==64
    changed=await provider.after_run('Changed result',provenance=provenance)
    other_run=await provider.after_run('Saved result',provenance=replace(provenance,run_id='other'))
    assert len({one.idempotency_key,changed.idempotency_key,other_run.idempotency_key})==3


async def test_canary_fragments_and_credential_patterns_redacted_before_candidate(fixture):
    connection,identity,policy,provenance,calls=fixture
    text='Result '+CANARY+' '+CANARY.split(':')[1][5:17]+' Bearer sensitive-private-key\npassword=private-password'
    candidate=await CaptureProvider(connection,policy,identity=identity).after_run(text,provenance=provenance)
    assert not scan({'candidate':candidate.body_json},[CANARY]) and calls==[]
    assert 'sensitive-private-key' not in candidate.body_json and 'private-password' not in candidate.body_json
    assert '[REDACTED_' in candidate.body_json
    assert all(part not in candidate.body_json for _,part in fragments(CANARY))


@pytest.mark.parametrize('mutation',['credential','origin','owner','tenant','agent','operation','http_error'])
async def test_identity_requires_bound_authenticated_server_responses(fixture,mutation):
    connection,_,_,_,calls=fixture
    identity,project=responses(connection)
    if mutation=='credential':identity.request.headers['Authorization']='Bearer other'
    elif mutation=='origin':identity.request.url=httpx.URL('https://foreign.test/mcp')
    elif mutation=='http_error':identity.status_code=401
    else:
        raw=identity.json()
        if mutation=='owner':raw['result']['content'][0]['text']=raw['result']['content'][0]['text'].replace('Owner ID: owner','Owner ID: other')
        elif mutation=='tenant':raw['result']['content'][0]['text']=raw['result']['content'][0]['text'].replace('"org"','"foreign"')
        elif mutation=='agent':raw['result']['content'][0]['text']=raw['result']['content'][0]['text'].replace('Agent ID: agent','Agent ID: none')
        elif mutation=='operation':identity.request=httpx.Request('POST','https://server.test/mcp',headers=identity.request.headers,json={'method':'tools/call','params':{'name':'remember'}})
        identity=httpx.Response(200,request=identity.request,headers=identity.headers,json=raw)
    with pytest.raises(CaptureRejected):ResolvedIdentity.from_server_responses(connection,identity,project)
    assert calls==[]


@pytest.mark.parametrize('target,kwargs',[(Target.STATE,{'state_key':'project-handoff'}),(Target.EVENT,{'event_type':'decision'})])
async def test_state_and_event_require_target_specific_behavior(fixture,target,kwargs):
    connection,identity,policy,provenance,calls=fixture
    with pytest.raises(CaptureRejected) as exc:
        await CaptureProvider(connection,replace(policy,target=target,**kwargs),identity=identity).after_run('Result',provenance=provenance)
    assert exc.value.gate==7 and calls==[]


@pytest.mark.parametrize('target,kwargs,gate',[
    (Target.STATE,{},9),
    (Target.EVENT,{},9),
    (Target.STATE,{'state_key':''},9),
    (Target.STATE,{'state_key':'Project-Handoff'},9),
    (Target.STATE,{'state_key':'-project-handoff'},9),
    (Target.STATE,{'state_key':'project/handoff'},9),
    (Target.STATE,{'state_key':'a' * 129},9),
    (Target.EVENT,{'event_type':''},9),
    (Target.EVENT,{'event_type':'Decision'},9),
    (Target.EVENT,{'event_type':'-decision'},9),
    (Target.EVENT,{'event_type':'event/type'},9),
    (Target.EVENT,{'event_type':'a' * 129},9),
])
async def test_state_and_event_require_explicit_configuration(fixture,target,kwargs,gate):
    connection,identity,policy,provenance,calls=fixture
    behavior = Behavior.STATE_VERSIONED_UPSERT if target is Target.STATE else Behavior.EVENT_APPEND_NO_DEDUPE
    with pytest.raises(CaptureRejected) as exc:
        await CaptureProvider(connection,replace(policy,target=target,behavior=behavior,**kwargs),identity=identity).after_run('Result',provenance=provenance)
    assert exc.value.gate==gate and calls==[]


@pytest.mark.parametrize('target,behavior,kwargs,path',[
    (Target.STATE,Behavior.STATE_VERSIONED_UPSERT,{'state_key':'project-handoff'},'/api/v1/update_state'),
    (Target.EVENT,Behavior.EVENT_APPEND_NO_DEDUPE,{'event_type':'decision'},'/api/v1/timeline/events'),
])
async def test_state_and_event_build_route_specific_candidates(fixture,target,behavior,kwargs,path):
    connection,identity,policy,provenance,calls=fixture
    candidate=await CaptureProvider(connection,replace(policy,target=target,behavior=behavior,**kwargs),identity=identity).after_run('Saved result',provenance=provenance)
    body=json.loads(candidate.body_json)
    assert candidate.path==path and candidate.method=='POST' and calls==[]
    assert body['content']=='Saved result' and body['bucket']=='work' and body['scope']==identity.scope
    assert body['source']==identity.agent and body['metadata']['capture']['idempotency_key']==candidate.idempotency_key
    if target is Target.STATE:
        assert body['state_key']=='project-handoff'
    else:
        assert body['event_type']=='decision'
        assert body['occurred_at']==provenance.occurred_at and body['session_id']==provenance.session_id


async def test_v01_remains_read_only_and_rejects_capture(fixture):
    connection,_,_,_,calls=fixture
    with pytest.raises(ValueError):Policy(capture_enabled=True)
    assert await Provider(connection).after_run('Result') is None
    assert calls==[]


def test_write_routes_only_occur_in_capture_module_and_dispatch_is_explicit():
    source=Path(__file__).parents[1]/'src'/'xmemo_agent_framework'
    write_paths={'/api/v1/remember','/v1/remember','/api/v1/update_state','/v1/update_state','/api/v1/timeline/events','/v1/timeline/events'}
    for path in source.glob('*.py'):
        tree=ast.parse(path.read_text())
        strings={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)}
        if strings&write_paths:assert path.name=='capture.py'
        if path.name=='capture.py':
            calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in {'request','send','post','put','patch','delete'}]
            assert len(calls)==1 and calls[0].func.attr=='request'
            assert len(calls[0].args)==2
            assert all(isinstance(arg,ast.Attribute) and arg.attr in {'method','path'} for arg in calls[0].args)


async def test_rotated_connection_cannot_reuse_old_identity(fixture):
    connection,identity,policy,provenance,calls=fixture
    connection._client.headers['Authorization']='Bearer rotated'
    with pytest.raises(CaptureRejected) as exc:
        await CaptureProvider(connection,policy,identity=identity).after_run('Result',provenance=provenance)
    assert exc.value.gate==3 and calls==[]


@pytest.mark.parametrize('secret',['sk-ant-'+'a'*30,'ghp_'+'b'*30,
    'eyJheader.eyJpayload.signature','-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----',
    'postgres://username:password@database.test/db'])
async def test_deterministic_credential_patterns_do_not_reach_candidate(fixture,secret):
    connection,identity,policy,provenance,calls=fixture
    candidate=await CaptureProvider(connection,policy,identity=identity).after_run('Result '+secret,provenance=provenance)
    assert secret not in candidate.body_json and calls==[]


async def test_incomplete_private_key_is_rejected(fixture):
    connection,identity,policy,provenance,calls=fixture
    with pytest.raises(CaptureRejected) as exc:
        await CaptureProvider(connection,policy,identity=identity).after_run('-----BEGIN PRIVATE KEY-----\nunclosed',provenance=provenance)
    assert exc.value.gate==4 and calls==[]


async def test_connection_credential_detected_even_if_not_in_extra_canaries(fixture):
    connection,identity,policy,provenance,calls=fixture
    policy=replace(policy,canaries=('other-high-entropy-canary-value-abcdefghijklmnop',))
    candidate=await CaptureProvider(connection,policy,identity=identity).after_run('Result '+CANARY,provenance=provenance)
    assert not scan({'candidate':candidate.body_json},[CANARY]) and calls==[]


@pytest.mark.parametrize('tamper',['content','key','path','unsealed','disabled'])
async def test_dispatch_rechecks_candidate_and_policy_before_http(fixture,tamper):
    connection,identity,policy,provenance,calls=fixture
    provider=CaptureProvider(connection,policy,identity=identity)
    candidate=await provider.after_run('Result',provenance=provenance)
    if tamper=='content':
        body=json.loads(candidate.body_json);body['content']='different'
        candidate=replace(candidate,body_json=json.dumps(body,sort_keys=True,separators=(',',':')))
    elif tamper=='key':candidate=replace(candidate,idempotency_key='changed')
    elif tamper=='path':candidate=replace(candidate,path='/api/v1/update_state')
    elif tamper=='unsealed':candidate=replace(candidate,seal=None)
    else:provider.policy=replace(policy,enabled=False)
    with pytest.raises(CaptureRejected):await provider.dispatch(candidate)
    assert calls==[]


@pytest.mark.parametrize('response_kind',[201,401,403,503,'timeout','invalid'])
async def test_dispatch_safe_result_or_error_no_retry(fixture,response_kind):
    from xmemo_agent_framework.capture import CaptureDispatchError
    connection,identity,policy,provenance,calls=fixture
    async def host(request):
        calls.append(request)
        if response_kind=='timeout':raise httpx.ReadTimeout('private transport detail',request=request)
        status=201 if response_kind=='invalid' else response_kind
        body={'id':SOURCE} if response_kind==201 else {'id':'malformed'} if response_kind=='invalid' else {'error':'private server detail'}
        return httpx.Response(status,json=body,headers={'X-XMemo-Audit-ID':SOURCE})
    connection._client._transport=httpx.MockTransport(host)
    provider=CaptureProvider(connection,policy,identity=identity)
    candidate=await provider.after_run('Result',provenance=provenance)
    if response_kind==201:
        receipt=await provider.dispatch(candidate)
        assert receipt.memory_id==SOURCE and receipt.audit_request_id==SOURCE
    else:
        with pytest.raises(CaptureDispatchError) as exc:await provider.dispatch(candidate)
        assert 'private' not in str(exc.value)
        if response_kind in ('timeout','invalid'):assert exc.value.code=='write_outcome_unknown'
    assert len(calls)==1
    assert calls[0].method=='POST' and calls[0].url.path=='/api/v1/remember'
    assert calls[0].headers['X-MAF-Session-ID']==provenance.session_id


async def test_identity_accepts_single_sse_response_for_same_rpc_id(fixture):
    connection,_,_,_,calls=fixture
    identity,project=responses(connection)
    payload=identity.json();payload['id']=1
    request=httpx.Request('POST','https://server.test/mcp',headers=identity.request.headers,
        json={'id':1,'method':'tools/call','params':{'name':'get_mcp_identity'}})
    response=httpx.Response(200,request=request,headers=identity.headers,content='event: message\ndata: '+json.dumps(payload)+'\n\n')
    assert ResolvedIdentity.from_server_responses(connection,response,project).owner=='owner'
    payload['id']=2
    wrong=httpx.Response(200,request=request,headers=identity.headers,content='data: '+json.dumps(payload)+'\n\n')
    with pytest.raises(CaptureRejected):ResolvedIdentity.from_server_responses(connection,wrong,project)
    assert calls==[]


async def test_project_optional_tenant_fields_use_authenticated_identity(fixture):
    connection,_,_,_,calls=fixture
    identity,project=responses(connection)
    payload=project.json();payload['project_scope']['organization_id']=None;payload['project_scope']['workspace_id']=None
    project=httpx.Response(200,request=project.request,headers=project.headers,json=payload)
    resolved=ResolvedIdentity.from_server_responses(connection,identity,project)
    assert (resolved.organization,resolved.workspace)==('org','ws')
    payload['project_scope']['organization_id']='foreign'
    wrong=httpx.Response(200,request=project.request,headers=project.headers,json=payload)
    with pytest.raises(CaptureRejected):ResolvedIdentity.from_server_responses(connection,identity,wrong)
    assert calls==[]
