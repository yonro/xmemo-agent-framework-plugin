"""Separate v0.2 candidate preparation. Explicit dispatch is separate from preparation."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
import uuid
import httpx
from .connection import ERROR_CODES, response_request_id


@dataclass(frozen=True)
class Finding:
    surface: str
    kind: str


def fragments(token):
    if not isinstance(token, str) or len(token) < 24:
        raise ValueError('Use a nonempty high-entropy canary credential')
    parts = [('full_token', token), ('bearer_header', 'Bearer ' + token)]
    secret = token.split(':', 1)[1] if ':' in token else token
    parts.append(('secret_value', secret))
    for offset in range(max(0, len(secret) - 11)):
        parts.append(('secret_window', secret[offset:offset+12]))
    split = len(secret) // 2
    for label, part in (('secret_first_half', secret[:split]), ('secret_second_half', secret[split:])):
        if len(part) >= 12:
            parts.append((label, part))
    return tuple(parts)


def scan(surfaces, credentials):
    if not credentials:
        raise ValueError('Canary credentials required')
    signatures = tuple(part for token in credentials for part in fragments(token))
    findings = []
    for surface, value in surfaces.items():
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        for kind, part in signatures:
            if part in text:
                findings.append(Finding(surface, kind))
    return tuple(dict.fromkeys(findings))


def redact(text, credentials):
    for token in credentials:
        for kind, part in sorted(fragments(token), key=lambda pair: len(pair[1]), reverse=True):
            text = text.replace(part, '[REDACTED_' + kind.upper() + ']')
    return text


class Target(str, Enum):
    REMEMBER = 'remember'
    STATE = 'update_state'
    EVENT = '/timeline/events'


class Behavior(str, Enum):
    UNKNOWN = 'unknown'
    # Source-verified personal remember semantics; not a generic HTTP retry promise.
    SEMANTIC_KEY_SAME_CONTENT_NOOP = 'semantic_key_same_content_noop'
    # update_state versions one active slot per owner/bucket/scope/state_key.
    STATE_VERSIONED_UPSERT = 'state_versioned_upsert'
    # timeline/events is append-oriented; this client never retries or dedupes it.
    EVENT_APPEND_NO_DEDUPE = 'event_append_no_dedupe'


@dataclass(frozen=True)
class CapturePolicy:
    enabled: bool = False
    target: Target | None = None
    behavior: Behavior = Behavior.UNKNOWN
    canaries: tuple[str, ...] = ()
    max_bytes: int = 8192
    # Target-specific write contracts stay explicit so a target cannot silently
    # fall back to a server default.
    state_key: str | None = None
    event_type: str | None = None

    def __post_init__(self):
        if type(self.enabled) is not bool or type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 65536:
            raise ValueError('Invalid capture policy')


class CaptureRejected(ValueError):
    def __init__(self, gate, reason=None):
        self.gate = gate
        self.reason = reason
        detail = f': {reason}' if reason else ''
        super().__init__(f'Capture candidate rejected at gate {gate}{detail}')


_SEAL = object()


@dataclass(frozen=True, init=False)
class ResolvedIdentity:
    """Host-only evidence from authenticated MCP identity + project responses.

    The application supplies transport responses, never model dictionaries.
    Binding verifies the credential/origin and operation that produced them;
    it does not create a remote permission or replace server authorization.
    """
    connection: object
    owner: str
    agent: str
    organization: str
    workspace: str
    project: str
    scope: str
    scopes: tuple[str, ...]
    receipts: tuple[str, ...]
    credential_fingerprint: str
    seal: object

    @classmethod
    def from_server_responses(cls, connection, identity_response, project_response):
        try:
            base = connection._client.base_url
            credential = connection._client.headers['Authorization']
            for response in (identity_response, project_response):
                request = response.request
                if (response.status_code != 200 or response.history or
                    request.url.scheme != base.scheme or request.url.host != base.host or
                    request.url.port != base.port or request.headers.get('Authorization') != credential):
                    raise ValueError()
            request = identity_response.request
            call = json.loads(request.content)
            if (request.method != 'POST' or request.url.path.rstrip('/') != '/mcp' or
                call.get('method') != 'tools/call' or call.get('params', {}).get('name') != 'get_mcp_identity'):
                raise ValueError()
            try:
                identity_payload = identity_response.json()
            except ValueError:
                events = [json.loads(line[6:]) for line in identity_response.text.splitlines()
                          if line.startswith('data: ')]
                matches = [event for event in events if event.get('id') == call.get('id')]
                if len(matches) != 1:
                    raise ValueError()
                identity_payload = matches[0]
            if identity_payload.get('id') != call.get('id'):
                raise ValueError()
            result = identity_payload['result']
            if result.get('isError') or 'error' in identity_payload:
                raise ValueError()
            text = '\n'.join(x['text'] for x in result['content'] if x.get('type') == 'text')
            fields = dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line)
            tenant = json.loads(fields['Tenant'])
            project = project_response.json()['project_scope']
            project_request = project_response.request
            if (project_request.method != 'POST' or
                project_request.url.path != '/v1/projects/' + project['project_id'] + '/context' or
                project['owner_id'] != fields['Owner ID'] or
                project['project_id'] != tenant['project_id'] or
                project.get('organization_id') not in (None, tenant['organization_id']) or
                project.get('workspace_id') not in (None, tenant['workspace_id']) or
                project.get('team_id') is not None or
                project['scope_key'] != 'tenant:project:' + project['project_id']):
                raise ValueError()
            values = {'connection': connection, 'owner': fields['Owner ID'], 'agent': fields['Agent ID'],
                      'organization': tenant['organization_id'], 'workspace': tenant['workspace_id'],
                      'project': tenant['project_id'], 'scope': project['scope_key'],
                      'scopes': tuple(fields['Scopes'].split(', ')),
                      'receipts': tuple(str(uuid.UUID(r.headers['X-XMemo-Audit-ID'])) for r in (identity_response, project_response)),
                      'credential_fingerprint': hashlib.sha256(credential.encode()).hexdigest(), 'seal': _SEAL}
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', values['project']):
                raise ValueError()
            if any(not isinstance(values[k], str) or values[k] in ('', 'none') or len(values[k]) > 128
                   for k in ('owner', 'agent', 'organization', 'workspace', 'project', 'scope')):
                raise ValueError()
            value = object.__new__(cls)
            for key, item in values.items():
                object.__setattr__(value, key, item)
            return value
        except (KeyError, ValueError, TypeError, AttributeError):
            raise CaptureRejected(3) from None


@dataclass(frozen=True)
class RunProvenance:
    run_id: str
    session_id: str
    source_ids: tuple[str, ...]
    occurred_at: str


@dataclass(frozen=True)
class CaptureRequest:
    method: str
    path: str
    body_json: str
    idempotency_key: str
    identity: ResolvedIdentity | None = field(default=None, repr=False)
    provenance: RunProvenance | None = field(default=None, repr=False)
    seal: object = field(default=None, repr=False)


@dataclass(frozen=True)
class CaptureWriteReceipt:
    memory_id: str
    status: int
    audit_request_id: str | None
    idempotency_key: str
    outcome: str = 'server_acknowledged'


@dataclass
class CaptureDispatchError(Exception):
    status: int
    code: str
    audit_request_id: str | None = None

    def __str__(self):
        return f'Capture dispatch failed: {self.code} ({self.status})'


_SECRET_PATTERNS = (
    r'(?i)Bearer\s+[A-Za-z0-9._~+/:=-]+',
    r'(?i)(?:api[_-]?key|password|secret|token)\s*[:=]\s*["\']?[^\s"\']+',
    r'\b(?:sk-(?:ant-)?|ghp_)[A-Za-z0-9_-]{12,}',
    r'(?i)(?:postgres(?:ql)?|https?)://[^/\s:@]+:[^/\s@]+@',
    r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    r'(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
)

_STATE_KEY_PATTERN = re.compile(r'[a-z0-9][a-z0-9_.:-]{0,127}\Z')
_EVENT_TYPE_PATTERN = re.compile(r'[a-z0-9][a-z0-9_.:-]{0,127}\Z')
_TARGET_CONTRACT_GATE = 9


class CaptureProvider:
    """Explicit v0.2 mode; after_run returns a candidate, never sends it."""
    def __init__(self, connection, policy=CapturePolicy(), *, identity=None):
        self.connection, self.policy, self.identity = connection, policy, identity

    async def after_run(self, content, *, provenance):
        policy, identity = self.policy, self.identity
        if not policy.enabled:
            raise CaptureRejected(1)
        if not isinstance(identity, ResolvedIdentity) or getattr(identity, 'seal', None) is not _SEAL:
            raise CaptureRejected(3)
        if 'memory:write' not in identity.scopes:
            raise CaptureRejected(2)
        if (identity.connection is not self.connection or identity.credential_fingerprint !=
            hashlib.sha256(self.connection._client.headers.get('Authorization', '').encode()).hexdigest()):
            raise CaptureRejected(3)
        if not isinstance(content, str) or not content.strip() or len(content.encode()) > policy.max_bytes:
            raise CaptureRejected(4)
        try:
            if policy.target in (Target.STATE, Target.EVENT) and any(
                re.search(pattern, content) for pattern in _SECRET_PATTERNS
            ):
                raise ValueError()
            credentials = tuple(dict.fromkeys((*policy.canaries,
                self.connection._client.headers['Authorization'].removeprefix('Bearer '))))
            sanitized = redact(content, credentials)
            for pattern in _SECRET_PATTERNS:
                sanitized = re.sub(pattern, '[REDACTED_SECRET]', sanitized)
            if (scan({'content': sanitized}, credentials) or
                re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----', sanitized) or
                re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', sanitized) or
                len(sanitized.encode()) > policy.max_bytes):
                raise ValueError()
        except (ValueError, TypeError):
            raise CaptureRejected(4) from None
        if not isinstance(provenance, RunProvenance):
            raise CaptureRejected(5)
        try:
            stamp = datetime.fromisoformat(provenance.occurred_at)
            if (stamp.tzinfo is None or not isinstance(provenance.source_ids, tuple) or
                not 1 <= len(provenance.source_ids) <= 64):
                raise ValueError()
            for source in provenance.source_ids:
                uuid.UUID(source)
        except (ValueError, TypeError, AttributeError):
            raise CaptureRejected(5) from None
        if (not provenance.run_id or not provenance.session_id or
            not isinstance(provenance.run_id, str) or not isinstance(provenance.session_id, str) or
            not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', provenance.run_id) or
            not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', provenance.session_id)):
            raise CaptureRejected(6)
        if not isinstance(policy.target, Target):
            raise CaptureRejected(8)
        expected_behavior = {
            Target.REMEMBER: Behavior.SEMANTIC_KEY_SAME_CONTENT_NOOP,
            Target.STATE: Behavior.STATE_VERSIONED_UPSERT,
            Target.EVENT: Behavior.EVENT_APPEND_NO_DEDUPE,
        }[policy.target]
        if policy.behavior is not expected_behavior:
            raise CaptureRejected(7, f'behavior does not match target {policy.target.value}')
        if policy.target is Target.STATE:
            if not isinstance(policy.state_key, str) or not _STATE_KEY_PATTERN.fullmatch(policy.state_key):
                raise CaptureRejected(_TARGET_CONTRACT_GATE, 'state_key is required and must match [a-z0-9][a-z0-9_.:-]{0,127}')
        elif policy.target is Target.EVENT:
            if not isinstance(policy.event_type, str) or not _EVENT_TYPE_PATTERN.fullmatch(policy.event_type):
                raise CaptureRejected(_TARGET_CONTRACT_GATE, 'event_type is required and must match [a-z0-9][a-z0-9_.:-]{0,127}')
        key_material = [identity.owner, identity.organization, identity.workspace, identity.project,
                        identity.agent, provenance.run_id, provenance.session_id, policy.target.value, sanitized]
        if policy.target is Target.STATE:
            key_material.extend(('state_key', policy.state_key))
        elif policy.target is Target.EVENT:
            key_material.extend(('event_type', policy.event_type, provenance.occurred_at))
        key = hashlib.sha256(json.dumps(key_material, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        metadata = {'capture': {'run_id': provenance.run_id, 'session_id': provenance.session_id,
                              'source_ids': list(provenance.source_ids), 'occurred_at': provenance.occurred_at,
                              'server_receipts': list(identity.receipts), 'idempotency_key': key}}
        if policy.target is Target.REMEMBER:
            body = {'content': sanitized, 'path': 'capture/' + identity.project, 'bucket': 'work',
                    'scope': identity.scope, 'source': identity.agent,
                    'semantic_key': 'maf-capture:' + key, 'dedupe': True, 'metadata': metadata}
            path = '/api/v1/remember'
        elif policy.target is Target.STATE:
            body = {'state_key': policy.state_key, 'content': sanitized, 'bucket': 'work',
                    'scope': identity.scope, 'source': identity.agent, 'metadata': metadata}
            path = '/api/v1/update_state'
        else:
            body = {'content': sanitized, 'event_type': policy.event_type,
                    'occurred_at': provenance.occurred_at, 'session_id': provenance.session_id,
                    'bucket': 'work', 'scope': identity.scope, 'source': identity.agent,
                    'metadata': metadata}
            path = '/api/v1/timeline/events'
        body_json = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        if (len(body_json.encode()) > 65536 or scan({'request': body_json}, credentials) or
            any(re.search(p, body_json) for p in _SECRET_PATTERNS)):
            raise CaptureRejected(4)
        return CaptureRequest('POST', path, body_json, key, identity, provenance, _SEAL)


    async def dispatch(self, candidate):
        """Send only an intact, gated candidate; no retries or client write state.

        The server reauthorizes this credential on the actual request. Transport
        errors have unknown server outcome and must not trigger automatic retry.
        """
        if (not isinstance(candidate, CaptureRequest) or candidate.seal is not _SEAL or
            candidate.identity is not self.identity):
            raise CaptureRejected(3)
        try:
            content = json.loads(candidate.body_json)['content']
        except (ValueError, KeyError, TypeError):
            raise CaptureRejected(7) from None
        expected = await self.after_run(content, provenance=candidate.provenance)
        if expected != candidate:
            raise CaptureRejected(7)
        request_id = str(uuid.uuid4())
        try:
            response = await self.connection._client.request(candidate.method, candidate.path,
                content=candidate.body_json.encode(), headers={'Content-Type': 'application/json',
                'X-Request-ID': request_id, 'X-MAF-Session-ID': candidate.provenance.session_id})
        except httpx.TimeoutException:
            raise CaptureDispatchError(0, 'write_outcome_unknown') from None
        except httpx.HTTPError:
            raise CaptureDispatchError(0, 'write_outcome_unknown') from None
        correlation = response_request_id(response)
        if not 200 <= response.status_code < 300:
            raise CaptureDispatchError(response.status_code,
                ERROR_CODES.get(response.status_code, 'unexpected_response'), correlation)
        try:
            data = response.json()
            memory_id = str(uuid.UUID(data.get('id') or data.get('memory_id')))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise CaptureDispatchError(response.status_code, 'write_outcome_unknown', correlation) from None
        return CaptureWriteReceipt(memory_id, response.status_code, correlation, candidate.idempotency_key)
