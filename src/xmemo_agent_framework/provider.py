"""Read-only context preparation independent of host SDK and server internals."""
from dataclasses import replace
from datetime import datetime, timezone
import json
import uuid
from .connection import XMemoError
from .budget import apply_budget
from .policy import Policy, ReadRoute
from .provenance import AuditEnvelope, ContextItem, ContextResult, Provenance


def _ids(value):
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("id", "memory_id", "logical_memory_id") and isinstance(item, str):
                found.append(item)
            elif isinstance(item, (dict, list)):
                found.extend(_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_ids(item))
    return tuple(dict.fromkeys(found))


class Provider:
    def __init__(self, connection, policy=Policy(), *, agent_id=None, agent_instance_id=None):
        self.connection, self.policy = connection, policy
        self.agent_id, self.agent_instance_id = agent_id, agent_instance_id

    async def before_run(self, query: str, *, session_id=None):
        request_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        _, path, _ = self.policy.request(query)
        requested = (f"tenant:project:{self.policy.project_id}" if self.policy.route is ReadRoute.PROJECT else self.policy.scope)
        na = [("principal", "Server credential authority owns principal resolution"),
              ("tenant", "Server credential authority owns tenant resolution"),
              ("effective_team", "Not returned by server; requested team is a filter"),
              ("effective_scope", "Not returned by server; requested scope is not authority")]
        for field, value in (("session_id", session_id), ("agent_id", self.agent_id),
                             ("agent_instance_id", self.agent_instance_id)):
            if value is None:
                na.append((field, "Not supplied by host"))
        audit = AuditEnvelope(request_id, session_id, self.agent_id, self.agent_instance_id,
            self.policy.route.value, requested, None, "xmemo:" + path, timestamp,
            "disabled", tuple(na), requested_team_id=self.policy.team_id,
            provenance_na_reason="Recall disabled: no request or content injection")
        if not self.policy.recall_enabled:
            return ContextResult((), audit)
        try:
            data = await self.connection.read(self.policy, query, request_id)
        except XMemoError as exc:
            failure = replace(audit, request_id=exc.response_request_id or request_id, outcome=exc.code, provenance_na_reason="Read failed before content injection")
            raise replace(exc, audit=failure) from None
        request_id = getattr(data, "response_request_id", None) or request_id
        audit = replace(audit, request_id=request_id)
        project_scope = data.get("project_scope")
        effective = project_scope.get("scope_key") if isinstance(project_scope, dict) else data.get("scope")
        if isinstance(effective, str):
            na = [(field, reason) for field, reason in na if field != "effective_scope"]
        if not isinstance(effective, str):
            effective = None

        provenance = Provenance("xmemo:" + path, (), (), request_id, requested, effective,
                                self.policy.route.value, timestamp)
        items = []
        oversized_pack = 0
        if self.policy.route is ReadRoute.SEARCH:
            for row in data.get("results", []):
                ids = _ids(row)
                if ids and isinstance(row, dict):
                    content = row.get("content")
                    text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
                    if content is not None and text:
                        items.append(ContextItem(text, replace(provenance, memory_ids=ids, source_ids=ids)))
        else:
            # Recall packs keep body text in context_text, not item metadata.
            # Preserve one composite pack with every returned source ID.
            ids = _ids(data.get("items", [])) if self.policy.route is ReadRoute.RECALL else _ids(data)
            text = data.get("context_text") if self.policy.route is ReadRoute.RECALL else json.dumps(data, ensure_ascii=False)
            returned_count = (len(data.get("items", [])) if self.policy.route is ReadRoute.RECALL
                              else (data.get("budget") or {}).get("used_items", 0))
            if returned_count > self.policy.max_items:
                # Composite text has no stable per-record slicing contract.
                # Fail closed rather than associate sliced text with wrong IDs.
                oversized_pack = returned_count
            elif ids and isinstance(text, str) and text:
                memory_ids = ids if self.policy.route is ReadRoute.RECALL else tuple(dict.fromkeys(
                    _ids(data.get("recent_memories", [])) + _ids(data.get("durable_context", {}))))
                items.append(ContextItem(text, replace(provenance, memory_ids=memory_ids, source_ids=ids)))
        kept, dropped, truncated, used = apply_budget(items,
            max_items=self.policy.max_items, max_tokens=self.policy.max_tokens)
        dropped += oversized_pack
        truncated = truncated or bool(oversized_pack)
        audit = replace(audit, effective_scope=effective, outcome="injected" if kept else "empty",
                        unavailable=tuple(na), provenance=tuple(item.provenance for item in kept),
                        provenance_na_reason=None if kept else "No retrieved content injected")
        return ContextResult(kept, audit, dropped, truncated, used)

    async def after_run(self, *args, **kwargs):
        return None
