"""Immutable injection receipts. Requested references never claim authority."""
from dataclasses import asdict, dataclass
import json


@dataclass(frozen=True)
class Provenance:
    source: str
    memory_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    request_id: str
    requested_scope: str | None
    effective_scope: str | None
    operation: str
    timestamp: str


@dataclass(frozen=True)
class ContextItem:
    text: str
    provenance: Provenance
    truncated: bool = False

    def render(self):
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True)
class AuditEnvelope:
    request_id: str
    session_id: str | None
    agent_id: str | None
    agent_instance_id: str | None
    operation: str
    requested_scope: str | None
    effective_scope: str | None
    source: str
    timestamp: str
    outcome: str
    unavailable: tuple[tuple[str, str], ...]
    requested_team_id: str | None = None
    provenance: tuple[Provenance, ...] = ()
    provenance_na_reason: str | None = None


@dataclass(frozen=True)
class ContextResult:
    items: tuple[ContextItem, ...]
    audit: AuditEnvelope
    dropped_items: int = 0
    truncated: bool = False
    budget_bytes: int = 0
