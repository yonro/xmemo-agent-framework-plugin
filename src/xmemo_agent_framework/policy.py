"""Request references are filters; XMemo alone authorizes identity and scope."""
from dataclasses import dataclass
from enum import Enum
import re


class ReadRoute(Enum):
    RECALL = "recall"
    PROJECT = "project"
    SEARCH = "search"


@dataclass(frozen=True)
class Policy:
    recall_enabled: bool = False
    capture_enabled: bool = False
    route: ReadRoute = ReadRoute.RECALL
    scope: str | None = None
    project_id: str | None = None
    team_id: str | None = None
    max_items: int = 8
    max_tokens: int = 2000

    def __post_init__(self):
        if type(self.recall_enabled) is not bool or type(self.capture_enabled) is not bool:
            raise ValueError("Recall/capture flags must be explicit booleans")
        if type(self.max_items) is not int or type(self.max_tokens) is not int:
            raise ValueError("Context budgets must be integers")
        if self.capture_enabled:
            raise ValueError("Capture is unavailable in v0.1")
        if not isinstance(self.route, ReadRoute):
            raise ValueError("Unknown read route")
        if not 1 <= self.max_items <= 1000 or not 1 <= self.max_tokens <= 50000:
            raise ValueError("Invalid context budget")
        if self.project_id is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.project_id):
            raise ValueError("Invalid project reference")
        if self.route is ReadRoute.PROJECT and not self.project_id:
            raise ValueError("Project route requires project_id")

    def request(self, query: str):
        if self.route is ReadRoute.PROJECT:
            return "POST", f"/v1/projects/{self.project_id}/context", {
                "team_id": self.team_id, "max_items": self.max_items,
                "max_tokens": self.max_tokens, "durable_query": query,
            }
        filters = {"scope": self.scope, "team_id": self.team_id}
        if self.route is ReadRoute.SEARCH:
            return "GET", "/v1/memories/search", {"query": query, "limit": self.max_items, **filters}
        return "POST", "/v1/recall/context", {
            "query": query, "max_items": self.max_items, "max_tokens": self.max_tokens, **filters,
        }
