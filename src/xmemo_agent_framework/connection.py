"""Credential-bound HTTP; no redirects, retries, writes or server imports."""
from dataclasses import dataclass
import re
import uuid
from urllib.parse import urlsplit
import httpx


@dataclass
class XMemoError(Exception):
    status: int
    code: str
    audit: object = None
    response_request_id: str | None = None

    def __str__(self):
        return f"XMemo read failed: {self.code} ({self.status})"


ERROR_CODES = {401: "authentication_required", 403: "permission_denied",
               422: "invalid_request", 503: "authorization_unavailable"}


class ReadPayload(dict):
    """Unchanged JSON mapping with transport-only correlation, per response."""
    def __init__(self, data, response_request_id):
        super().__init__(data)
        self.response_request_id = response_request_id


def response_request_id(response):
    try:
        return str(uuid.UUID(response.headers.get("X-XMemo-Audit-ID", "")))
    except (ValueError, TypeError, AttributeError):
        return None


class Connection:
    def __init__(self, base_url: str, token: str, *, timeout: float = 10,
                 allow_local_http: bool = False, transport=None):
        url = urlsplit(base_url)
        if (url.username or url.password or url.query or url.fragment or
            url.path not in ("", "/") or not url.hostname or
            (url.scheme != "https" and not (allow_local_http and url.scheme == "http" and
                                           url.hostname in ("127.0.0.1", "::1", "localhost")))):
            raise ValueError("Use an HTTPS origin or explicitly enabled loopback HTTP")
        if not token or "\n" in token or "\r" in token or timeout <= 0:
            raise ValueError("Invalid credential or timeout")
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"}, timeout=timeout,
            follow_redirects=False, transport=transport)

    async def read(self, policy, query: str, request_id: str):
        method, path, payload = policy.request(query)
        if not ((method == "POST" and (path == "/v1/recall/context" or
                re.fullmatch(r"/v1/projects/[A-Za-z0-9_-]{1,128}/context", path))) or
                (method == "GET" and path == "/v1/memories/search")):
            raise ValueError("Route is outside the read-only contract")
        payload = {k: v for k, v in payload.items() if v is not None}
        try:
            response = await self._client.request(method, path,
                headers={"X-Request-ID": request_id},
                **({"params": payload} if method == "GET" else {"json": payload}))
        except httpx.TimeoutException:
            raise XMemoError(0, "timeout") from None
        except httpx.HTTPError:
            raise XMemoError(0, "transport_unavailable") from None
        if response.status_code != 200:
            raise XMemoError(response.status_code, ERROR_CODES.get(response.status_code, "unexpected_response"),
                             response_request_id=response_request_id(response))
        try:
            data = response.json()
        except ValueError:
            raise XMemoError(200, "invalid_response") from None
        if not isinstance(data, dict):
            raise XMemoError(200, "invalid_response")
        return ReadPayload(data, response_request_id(response))

    async def aclose(self):
        await self._client.aclose()
