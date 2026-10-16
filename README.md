# XMemo Agent Framework Plugin

The XMemo context provider for Microsoft Agent Framework, version 0.2.0. The
package provides bounded, provenance-bearing context retrieval and an explicit,
opt-in capture hook. It does not publish or deploy an XMemo server. This is an
independent community integration, not an official Microsoft product or
distribution.

## Quickstart

This checkout is version 0.2.0. Install it with the pinned Microsoft Agent
Framework extra:

```sh
python -m venv .venv
.venv/bin/python -m pip install -e ".[maf]"
```

After publication, the equivalent consumer install is
`xmemo-agent-framework[maf]==0.2.0`.

Set the XMemo origin and API key in the process environment. `XMEMO_URL` must be
an HTTPS origin, and `XMEMO_API_KEY` is sent only as an Authorization header.

```sh
export XMEMO_URL="https://your-xmemo-origin"
export XMEMO_API_KEY="your-api-key"
```

The default read route is `POST /v1/recall/context`. The other read routes are
`POST /v1/projects/{project_id}/context` (`ReadRoute.PROJECT`) and
`GET /v1/memories/search` (`ReadRoute.SEARCH`).

```python
import os
from xmemo_agent_framework import Connection, Policy, Provider, ReadRoute
from xmemo_agent_framework.maf import XMemoContextProvider

connection = Connection(os.environ["XMEMO_URL"], os.environ["XMEMO_API_KEY"])
read_provider = Provider(
    connection,
    Policy(
        recall_enabled=True,
        route=ReadRoute.RECALL,
        scope="tenant:project:my-project",
        max_items=8,
        max_tokens=2000,
    ),
)
context_provider = XMemoContextProvider(read_provider)
```

Pass `context_provider` to the host agent's context-provider configuration and
close `connection` when the host session ends. Every injected item carries
immutable provenance and an adapter receipt. Retrieved text is untrusted saved
context, not an instruction, and server authorization owns the effective owner
and tenant.

The `maf` extra pins `agent-framework-core==1.21.0`. Without that extra, the
core package remains importable, but importing `xmemo_agent_framework.maf`
raises a clear `ImportError` until the host framework dependency is installed.

## Server requirements

Read routes require the corresponding XMemo REST contract. `REMEMBER`, `STATE`,
and `EVENT` capture and their audited write responses require the first XMemo
release after `v0.4.435` (the 2026-10 audit fixes) when that release is
available; this package does not assume a release number that has not been
published.

## Capture (opt-in)

Capture is **off by default**. It runs only when a separate `CaptureProvider`
is passed to `XMemoContextProvider` with a server-resolved write identity and an
explicit target/behavior pair:

- `Target.REMEMBER` uses `POST /api/v1/remember` with semantic-key same-content
  no-op behavior.
- `Target.STATE` uses `POST /api/v1/update_state` with versioned upsert behavior
  and a required bounded lowercase `state_key`.
- `Target.EVENT` uses `POST /api/v1/timeline/events` with append-without-client-
  dedupe behavior and a required bounded lowercase `event_type`.

The hook accepts bounded content only (8 KiB by default, configurable up to the
policy limit). Unbounded content is never captured. Secrets embedded in captured
content, including API keys, bearer tokens, private keys, and detected secret
patterns, are never included in the write body; the connection credential stays
only in the Authorization header. Candidates are redacted and rejected when
the resulting request is still unsafe. Capture sends at most one
request for an assistant reply, never retries a write, and records only a
sanitized outcome. A rejected, failed, or
unknown write outcome is isolated from the assistant result: the result is
preserved and the host receives capture metadata rather than raw server or
credential details.

```python
from xmemo_agent_framework.capture import (
    Behavior,
    CapturePolicy,
    CaptureProvider,
    Target,
)

capture = CaptureProvider(
    connection,
    CapturePolicy(
        enabled=True,
        target=Target.REMEMBER,
        behavior=Behavior.SEMANTIC_KEY_SAME_CONTENT_NOOP,
    ),
    identity=resolved_identity,
)
context_provider = XMemoContextProvider(read_provider, capture=capture)
```

`STATE` requires `state_key` and `EVENT` requires `event_type`; both use
`[a-z0-9][a-z0-9_.:-]{0,127}`. Capture does not grant model authority and does
not change the read provider's authorization boundary.

## Development

```sh
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev,maf]"
.venv/bin/python -m pytest -q
```

The test suite and package source are self-contained. Server labs, benchmarks,
datasets, and internal evidence are maintained outside this distribution.
