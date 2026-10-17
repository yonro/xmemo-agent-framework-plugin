# Changelog

All notable changes to `xmemo-agent-framework` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-10-17

### Changed
- Unified public display name to "XMemo for Microsoft Agent Framework".
- Restructured README with PyPI installation first, explicit `agent-framework-core` pin explanation, and local editable setup moved to Development.
- Expanded package metadata in `pyproject.toml` with author info, license, classifiers, keywords, and project URLs (Homepage, Repository, Issues, Changelog, PyPI).
- Documentation and package metadata only; no functional changes.

## [0.2.0] - 2026-10-16

### Added
- Opt-in write capture provider via `XMemoContextProvider` and the `after_run` hook.
- Support for three capture targets:
  - `Target.REMEMBER`: Semantic memory capture via `/api/v1/remember` with `Behavior.SEMANTIC_KEY_SAME_CONTENT_NOOP`.
  - `Target.STATE`: Explicit versioned state capture via `/api/v1/update_state` with `Behavior.STATE_VERSIONED_UPSERT` and bounded `state_key` validation.
  - `Target.EVENT`: Explicit timeline event capture via `/api/v1/timeline/events` with `Behavior.EVENT_APPEND_NO_DEDUPE` and bounded `event_type` validation.
- Leak prevention harness and canary scans preventing sensitive data, credentials, or unbounded scratch content from being captured.
- Fail-closed error isolation in `after_run`: agent response dispatch is never blocked or altered; errors are safely mapped to context metadata.
- Request correlation with `X-XMemo-Audit-ID` tracking for captured writes.
- Informative `ImportError` when `xmemo_agent_framework.maf` is imported without the `[maf]` extra.

### Changed
- Refactored server integration documentation to describe behavior purely via the public REST/MCP API contract.
- Added explicit server compatibility requirements (requires XMemo server with 2026-10 audit fixes, the first release after v0.4.435, for STATE/EVENT capture).

## [0.1.0] - 2026-10-13

### Added
- Initial release of `xmemo-agent-framework`.
- Opt-in read-only context provider for Microsoft Agent Framework (`agent-framework-core==1.21.0`).
- Read routes: `RECALL` (`/v1/recall/context`), `SEARCH` (`/v1/memories/search`), and `PROJECT` (`/v1/projects/{project_id}/context`).
- Immutable provenance tracking and receipt injection (`X-XMemo-Audit-ID`).
- Token budgeting and truncation handling for injected context.
- Safe adapter error mapping (no raw server details or credentials leaked).
