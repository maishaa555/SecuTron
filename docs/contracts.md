# Finding and interface contract

This contract is the stable boundary between analysis, CLI output, later UI, and optional AI. Version it before exposing it to integrations.

## Finding object (v1 draft)

```json
{
  "schema_version": "1",
  "id": "stable-per-location-identifier",
  "rule_id": "PY.SQL.UNTRUSTED",
  "title": "Untrusted input may reach a dynamically built SQL query",
  "severity": "high",
  "confidence": 0.72,
  "path": "src/routes.py",
  "start": {"line": 18, "column": 12},
  "end": {"line": 19, "column": 41},
  "message": "Request-derived data appears in a query string passed to an execution API.",
  "evidence": [{"path": "src/routes.py", "line": 18, "role": "source", "excerpt": "..."}],
  "trace": [
    {"path": "src/routes.py", "line": 18, "label": "request input"},
    {"path": "src/routes.py", "line": 19, "label": "query construction"},
    {"path": "src/routes.py", "line": 20, "label": "database execution"}
  ],
  "limitations": ["Only recognized local Python patterns are tracked."],
  "rule_version": "0.2.0"
}
```

The JSON CLI wraps finding objects in a scan report:

```json
{
  "schema_version": "1",
  "complete": true,
  "findings": [],
  "errors": [],
  "scanned_files": 4
}
```

`complete` is false if a supported path could not be fully walked or analyzed; intentionally ignored directories and unsupported file types do not make the report incomplete. `errors` carries the relative path and reason. A report with `complete: false` must not be presented as a clean scan.

`scanned_files` counts supported files whose contents were successfully read as UTF-8 and passed to the Python or `.env` analyzer. Files that fail reading or UTF-8 decoding are excluded from the count; Python files with recoverable syntax errors are included because Tree-sitter still analyzes their recovered syntax.

Text output uses “No findings in the analyzed files; this scan is incomplete.” when there are no findings but `complete` is false.

The current ID is a deterministic 64-bit FNV-1a identifier built from the rule, repository-relative path, and a rule-specific source-location fingerprint. Python secret findings include the start line, column, and credential-like name (variable, dictionary key, keyword argument, or parameter); `.env` secret findings include the line and key; direct sink findings include the call's byte offset and callee; local-flow findings include the call's byte offset. These fingerprints are not cryptographic and are not guaranteed collision-free. Fields `confidence`, `evidence`, and `trace` must reflect implemented logic. Do not fabricate traces or precision. Excerpts are optional in persisted output and should be redacted before external model requests.

Secret-rule locations cover only the credential-like variable, dictionary key, keyword argument, parameter name, or `.env` key. They do not expose value text or encode the value's approximate length.

## Enums

Severity: `critical | high | medium | low | info`. Confidence: numeric 0–1, documented as rule confidence, not exploit probability. Paths are repository-relative, normalized with `/`, and never absolute.

## CLI contract draft

- `secutron scan <path> --format text|json|sarif`
- `secutron rules` lists implemented rule IDs, supported patterns, and material limitations from the same catalog used for SARIF metadata.
- `secutron --help` and `secutron --version` provide CLI usage and package version.
- Text output displays evidence labels and sanitized excerpts, not the source line or secret value.
- Exit codes: `0` scan completed with no findings; `1` scan completed with findings; `2` invocation/configuration error; `3` one or more supported files or paths could not be fully analyzed, including when a resource limit is reached. Incomplete status takes precedence over findings.

JSON finding columns are one-based UTF-8 byte offsets, matching Tree-sitter's source positions; they are not user-perceived character columns for non-ASCII text. SARIF output uses SARIF 2.1.0, percent-encodes special characters in relative artifact URIs, includes the full implemented rule catalog even when no findings are present, and omits columns because Tree-sitter columns are byte-based while SARIF columns have different encoding semantics. SARIF run and invocation properties include `complete`; an incomplete scan also sets `executionSuccessful` to false and emits warning notifications for the recorded errors. Exit codes are implemented as documented above: 0 for complete scans with no findings, 1 for complete scans with findings, 2 for invocation errors, and 3 for incomplete scans (even if findings were produced).

## Local HTTP API

`secutron serve` currently exposes `POST /api/scan` on a loopback listener. The request body is `{"path":"..."}` and the response is the same versioned scan report returned by the CLI. The local server uses a process-random bearer token, exact Host/Origin checks, no CORS, an 8 KiB JSON request limit, a single-scan concurrency gate, and a bounded scanner-output read. The token is printed once at startup and is not embedded in served assets. This endpoint is intended for a same-origin local dashboard, not network exposure. Persistence, tenancy, WebSocket streaming, and remote access are not supported.

`secutron pr-check <report.json>` accepts only schema version 1 reports. It defaults to a `high` blocking threshold, supports `critical|high|medium|low|info`, and produces a deterministic JSON summary containing a Markdown comment. It returns 0 for a complete report with no findings at or above threshold, 1 when the threshold is exceeded, 2 for invalid input, and 3 for an incomplete scan. It does not contact GitHub or publish comments. Incomplete reports never pass.

`secutron benchmark <path> [--runs 1..10]` runs the scanner repeatedly and reports median wall time, files/second, and non-empty supported source lines/second. Process startup is included; line counts are not logical LOC. Results are measurements for the current machine and input tree, not portable performance claims.

