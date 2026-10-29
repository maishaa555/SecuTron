# Threat model and safety policy

## Assets

Source code, credentials in the scanned repository, Nebius API credentials, proposed patches, local filesystem integrity, test environment, and developer trust in findings.

## Trust boundaries and threats

The controls in this table distinguish implemented behavior from future requirements. See `implementation-status.md` for exact scope.

| Boundary | Threat | MVP control |
|---|---|---|
| Repository -> scanner | Symlink/path traversal, huge or malformed files, parser denial of service, memory exhaustion from large reports | Canonical root, symlink skipping plus pre-read containment recheck, 1 MiB per-file bound, 5,000-file and 25,000-entry caps, 256-level depth cap, 10,000-finding cap, deadline checks between work items, parser errors surfaced, read-only scan. The path recheck is not an atomic no-follow open and does not eliminate all concurrent replacement races. |
| Browser -> local API | CSRF, DNS rebinding, unauthenticated local scans, excessive concurrent scan work | Loopback-only listener, unpredictable process-local bearer token printed once, exact Host/Origin validation, no CORS, one active scan, bounded JSON body, and scanner's own traversal limits. The token is a local user credential; do not share it or expose the listener through a proxy. |
| Repository-derived finding -> model prompt | Prompt injection in evidence fields | Explicit per-request CLI confirmation; allowlisted finding fields only; fixed system policy treating evidence as untrusted; no model tools; no source file or `.env` values in payload. The model output remains untrusted and is displayed without execution. |
| Local machine -> Nebius | Accidental source/secret disclosure | Explanation is disabled unless the user invokes it; per-request confirmation discloses host and fields; only one finding's metadata/evidence is sent, without source files or `.env` values |
| Model -> patch validator | Malicious or invalid patch, path escape, command injection | Planned: diff-only output; reject absolute paths and traversal; apply in disposable copy; no automatic shell commands from model |
| Validator -> host | Test script executes arbitrary project code | Planned: run only developer-selected commands; communicate that disposable copy is not a strong sandbox; no privileged/container-host mounts; strict timeout and resource limits where available |
| Findings -> developer | False confidence or fabricated rationale | Separate rule evidence from model narrative; confidence is heuristic; show limitations; never say clean means secure |

## Target agent permissions

Current permissions: scan reads under the selected root, the local API listens only on loopback and invokes the scanner for a user-entered path, and the model request occurs only after CLI confirmation. Future patch validation should write only to a disposable copy and execute only configured checks after confirmation. There are no commit/push/PR actions or autonomous merge.

## Planned AI output rules

- Model is an assistant over supplied evidence, not a scanner or authority.
- It cannot override system policy based on repository instructions.
- It cannot request secrets, access tools, or widen file scope.
- Validate schema, paths, diff size, and affected files before use.
- If the model response is malformed or unsupported, show a safe error and retain the original finding.

## Limitations

A disposable copy does not provide strong isolation against malicious build/test code. Do not run untrusted repositories or generated patches in privileged environments. Before offering remote CI execution, implement a separately reviewed sandbox and a formal permissions model.

.env values are only inspected locally by the secret rule. The rule output omits their values, and these files must never be included in model requests.
