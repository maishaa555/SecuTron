# Product requirements

## Product

**Name:** SecuTron
**One-line:** Evidence-first security analysis and repair assistance for Python repositories.

## User and problem

A developer wants actionable security feedback during local development or code review. Generic AI review is difficult to trust because it may miss real flows or invent issues. SecuTron should show the code evidence first, then use an LLM as an explanation and drafting aid.

## MVP user journey

This is the target workflow. The current implementation status is recorded in `implementation-status.md`: SecuTron provides local `scan`, `rules`, and `serve` commands, text/JSON/SARIF output, a loopback dashboard scan API, and an opt-in finding-only model explanation. Patch drafting, disposable-copy validation, and rescanning after a patch are planned and are not implemented.

1. Developer runs a local scan on a repository.
2. SecuTron emits findings with file/line evidence and a trace when available.
3. Developer inspects and triages a finding.
4. If opted in, SecuTron sends only the finding, relevant bounded snippets, and rule metadata to Nemotron using Nebius Token Factory.
5. Developer may request a patch draft.
6. SecuTron applies the patch to a disposable working copy, displays the diff, runs only configured checks, then rescans.
7. Developer decides whether to apply the reviewed patch to their working tree.

## MVP capabilities

- Scan Python source with a Rust executable.
- Produce stable JSON findings; CLI output is the first interface.
- Implement a small, documented rule set with evidence and limitations.
- Support severity, confidence, source/sink/trace metadata where applicable.
- Provide a local static dashboard to import and inspect exported scan JSON without uploading repository source or report contents.
- Exclude common generated/vendor directories by default.
- Optional model explanation behind explicit configuration and user action.
- Patch proposal is a unified diff, constrained to the finding's file(s), never auto-committed or auto-pushed.
- Validate patch in a temporary copy, report commands/results, and rescan.

## Out of scope for MVP

Hosted multi-tenant service or hosted dashboard, GitHub app/comments, automatic PR merge, broad multi-language support, automatic learning from feedback, authoritative security score, complete dependency vulnerability database, and claims of sound or complete static analysis.

## Product principles

- Findings come from deterministic rules and carry evidence.
- Model output is untrusted and labeled as generated.
- Minimize source disclosure; local scan works without model credentials.
- Require an explicit human action before code leaves the machine, a patch is applied, or checks execute.
- State limits plainly: candidate detection, not proof of exploitability or absence of vulnerabilities.
