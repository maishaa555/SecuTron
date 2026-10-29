# Architecture and scope

## Data flow

```text
Repository (read-only scan)
  -> file selection and exclusions
  -> Python syntax/structure adapter
  -> deterministic rules and bounded flow tracking
  -> normalized findings
  -> text, JSON, or SARIF output
  -> (planned) optional Nemotron explanation / patch draft
  -> (planned) disposable copy, explicit checks, rescan
  -> human-reviewed result
```

Separate offline utilities consume completed reports for a fail-closed PR gate summary and measure repeated local scans. They do not publish GitHub comments or change repository files.

## Component boundaries

- **CLI:** argument parsing, output, help, and version display. Model consent prompts are planned but no model calls are implemented.
- **Walker:** canonicalize the root, skip symlinks and common generated directories, recheck containment before reading, and enforce file, entry, depth, byte, finding, and time budgets. The containment check is best-effort and cannot eliminate every concurrent replacement race.
- **Language adapter:** Tree-sitter parses Python into structural nodes and source spans. Parse errors mark results incomplete rather than being treated as safe.
- **Rule engine:** versioned rules return evidence and rationale; rules do not call the model.
- **Flow engine:** MVP supports only explicitly implemented local propagation patterns. It does not claim whole-program or interprocedural taint proof.
- **Finding output:** stable per-location 64-bit FNV-1a IDs from rule and location metadata, engine/rule versions, evidence roles, and limitations. IDs are non-cryptographic and can theoretically collide.
- **AI client:** opt-in Nebius Token Factory OpenAI-compatible explanation request. It sends a single selected finding after interactive confirmation; source files and `.env` values are excluded. Endpoint/model defaults are documented in `ai-policy.md`; the API key is read from the environment and never embedded in source.
- **Patch validator (planned):** disposable directory, patch path restrictions, command allowlist supplied by user, timeout/output bounds, rescan. Treat this as risk reduction, not a hardened hostile-code sandbox.
- **PR simulation:** `pr-check` creates a local gate conclusion and Markdown text from a version 1 report; it has no GitHub credentials and performs no network writes.
- **Benchmark:** `benchmark` measures local process wall time and supported-file throughput on the supplied tree; it emits no benchmark claim until run on a named, reproducible machine/corpus.

## Initial rule candidates

1. `PY.SECRET.LITERAL`: direct, annotated, or assignment-expression credential-like Python variable assignment, string-keyed dictionary value, keyword argument, or parameter default with a non-placeholder string literal. Heuristic; values are omitted.
2. `PY.SQL.UNTRUSTED`: recognized request input in an execute-like call's query argument, directly or through simple local assignment. SQL library identity and parameterization are not resolved.
3. `PY.COMMAND.UNTRUSTED`: recognized request input passed to `os.system`/`os.popen`, `asyncio.create_subprocess_shell`, or a call named `run`, `popen`, `Popen`, or `call` with `shell=` set to `True`, a statically nonzero numeric literal, or a nonempty string literal, directly or through simple local assignment. Parenthesized literals are accepted; process-like calls are identified by method name without resolving library identity.
4. `PY.PATH.UNTRUSTED`: recognized request input passed to `open()` or a method named `open`, including the method receiver and positional/`path=`/`file=` arguments, directly or through simple local assignment. Path containment is not assessed.
5. `PY.CODE.UNTRUSTED`: recognized request input passed to calls spelled `eval`, `exec`, `builtins.eval`, `builtins.exec`, `__builtins__.eval`, or `__builtins__.exec`, directly or through simple local assignment. Other aliases and name shadowing are not resolved.
6. `PY.CRYPTO.WEAK`: direct MD5/SHA-1 constructor calls; module identity and security purpose are heuristic.
7. `PY.RANDOM.INSECURE`: common direct calls to Python `random` functions; aliases and security context are not resolved.

Each rule needs positive, negative, and edge-case fixtures before being called supported. If the selected parser cannot robustly represent a pattern, defer that rule rather than substituting broad text matching without disclosure.

## Nonfunctional constraints

- Default scan is local and read-only.
- Bound file size, directory entries, directory depth, supported files, findings, and wall-clock checks between work items. The deadline cannot interrupt a blocking filesystem operation or parser call. Model input and validation limits are planned.
- Deterministic output ordering and rule-version metadata.
- Avoid logging source snippets, credentials, or model authorization headers.
- No benchmark figures until reproducible measurements exist.

## Future interfaces

The CLI and JSON contract remain the scanner interface. `secutron serve` hosts the browser UI and an authenticated `/api/scan` route that invokes the same CLI executable with an argument vector. It binds to loopback by default. An explicit `--public-origin` is required for non-loopback binds, and it must be a loopback origin pinned to the same port; Compose uses this with a host port published only on `127.0.0.1`. It has no persistence or tenancy, and the browser does not send reports to an external server. WebSocket streaming remains future work.

## Current input scope

Python source files with case-insensitive `.py` extensions are parsed with Tree-sitter. `.env` and `.env.*` names are matched case-insensitively and handled by a separate line-based local secret check; they are not parsed as Python or sent to a model. Other configuration formats are not scanned yet.

