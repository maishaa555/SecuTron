# Build plan and acceptance criteria

## Phase 0 — decisions and feasibility

- Confirm Rust toolchain and choose Python parser by testing syntax coverage, source spans, maintenance, license, and Windows support.
- Record configurable Nebius endpoint/model defaults from current official documentation; recheck model availability and event eligibility before release.
- Finalize license and repository ownership before publication.

**Done when:** a short decision record answers these questions and no unsupported platform claims remain.

## Phase 1 — local scanner foundation

- Rust CLI, safe file walker, exclusions, bounded file sizes, structured errors.
- Versioned finding type and deterministic output.
- Parser adapter and initial secret-literal rule.

**Acceptance:** scans a fixture tree deterministically; handles parse errors; does not read outside root through symlinks; JSON follows `contracts.md`.

## Phase 2 — evidence-backed code-flow rules

- Implement limited SQL, command, and path rules one at a time.
- Build positive, negative, and edge fixtures for each rule.
- Document each supported syntax pattern and known blind spots.

**Acceptance:** rule fires on intended fixtures, avoids specified negative fixtures, includes truthful evidence/trace, and reports unsupported constructs instead of claiming coverage.

## Phase 3 — optional Nebius/Nemotron analysis

- Configurable provider adapter, explicit opt-in, redaction and bounded payload. (The opt-in finding-only explanation command is implemented; broader prompt/response validation remains.)
- Explain operation first; patch drafting only after explanation and output validation work.

**Acceptance:** scan works offline; absent/bad credentials produce a useful error only for AI command; request includes no whole repository; provider/model is named accurately in docs/demo.

## Phase 4 — patch validation

- Disposable copy, strict path/diff checks, explicit user-selected commands, timeout/output caps, rescan comparison.

**Acceptance:** invalid/out-of-scope diff rejected; validation records exact checks and outcomes; no automatic commit/push; warning explains test code executes.

## Phase 5 — interface and submission

- Preserve the founder-provided SecuTron wordmark, font feel, and navy/electric-blue/cream visual theme. A loopback-only Axum server now serves the dashboard and an authenticated scan endpoint; WebSocket streaming and an in-dashboard AI/patch workflow remain unimplemented.
- Prepare public repository, license, README, demo repo, short demo video, and final rule review.

**Acceptance:** clean checkout setup instructions work, demo uses a reproducible repository, the video is publicly accessible and within event limits, and all event requirements are rechecked.

## Engineering evidence (no invented metrics)

Record fixture counts and exact commands. Benchmark scan time and memory only after implementation, on named hardware and a reproducible corpus; report corpus size, warm/cold conditions, and tool versions. Measure model latency/cost separately from scanner performance.
