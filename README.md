# SecuTron

SecuTron is an evidence-first local security scanner. The Rust CLI parses Python syntax, applies deterministic rules, and reports candidate findings. An opt-in finding-only explanation command can send selected report metadata to NVIDIA Nemotron through Nebius Token Factory; patch assistance and validation remain planned.

## Current implementation

- `secutron scan <path> [--format text|json|sarif]` walks Python and `.env` files under a repository root, matching extensions and `.env` names without case sensitivity.
- Skips symlinks and common generated/vendor directories (including Python virtual environments, tox/nox environments, package caches, `node_modules`, `target`, and `dist`; names are matched case-insensitively), and rechecks file containment before reading. Caps individual source files at 1 MiB, traversal at 25,000 directory entries and 256 levels, and results at 5,000 supported files and 10,000 findings. When directory collection completes, files over the 5,000 limit are reduced to the first 5,000 lexical paths and the scan is marked incomplete. If a traversal limit stops collection sooner, only the paths reached before that limit are considered. A 30-second deadline is checked between entries and files.
- Reports parse, read, size, file-count, directory-entry, depth, finding-count, and time-limit errors as incomplete scans. JSON includes `complete: false` whenever any supported file or path could not be fully scanned.
- `PY.SECRET.LITERAL` flags direct, annotated, and assignment-expression string-literal assignments, credential-like dictionary values, keyword arguments, and parameter defaults. `GEN.SECRET.LITERAL` checks credential-like keys in `.env` files. Values are never included in output, and finding ranges point only to the variable/key/argument/parameter name.
- `PY.SQL.UNTRUSTED` recognizes request data passed directly or through simple local variables as the query argument to execution calls, including raw request-supplied queries.
- `PY.COMMAND.UNTRUSTED` recognizes direct request markers or simple request-derived locals in `os.system`/`os.popen`, `asyncio.create_subprocess_shell`, and positional or `args=` inputs to calls named `run`, `popen`, `Popen`, or `call` when `shell=` is `True`, a statically nonzero numeric literal, or a nonempty string literal. Parenthesized literals are accepted; library identity for process-like calls is not resolved.
- `PY.CODE.UNTRUSTED` recognizes request-derived input passed to calls spelled `eval(...)`, `exec(...)`, `builtins.eval(...)`, `builtins.exec(...)`, `__builtins__.eval(...)`, or `__builtins__.exec(...)`. Other aliases and name shadowing are not resolved.
- `PY.CRYPTO.WEAK` flags direct MD5/SHA-1 constructor spellings; module identity and whether the digest is security-sensitive are not resolved.
- `PY.RANDOM.INSECURE` flags common direct calls to Python's `random` module; aliases and whether the value is security-sensitive are not resolved.
- `PY.PATH.UNTRUSTED` recognizes direct request markers or simple request-derived locals in built-in `open()` positional or `file=` path arguments, and in a method named `open`'s receiver or positional/`path=`/`file=` arguments. Method/library identity and path containment are not evaluated.
- Emits JSON and SARIF 2.1.0 with sorted findings/errors, rule metadata, and repository-relative paths.
- `secutron rules` prints the current supported patterns and their main limitations.
- `secutron pr-check <scan-report.json> [--fail-on high]` makes a fail-closed pull-request gate decision from a completed SecuTron report and emits JSON with a Markdown summary. Incomplete scans return exit code 3; qualifying findings return 1.
- `secutron benchmark <path> [--runs 1..10]` measures repeated scan wall time and reports median files/sec plus non-empty supported source lines/sec. The measurement includes process startup and does not label non-empty lines as logical LOC.
- `secutron explain <scan-report.json> <finding-id>` offers an opt-in Nebius/Nemotron explanation for one finding. It displays the destination and payload categories and requires interactive confirmation; it sends only that finding's metadata/evidence, never source files or `.env` values. Set `NEBIUS_API_KEY`; optionally set `SECUTRON_API_BASE` and `SECUTRON_MODEL`. The scan command itself remains offline.
- Text findings include the rule message, heuristic confidence, sanitized evidence labels, and limitations; source lines and detected secret values are not printed.

This is an early heuristic prototype, not a complete vulnerability scanner. A clean result does not establish that code is secure. The flow pass tracks simple local assignments in source order within a function, including annotated assignments, assignment expressions, and `for` loop targets. It does not model branch paths, aliases, attributes, sanitizers, imports, or interprocedural flows, and does not establish exploitability. False positives and missed cases are expected.

JSON line and column positions are one-based and columns count UTF-8 bytes. Non-ASCII source can therefore make the displayed column differ from a character-counting editor column. SARIF omits columns for this reason.

## Build and run

Requires Rust 1.85+ and Cargo (the package's declared minimum for Rust 2024 edition). From this directory:

```powershell
cargo run -- --help
cargo run -- --version
cargo run -- scan .
cargo run -- scan . --format json
cargo run -- scan . --format sarif
cargo run -- rules
cargo run -- explain scan.json <finding-id>
cargo run -- pr-check scan.json --fail-on high
cargo run -- benchmark fixtures/vulnerable-shop/vulnerable --runs 5
cargo run -- serve
cargo test --locked
```

Exit codes: `0` completed with no findings; `1` completed with findings; `2` invalid invocation/path; `3` incomplete scan. Rust dependencies are resolved from crates.io on first build.

## Local dashboard

Run `cargo run -- serve`, then open the loopback URL printed by SecuTron and enter the one-time token printed in the terminal. The dashboard's **Run a local scan** panel calls the authenticated loopback API; enter a repository folder on the machine running SecuTron. The token stays in page memory and reports are not persisted by the server. The page can also be opened directly as [`web/index.html`](web/index.html) to import saved JSON reports. Imported or live reports offer JSON download and a CLI explanation command template; the browser never contacts the AI provider.

The initial CLI integration fixtures are in [`fixtures/vulnerable-shop/`](fixtures/vulnerable-shop/). The `vulnerable/` examples are intentionally unsafe scanner inputs, not a runnable or deployable shop application.

## Docker Compose

With Docker Compose installed, run `docker compose up --build` and open `http://127.0.0.1:8765`. The image runs as a non-root user with a read-only filesystem and read-only repository mount; the host port is loopback-only. The mounted repository is available to the dashboard scanner as `/workspace`. Use `docker compose logs secutron` to read the one-time API token. To scan a different directory, set `SECUTRON_SCAN_PATH` before launching Compose (on Windows, use a path such as `C:/Users/you/projects/my-app`). Stop the service with `docker compose down`.

The separate Vercel deployment is a static report viewer. It supports importing and reviewing JSON reports; the local scanner API is intentionally unavailable on the hosted domain.

## Project decisions

- First language: Python, parsed with Tree-sitter.
- Initial rules: heuristic credential-like literals and limited Python source-to-sink patterns.
- Local scanning works without model credentials or network access after dependencies are installed.
- The local dashboard in `web/` uses the supplied SecuTron artwork, imports CLI JSON reports, and can request local scans through the authenticated Axum server. It does not call the model provider or store reports.

See [`docs/`](docs/product-requirements.md) for product, architecture, safety, contracts, and roadmap.



Current implementation boundaries are listed in [implementation status](docs/implementation-status.md).

