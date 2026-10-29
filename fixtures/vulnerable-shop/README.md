# vulnerable-shop scanner fixtures

This tiny, dependency-free shop sketch exists only to exercise SecuTron's current rules. It is not a runnable application and must not be deployed. The `vulnerable/` folder intentionally contains unsafe patterns; `secure/` contains narrow negative examples; `edge-cases/` covers `.env` parsing; and `incomplete/` checks syntax-error reporting.

Run the end-to-end fixture checks from the project root with `cargo test --locked`.
