# agy-intercept-bash

Deterministic, zero-overhead Bash and Shell command interceptor hook for **Google AntiGravity CLI (`agy-cli`)** written in pure Rust `std`.

## Architecture & Invariants

- **Pure Rust `std`**: 0 external crate dependencies, compiles in <1s.
- **Embedded RFC-8259 JSON parser**: handles UTF-8 strings and Cyrillic commit messages without external dependencies.
- **Quote-aware shell tokenizer**: accurately splits chained commands (`&&`, `||`, `;`, `|`) avoiding naive split bugs.
- **Recursive `bash -c "..."` parsing**: inspects nested shell wrappers.
- **Deterministic Security Gates**:
  - `ALLOW`: safe read-only operations, status checks, formatters, and whitelisted test targets.
  - `DENY`: system-level destructive commands (`rm -rf /`, `mkfs`, `dd`, fork bombs, unauthorized git pushes/commits).
  - `FORCE_ASK`: user confirmation required for sensitive actions.
  - `CARGO_BUILD_JOBS`: enforces `-j 2` CPU limit on dual-core hosts.

## Build & Test

```bash
cargo test
cargo build --release
```
