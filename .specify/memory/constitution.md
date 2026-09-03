# agentpacknest Constitution

## Core Principles

### I. Packaging Layer, Not an Agent
agentpacknest is NOT a new coding agent. It is a packaging and runtime layer
that sits on top of existing harnesses (Pi, Aider, etc.). It makes coding
agents portable by bundling their config, skills, memory, and encrypted secrets.

### II. Harness Abstraction
All harness interactions go through the single `Harness` contract in
`src/harness/traits.rs` (`detect` → `discover` → `prepare_runtime`). Adding a
new harness (e.g., Aider, Claude Code) must not require changes to the core
packaging logic. The contract defines: detection, portable-environment
discovery (components, secret sources, launch spec, runtime requirements), and
runtime preparation. Harness layout vocabulary (paths, packages, secret
sources) belongs to each harness's `discover()` implementation — never to
application/domain/security code. Core resolves harnesses only through
`HarnessRegistry` (`src/harness/registry.rs`); there is no second abstraction.

### III. Security First
- Secrets are ALWAYS encrypted at rest (AES-256-GCM + Argon2 key derivation)
- Passphrases are NEVER stored — only in memory during the operation
- Passphrase rotation (`pn rekey`) is atomic (decrypt with old passphrase,
  re-encrypt with new, temp-file rename) — a failure never destroys the
  only decryptable copy
- KEK/DEK envelope primitives exist but are NOT the persisted secret format in
  v0.1.x (rotation is direct re-encryption); the envelope is a v1.0 / Bundle
  Format v2 target
- Ed25519 signing provides tamper-evident bundles
- File permissions: keys.enc is 0600, keypair is 0600
- `env_clear()` in run prevents leaking host environment

### IV. Portability
- Bundles are primarily directories (optionally archived as .tar.gz)
- All internal paths are relative — no absolute paths in bundles
- Cross-platform: Linux, macOS, Windows (at least detection)
- Node.js is verified but NOT bundled (Pi harness)
- The bundle structure is deterministic and documented

### V. Simplicity (YAGNI)
- Start with one harness (Pi), add others only when needed
- No heavy dependencies without justification
- CLI remains lightweight and fast
- Prefer stdlib over custom implementations where possible

## Technical Constraints

- Language: Rust (edition 2021)
- CLI: clap with derive
- Serialization: serde + serde_yaml
- Crypto: aes-gcm, argon2, ed25519-dalek
- Error handling: anyhow + thiserror
- Binary name: `pn`
- Package name: `agentpacknest`
- Manifest schema version: 0.2 (`schema_version`); bundle format version: 1

## Development Workflow

- Features are developed on `staging` branch, merged to `main` after review
- One commit = one logical change with clear message
- CI runs: cargo check, cargo test, cargo clippy (-D warnings), cargo fmt --check
- All tests must pass before merge
- README limitations section must match actual capabilities

## Governance

This constitution supersedes all other practices for agentpacknest.
Amendments require documentation in this file with updated version and date.
All PRs/reviews must verify compliance with these principles.

**Version**: 1.1.0 | **Ratified**: 2026-09-02 | **Last Amended**: 2026-09-03

### Amendment 1.1.0 (2026-09-03)
Replaced the `HarnessAdapter` abstraction with the single live `Harness`
contract (`detect`/`discover`/`prepare_runtime`) ratified by the v0.2
corrections; Pi's layout vocabulary is declared by `PiHarness::discover()` and
Core resolves harnesses via `HarnessRegistry` only. Corrected the secret
rotation statement to match the implemented atomic re-encryption (`pn rekey`).
