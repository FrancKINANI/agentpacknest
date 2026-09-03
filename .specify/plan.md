# Plan: AgentPackNest v0.1.1 — Correctness, Security, Testing & Architecture Completion

**Version**: v0.1.1
**Branch**: staging
**Status**: **SUPERSEDED** — v0.1.1/v0.1.2 work is shipped (see `docs/bundle-format.md`, the authoritative spec). The current working plan for harness work lives in `specs/main/plan.md`. This file is kept as historical record.

## Summary
Make the existing v0.1 implementation trustworthy, thoroughly tested, internally coherent, and complete the architectural groundwork that already exists.

## User Stories & Priorities

### US01: End-to-End Lifecycle Testing (P0)
- **Goal**: Create genuine integration tests proving the complete CLI lifecycle with a fake Pi fixture
- **Critical path**: Fake Pi installation → pn init → pn pack → verify bundle → pn info → pn diff → pn run --dry-run
- **Acceptance**: All lifecycle steps succeed; no panics on invalid input; bundle integrity verified

### US02: Tampering and Integrity Tests (P0)
- **Goal**: Add explicit tests for security invariants
- **Checksum integrity**: Modify packed file → verification fails; Modify manifest integrity → verification fails
- **Signature integrity**: Sign manifest → verify succeeds; Modify signed manifest → signature verification fails; Invalid/missing/corrupted signature → fails safely

### US03: Security Policy for `pn run` (P0)
- **Goal**: Implement clear security policy
- **Policy**: `pn run bundle` must verify integrity and signature before execution
- **Fallback**: `pn run --allow-unverified bundle` with explicit warning
- **Failure handling**: Define exact behavior for missing/invalid signature, checksum failures, incomplete integrity

### US04: Secret Security Audit (P0)
- **Goal**: Repository-wide audit for secret leakage
- **Search**: All code for println!, eprintln!, debug!, info!, warn!, error!, format!, panic!, expect
- **Verification**: Plaintext secrets must never be in logs, error messages, debug output, panic messages, temporary files
- **Test**: Pack SUPER_SECRET_VALUE → scan bundle files → VALUE must not exist outside encrypted ciphertext

### US05: Rekey Integration Tests (P0)
- **Goal**: Complete KEK/DEK envelope tests
- **Flow**: Create encrypted secrets with old passphrase → rekey old→new → old fails, new succeeds → secret values identical
- **Negative**: Incorrect old passphrase, corrupted envelope, interrupted/failed rekey does not destroy existing secrets
- **Atomic**: Use atomic replacement when rewriting encrypted secret material

### US06: Crypto Format Clarity (P1)
- **Goal**: Define precise cryptographic format
- **Specify**: Argon2id variant, memory cost, iteration cost, parallelism, salt length, nonce handling, encryption algorithm version
- **Versioning**: AgentPackNest application version | Bundle format version | Crypto format/version | Manifest schema version
- **Tests**: Compatibility and invalid/unsupported crypto version tests

### US07: Application Layer Dependency Direction (P1)
- **Goal**: Fix dependency direction: CLI/commands → application → domain → harness/infrastructure/security
- **Current**: application → commands (partly façades delegating back)
- **Target**: CLI/commands parse input → construct requests → call application → domain → harness/infrastructure/security
- **Refactor**: Incrementally fix without breaking working behavior

### US08: Remove Dead/Fake Architectural Abstractions (P1)
- **Goal**: Audit and complete/simplify abstractions
- **Ask**: "Does this abstraction currently have a real responsibility?"
- **Action**: Complete migration properly OR remove/simplify
- **Result**: Architecture must have real dependency boundaries

### US09: Harness Abstraction Review (P1)
- **Goal**: Keep Harness abstraction unless concrete issue requires change
- **Do not**: Over-engineer plugin system
- **Pi**: Reference production harness; Aider clearly marked unsupported/skeleton
- **Core principle**: "Core application code should not know Pi-specific filesystem conventions"

### US10: Environment Isolation Tests (P1)
- **Goal**: Test env_clear() claim
- **Tests**: 
  - HOST_SECRET=should_not_leak in parent but absent from isolated launch
  - Allowed system variables preserved where required
  - Agent variables injected
  - Secret variables injected intentionally
  - Unrelated host variables not inherited
  - Do not make pn run unusable

### US11: File Permissions (P1)
- **Goal**: Verify 0600 permissions claim on Unix
- **Test**: keys.enc has owner-only permissions after creation
- **Document**: If Windows not implemented, do not claim universal guarantees; document platform limitation

### US12: Symlink and Path Safety (P1)
- **Goal**: Test symlink and path safety claims
- **Test**: Symlinks inside source, symlinks pointing outside root, malicious destination paths, archive extraction path traversal
- **Behavior**: Safe and documented; never allow ../../outside paths

### US13: Archive Security (P1)
- **Goal**: Test archive if advertised
- **Tests**: create archive, extract archive, verify contents; corrupted archive, malicious traversal, extraction outside destination, invalid encrypted archive
- **Action**: Complete or remove claim

### US14: Atomic File Operations (P1)
- **Goal**: Audit writes to critical files
- **Pattern**: write temp file → flush/sync → atomic rename
- **Important**: pn rekey — failed rekey must not destroy only decryptable copy
- **Tests**: Failure-oriented tests

### US15: Reproducibility Score (P1)
- **Goal**: Audit score determinism and explainability
- **Criteria**: Deterministic, explainable, based only on facts measured
- **Format**: Score with reasons (✓/✗/⚠)
- **Tests**: Prove score determinism

### US16: README and SECURITY Claims Audit (P1)
- **Goal**: Verify every claim in README.md and SECURITY.md
- **Rule**: For each claim: implemented + tested, OR clearly documented as limitation
- **Specific**: AES-256-GCM, Argon2 config, KEK/DEK rotation, Ed25519 signing, checksum verification, zeroization, env_clear isolation, 0600 permissions, symlink rejection, reproducibility score, provenance, stale bundle behavior

### US16: Error Handling (P2)
- **Goal**: Audit production paths for unwrap/expect/panic
- **Focus**: Production code and user-controlled input
- **Rule**: User errors → meaningful messages, no panic, no secret exposure, no bundle corruption
- **Pattern**: Structured errors with context

### US17: Command Consistency (P2)
- **Goal**: Audit all supported commands for consistency
- **Commands**: pn init, pn pack, pn info, pn diff, pn unlock, pn rekey, pn run
- **Ensure**: Consistent path handling, argument naming, error messages, bundle validation behavior
- **Fix**: If documented but not supported, fix or correct documentation

## Test Requirements

Before declaring v0.1.1 complete, run:
- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo build --release`

Test suite should cover:
- **Unit tests**: crypto primitives, manifest validation, reproducibility scoring, harness detection, integrity verification
- **Integration tests**: real CLI/application lifecycle, pack→inspect→diff, secrets lifecycle, rekey lifecycle, signature verification, tampering
- **Security negative tests**: wrong passphrase, corrupted ciphertext, tampered files, tampered manifest, invalid signature, symlink traversal, path traversal, host environment leakage

## Scope Limits

**DO NOT add**:
- new production harnesses
- dynamic plugin loading
- MCP support
- Marketplace
- Registry
- SaaS
- Web UI
- remote bundle service

**DO NOT perform**: Speculative rewrite

This is a correctness and hardening release.

## Versioning

Released as: **v0.1.1**

Version meaning: "v0.1 functionality, corrected and hardened, with the already-started architectural foundations made internally coherent."

Do not market as v0.2 multi-harness release.
