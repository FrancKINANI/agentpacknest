# Tasks: AgentPackNest v0.1.1 — Correctness, Security, Testing & Architecture Completion

> **SUPERSEDED** — v0.1.1/v0.1.2 work is shipped. The current task list for harness work lives in `specs/main/tasks.md`. This file is kept as historical record.

## Phase 0: Foundation & Baseline

### T001 [P] [P0] Create fake Pi fixture and test infrastructure
- **Goal**: Set up temporary Pi installation fixture for integration tests
- **Action**: Write test fixture that sets up a temporary Pi directory with known content
- **Location**: tests/fixtures/pi_fixture/ or similar
- **Content**: settings.json, auth.json (with test API keys), sessions/, extensions/, skills/, themes/

### T002 [P] [P0] Run baseline test suite and capture results
- **Goal**: Establish baseline before changes
- **Action**: Run `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo build --release`
- **Deliverable**: Baseline test results documented; no regressions allowed

### T003 [P] [P0] Audit current test coverage gaps
- **Goal**: Identify what the existing tests cover and what they don't
- **Action**: Trace every test file, identify which CLI lifecycle paths are tested, which are missing
- **Deliverable**: Gap analysis report

## Phase 1: End-to-End Integration Tests (P0)

### T004 [P] [P0] Implement fake Pi integration test fixture
- **Goal**: Create reusable fixture for integration tests
- **Action**: Write test fixture that sets up a temporary Pi directory with known content
- **Location**: tests/fixtures/pi_fixture/ or similar

### T005 [P] [P0] Create end-to-end lifecycle integration tests
- **Goal**: Test the complete CLI lifecycle
- **Tests**: 
  - init succeeds
  - pack succeeds
  - manifest exists and is valid
  - expected components are copied
  - info succeeds
  - diff detects no drift immediately after packing
  - run --dry-run produces the expected launch configuration
- **Location**: tests/integration/lifecycle_test.rs or similar

### T006 [P] [P0] Create negative lifecycle tests
- **Goal**: Test error cases don't panic
- **Tests**: 
  - invalid bundle fails cleanly
  - missing manifest fails cleanly
  - corrupted bundle fails cleanly
  - unsupported harness fails cleanly
  - incorrect paths do not panic
- **Location**: tests/integration/negative_lifecycle_tests.rs

## Phase 2: Security and Integrity Tests (P0)

### T007 [P] [P0] Add checksum integrity tests
- **Goal**: Test that modifying packed files breaks verification
- **Tests**: 
  - pack bundle → modify a packed file → verification fails
  - pack bundle → modify manifest integrity metadata → verification fails

### T008 [P] [P0] Add signature integrity tests
- **Goal**: Test signature verification invariants
- **Tests**: 
  - sign manifest → verify succeeds
  - modify signed manifest → signature verification fails
  - invalid signature fails cleanly
  - missing signature fails cleanly
  - corrupted signature fails cleanly

### T009 [P] [P0] Add secret security audit tests
- **Goal**: Prove plaintext secrets not in bundle
- **Tests**: 
  - pack secret = SUPER_SECRET_VALUE
  - scan generated bundle files
  - SUPER_SECRET_VALUE must not exist outside encrypted ciphertext

### T010 [P] [P0] Add rekey integration tests
- **Goal**: Test KEK/DEK envelope flow
- **Tests**: 
  - create encrypted secrets with old passphrase
  - rekey using old → new passphrase
  - old passphrase fails
  - new passphrase succeeds
  - secret values remain identical
  - incorrect old passphrase
  - corrupted envelope
  - interrupted/failed rekey does not destroy existing secrets

## Phase 3: Security Policy and Hardening (P0)

### T011 [P] [P0] Implement security policy for `pn run`
- **Goal**: Clear policy: verify before run, override only with explicit flag
- **Action**: Modify `pn run` to verify integrity and signature before execution
- **Add**: `pn run --allow-unverified bundle` with strong warning
- **Define**: Exact behavior for missing/invalid signature, checksum failures, incomplete integrity

### T012 [P] [P0] Document security policy in README and SECURITY.md
- **Goal**: Clear documented policy
- **Action**: Update documentation with exactly what happens when:
  - signature is missing
  - signature is invalid
  - checksums fail
  - integrity metadata is incomplete
  - --allow-unverified is used

## Phase 4: Cryptographic and Architecture Improvements (P1)

### T013 [P] [P1] Define precise cryptographic format
- **Goal**: Specify Argon2id parameters and versioning
- **Action**: 
  - Specify Argon2id variant, memory cost, iteration cost, parallelism, salt length, nonce handling
  - Add version fields: application version, bundle format version, crypto format/version, manifest schema version
  - Do not rely on undocumented library defaults
- **Tests**: Compatibility and invalid/unsupported crypto version tests

### T014 [P] [P1] Fix application layer dependency direction
- **Goal**: CLI/commands → application → domain → harness/infrastructure/security
- **Action**: Refactor incrementally
- **Current**: application/run_bundle.rs delegates to commands::run
- **Target**: commands construct requests → application orchestrates → domain → harness/infrastructure/security
- **Constraint**: Preserve working behavior

### T015 [P] [P1] Complete/simplify architectural abstractions
- **Goal**: Remove dead/fake abstractions
- **Action**: Audit application/, domain/, harness/, infrastructure/
- **Rule**: If abstraction has no real responsibility, either complete migration or remove/simplify
- **Result**: Architecture with real dependency boundaries

### T016 [P] [P1] Review harness abstraction
- **Goal**: Keep Harness abstraction; remove Pi-specific assumptions from core
- **Action**: 
  - Keep Harness abstraction unless concrete issue requires change
  - Do not over-engineer plugin system
  - Pi remains reference production harness
  - Aider clearly marked unsupported/skeleton
  - Core principle: "Core application code should not know Pi-specific filesystem conventions"

## Phase 4: Isolation, Permissions, and Archive (P1)

### T017 [P] [P1] Add environment isolation tests
- **Goal**: Test env_clear() claim
- **Tests**: 
  - HOST_SECRET=should_not_leak in parent but absent from isolated launch
  - Allowed system variables preserved where required
  - Agent variables injected
  - Secret variables injected intentionally
  - Unrelated host variables not inherited
  - Do not make pn run unusable

### T018 [P] [P1] Verify file permissions on Unix
- **Goal**: Verify 0600 permissions for keys.enc
- **Tests**: 
  - keys.enc has owner-only permissions after creation
  - Document platform limitations if Windows not implemented

### T019 [P] [P1] Add symlink and path safety tests
- **Goal**: Test symlink and path safety claims
- **Tests**: 
  - symlink inside source environment
  - symlink pointing outside source root
  - malicious destination path
  - archive extraction path traversal
- **Behavior**: Safe and documented; never allow ../../outside

### T020 [P] [P1] Add archive security tests
- **Goal**: Test archive if advertised
- **Tests**: 
  - create archive
  - extract archive
  - verify contents
  - corrupted archive
  - malicious archive traversal path
  - archive extraction outside destination
  - invalid encrypted archive input

## Phase 5: Error Handling, Commands, and Polish (P2)

### T021 [P] [P2] Audit and fix error handling
- **Goal**: Remove unwrap/expect/panic from production paths
- **Focus**: Production code and user-controlled input
- **Rule**: User errors → meaningful messages, no panic, no secret exposure, no bundle corruption
- **Pattern**: Structured errors with context

### T022 [P] [P2] Audit command consistency
- **Goal**: Ensure all commands behave consistently
- **Commands**: pn init, pn pack, pn info, pn diff, pn unlock, pn rekey, pn run
- **Ensure**: Consistent path handling, argument naming, error messages, bundle validation behavior
- **Fix**: If documented but not supported, fix or correct documentation

### T023 [P] [P2] Audit README and SECURITY claims
- **Goal**: Verify every claim is implemented + tested OR documented as limitation
- **Action**: Audit every security/product claim in both files
- **Specific**: AES-256-GCM, Argon2 config, KEK/DEK rotation, Ed25519 signing, checksum verification, zeroization, env_clear isolation, 0600 permissions, symlink rejection, reproducibility score, provenance, stale bundle behavior

### T024 [P] [P2] Final validation and release preparation
- **Goal**: Ensure everything works before release
- **Action**: 
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - `cargo test` (all tests including new integration tests)
  - `cargo build --release`
  - Run at least one complete end-to-end scenario with fake Pi environment
- **Acceptance**: "A user can capture a Pi environment, package it, verify its integrity, move it, and reproduce the intended environment without secrets being exposed."

### T025 [P] [P2] Update version to v0.1.1
- **Action**: Update version strings in appropriate places
