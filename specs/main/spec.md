# agentpacknest — Remaining Implementation Spec

## Context

agentpacknest (binary: `pn`) packages coding agents into portable bundles.
P0 (rename, snapshot), P1 (signing, encrypt-archive, rekey, ignore), and
P2.2 (CI) are complete. This spec covers the remaining items.

## What to Build

### 1. Second Harness End-to-End (P2.1)

The single `Harness` contract (`src/harness/traits.rs`:
`detect` → `discover` → `prepare_runtime`) is **live and fully wired for Pi**:
`pn init`/`pn pack`/`pn run` resolve harnesses through `HarnessRegistry`, and
all Pi layout vocabulary (config/memory/packages/secret sources, Node ≥ 20) is
declared by `PiHarness::discover()` — the application layer never hardcodes Pi
paths. The Aider harness (`harness/aider/harness.rs`) is a **detection-only
scaffold**: `detect()` finds the binary and version, while `discover()` and
`prepare_runtime()` return clean "not implemented" errors.

**Acceptance Criteria (v0.2):**
- The `Harness` contract methods are exercised by Pi end-to-end
  (detect/discover at pack time, prepare_runtime at run time)
- Aider `discover()` describes its portable environment
  (`.aider.conf.yml`, `.env`, `.aider/` chat history)
- Aider `prepare_runtime()` returns a valid launch spec
- `pn init --harness aider` creates a valid bundle with the correct launch command
- `pn pack`/`pn run` for Aider copy config/secrets correctly

### 2. Windows Detection (P2.3)

Pi detection currently only works on Unix (~/.pi/agent, PI_HOME, etc.).

**Acceptance Criteria:**
- On Windows: check `%APPDATA%\pi\agent\` and `%LOCALAPPDATA%\pi\agent\`
- `pn init --harness pi` doesn't crash on Windows (graceful fallback)
- Cross-platform path handling (Path/PathBuf everywhere, no hardcoded `/`)

## Constraints

- Don't break the existing Pi workflow (Pi is behind the live contract)
- Aider support is detection + paths first, then end-to-end wiring on the
  same `Harness` contract
- Windows: detection-only, no full support required
- All changes must pass CI (clippy -D warnings, fmt, tests)
