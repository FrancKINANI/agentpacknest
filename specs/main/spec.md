# agentpacknest — Remaining Implementation Spec

## Context

agentpacknest (binary: `pn`) packages coding agents into portable bundles.
P0 (rename, snapshot), P1 (signing, encrypt-archive, rekey, ignore), and
P2.2 (CI) are complete. This spec covers the remaining items.

## What to Build

### 1. Multi-Harness Abstraction (P2.1)

The `HarnessAdapter` trait exists but is partially implemented.
The Aider harness has a skeleton (`harness/aider/`) but no real detection.

**Acceptance Criteria:**
- `HarnessAdapter` trait methods are all exercised by Pi
- Aider `detect()` works: finds `aider` binary via `which`, reads version
- Aider paths resolve correctly (`.aider.conf.yml`, `.env`, `.aider/`)
- `pn init --harness aider` creates a valid bundle with correct launch command
- `pn pack` for Aider copies config/skills correctly

### 2. Windows Detection (P2.3)

Pi detection currently only works on Unix (~/.pi/agent, PI_HOME, etc.).

**Acceptance Criteria:**
- On Windows: check `%APPDATA%\pi\agent\` and `%LOCALAPPDATA%\pi\agent\`
- `pn init --harness pi` doesn't crash on Windows (graceful fallback)
- Cross-platform path handling (Path/PathBuf everywhere, no hardcoded `/`)

## Constraints

- Don't break existing Pi workflow
- Aider support is detection + paths only (no pack copy logic yet for Aider)
- Windows: detection-only, no full support required
- All changes must pass CI (clippy -D warnings, fmt, tests)
