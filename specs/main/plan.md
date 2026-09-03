# Implementation Plan — Second Harness End-to-End + Windows Detection

## Architecture

### Current State
- `Harness` contract: `traits.rs` — `detect()` → `discover()` → `prepare_runtime()`,
  with `HarnessContext`, `DetectionResult`, `PortableEnvironment` (components,
  launch, runtime requirements), `PortableComponent` (+ `SecretSource` kinds),
  `PrepareRuntimeRequest`, `PreparedRuntime`
- Pi harness: **fully functional** — `PiHarness` implements the contract;
  detection via `PI_CODING_AGENT_DIR` → `~/.pi/agent`; `discover()` declares
  config/memory/packages/secret sources; `prepare_runtime()` enforces Node ≥ 20
- Aider harness: scaffold only — `AiderHarness::detect()` works
  (binary + version), `discover()`/`prepare_runtime()` error as unimplemented

### Changes

#### Task 1: Complete Aider discover + prepare_runtime

File: `src/harness/aider/harness.rs`

1. Implement `AiderHarness::discover(context)`:
   - Describe `.aider.conf.yml` (config), `.env` (secret source), and
     `.aider/` / chat history as `PortableComponent`s
   - Return `runtime_requirements` (Python) and a launch spec
2. Implement `AiderHarness::prepare_runtime(request)`:
   - Return `PreparedRuntime` with command `aider` (from detected binary path),
     args, and working directory
3. Do NOT touch Core: pack/run consume the same registry path Pi uses

#### Task 2: Windows Detection for Pi

File: `src/harness/pi/detect.rs`

1. Add Windows paths to the detection chain:
   - `%APPDATA%\pi\agent\`
   - `%LOCALAPPDATA%\pi\agent\`
   - `%PI_HOME%\agent\` (env var fallback)

2. Use `dirs::data_dir()` / `dirs::config_dir()` for cross-platform base paths

3. Guard Unix-only paths with `#[cfg(unix)]` / `#[cfg(windows)]`

#### Task 3: Integration

1. Update `commands/init.rs` to dispatch based on harness name via the registry
2. Update `commands/pack.rs` to handle Aider-specific copy logic (config only)
3. Add tests for Aider discover/prepare_runtime and Windows paths

## Testing

- Unit tests: AiderHarness::discover/prepare_runtime with mock binary
- Unit tests: PiInstallation with Windows-style paths (mock)
- Integration: `pn init --harness aider` with mock aider binary
- All existing tests must continue passing
