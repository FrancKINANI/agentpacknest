# Implementation Plan — Multi-Harness + Windows Detection

## Architecture

### Current State
- `HarnessAdapter` trait: `types.rs` — defines `name()`, `root()`, `config_path()`,
  `memory_path()`, `packages_path()`, `skills_path()`, `themes_path()`,
  `extensions_path()`, `secrets_path()`, `config_file()`
- Pi adapter: fully functional, detects via `PI_CODING_AGENT_DIR` → `~/.pi/agent`
- Aider adapter: skeleton only, struct defined but `detect()` not implemented

### Changes

#### Task 1: Complete Aider Detection

File: `src/harness/aider/detect.rs`

1. Implement `AiderInstallation::detect(path)`:
   - If explicit path given, verify it looks like an aider project dir
   - Otherwise, find `aider` binary via `which aider`
   - Read version from `aider --version` output
   - Validate: presence of `.aider.conf.yml` or `.env` in project root

2. Implement `HarnessAdapter` for `AiderInstallation`:
   - `name()` → "aider"
   - `root()` → project dir (not a global install dir)
   - `config_path()` → project dir (where `.aider.conf.yml` lives)
   - `memory_path()` → project dir (chat history is per-repo)
   - `packages_path()` → project dir (CONVENTIONS.md)
   - `skills_path()` → project dir
   - `launch.command()` → "aider" (from detected binary path)

3. Update `pn init` to accept `--harness aider`:
   - Validate harness name before calling detect
   - Use aider-specific manifest defaults

#### Task 2: Windows Detection for Pi

File: `src/harness/pi/detect.rs`

1. Add Windows paths to the detection chain:
   - `%APPDATA%\pi\agent\`
   - `%LOCALAPPDATA%\pi\agent\`
   - `%PI_HOME%\agent\` (env var fallback)

2. Use `dirs::data_dir()` / `dirs::config_dir()` for cross-platform base paths

3. Guard Unix-only paths with `#[cfg(unix)]` / `#[cfg(windows)]`

#### Task 3: Integration

1. Update `commands/init.rs` to dispatch based on harness name
2. Update `commands/pack.rs` to handle Aider-specific copy logic (config only)
3. Add tests for Aider detection and Windows paths

## Testing

- Unit tests: AiderInstallation::detect with mock binary
- Unit tests: PiInstallation with Windows-style paths (mock)
- Integration: `pn init --harness aider` with mock aider binary
- All existing tests must continue passing
