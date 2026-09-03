# Tasks — Second Harness End-to-End + Windows Detection

## Task 1: Complete Aider discover + prepare_runtime
- [ ] Implement `AiderHarness::discover(context)` describing portable components
  - [ ] `.aider.conf.yml` (config)
  - [ ] `.env` (secret source)
  - [ ] `.aider/` / chat history (memory)
  - [ ] Return `runtime_requirements` (Python) and launch spec
- [ ] Implement `AiderHarness::prepare_runtime(request)` returning `PreparedRuntime`
- [ ] Add tests: discover with mock project, prepare_runtime, invalid path

## Task 2: Aider init support
- [ ] Update `commands/init.rs` to accept `--harness aider` (via the registry)
- [ ] Create aider manifest defaults
- [ ] Dispatch to aider harness when harness=aider
- [ ] Add test: init with aider harness

## Task 3: Windows Pi detection
- [ ] Add `#[cfg(windows)]` paths to Pi detection chain
- [ ] Use `dirs::data_dir()` / `dirs::config_dir()` for cross-platform
- [ ] Add tests: Windows-style path detection (mock)

## Task 4: Integration & verification
- [ ] Verify `pn init --harness aider` works end-to-end
- [ ] Verify existing Pi tests still pass (Pi stays on the live `Harness` contract)
- [ ] Run full CI: clippy, fmt, test
- [ ] Update README limitations section
