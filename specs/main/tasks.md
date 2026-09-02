# Tasks — Multi-Harness + Windows Detection

## Task 1: Implement Aider detection
- [ ] Implement `find_aider_binary()` — find via `which`
- [ ] Implement `get_aider_version()` — parse `aider --version`
- [ ] Implement `AiderInstallation::detect(path)` with validation
- [ ] Implement `HarnessAdapter` for `AiderInstallation`
- [ ] Add tests: detect with mock binary, detect with explicit path, invalid path

## Task 2: Aider init support
- [ ] Update `commands/init.rs` to accept `--harness aider`
- [ ] Create `default_aider()` manifest function
- [ ] Dispatch to aider detection when harness=aider
- [ ] Add test: init with aider harness

## Task 3: Windows Pi detection
- [ ] Add `#[cfg(windows)]` paths to Pi detection chain
- [ ] Use `dirs::data_dir()` / `dirs::config_dir()` for cross-platform
- [ ] Add tests: Windows-style path detection (mock)

## Task 4: Integration & verification
- [ ] Verify `pn init --harness aider` works end-to-end
- [ ] Verify existing Pi tests still pass
- [ ] Run full CI: clippy, fmt, test
- [ ] Update README limitations section
