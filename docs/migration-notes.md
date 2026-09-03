# Migration Notes: v0.1.x → Canonical v1.0

**Status**: Superseded — the canonical-format items below were implemented in **v0.1.2** (see `docs/bundle-format.md`, which is the authoritative specification and is kept in sync with the implementation).

This file records the original migration plan. Implemented in v0.1.2:
- ✅ Canonical JSON signing (`Manifest::canonical_json()`, sorted keys) + bundled-public-key verification
- ✅ Strict `pn run` verification (refuse on any integrity/signature/structural failure)
- ✅ `--allow-unverified` with precise boundaries (trust checks only)
- ✅ Deterministic, NUL-delimited, fail-closed payload integrity incl. `secrets/keys.enc`
- ✅ Schema/version separation: `schema_version`, `bundle_version`, `integrity.format_version`, `crypto.format_version`
- ✅ Pack orchestration moved into `application/pack_bundle.rs`; commands are thin wrappers

Remaining for canonical v1.0 / Bundle Format v2:
- `payload/` wrapper directory (layout-only change)
- KEK/DEK envelope as the persisted secret format (primitives exist, unit-tested, unused)
- Archive encryption format spec

---

## 1. Summary of Changes Required

### Manifest Schema (`src/domain/manifest.rs`)

| Current Field | Action | Canonical Field |
|---------------|--------|-----------------|
| `launch.command` (string with args) | SPLIT | `launch.command` (string) + `launch.args` (Vec<String>) |
| `security.encryption` (string) | KEEP + VERSION | `security.encryption` + `crypto.format_version: 1` |
| `integrity.checksum` (string) | KEEP + VERSION | `integrity.checksum` + `integrity.format_version: 1` |
| (missing) | ADD | `bundle_version: 1` |
| (missing) | ADD | `crypto.format_version: 1` |
| (missing) | ADD | `compatibility.min_agentpacknest_version: "0.1.0"` |
| (missing) | ADD | `launch.working_directory` (already exists) |

### Integrity (`src/security/integrity.rs`)

| Current Behavior | Required Change |
|------------------|-----------------|
| Hashes `agent/` + `secrets/` at bundle root | Document as equivalent to `payload/` scope |
| Excludes `keys.enc`, `manifest.sig` | Must also exclude `manifest.yaml`, `signing/public.key` |
| Uses `walkdir` with `filter_map` | Must use `filter_map` → `?` for fail-closed on errors |
| Silent skip on read error | Return `Err` on any read failure |
| No format version | Add `integrity.format_version: 1` to manifest |

### Signing (`src/security/signing.rs`) — DONE in v0.1.2

| v0.1.2 Behavior | |
|------------------|-----------------|
| Signs `manifest.canonical_json()` (deterministic sorted-key JSON) | Verification recomputes canonical bytes and checks them against the bundled `signing/public.key` |
| Loads verifying key from `~/.config/agentpacknest/` | Keep for local signing; verification uses bundled `signing/public.key` |
| Saves signature to `manifest.sig` (bundle root) | Keep |
| Saves public key to `signing/public.key` (bundle) | Keep (already implemented in staging) |
| No canonical serialization | Add `canonicalize_for_signing()` function |

### Pack Command (`src/commands/pack.rs`)

| Current Behavior | Required Change |
|------------------|-----------------|
| Computes checksum after copying files | Move to application layer; compute over canonical payload |
| Signs manifest via local `sign_manifest()` | Delegate to `application::pack_bundle` |
| Writes `manifest.sig` at bundle root | Keep |
| **Does not write `signing/public.key`** | **ADD: call `signing::save_public_key()`** |
| Updates `manifest.integrity.checksum` | Also set `integrity.format_version`, `crypto.format_version` |

### Run Command (`src/application/run_bundle_impl.rs`)

| Current Behavior | Required Change |
|------------------|-----------------|
| Verifies checksum then signature (good) | Keep sequence; ensure fail-closed |
| Uses `split_whitespace()` on `launch.command` | **CHANGE: use structured `launch.args`** |
| `--allow-unverified` skips both checks | Keep; improve warning messages |
| Decrypts secrets after verification | Keep (correct order) |

### CLI (`src/cli.rs`)

| Current | Required |
|---------|----------|
| `--allow-unverified` flag added | Keep |
| `launch.command` parsing | Update help/examples for structured args |

---

## 2. File-by-File Migration Plan

### `src/domain/manifest.rs`
- [ ] Add `bundle_version: u32` (default 1)
- [ ] Add `crypto.format_version: u32` (default 1) — maybe as `crypto: CryptoMeta` struct
- [ ] Add `integrity.format_version: u32` (default 1)
- [ ] Add `compatibility: Compatibility` struct with `min_agentpacknest_version`
- [ ] Split `Launch` into `command: String` + `args: Vec<String>`
- [ ] Update `default_pi()` to populate new fields
- [ ] Update `validate()` for new fields
- [ ] Add `canonical_json()` method for signing

### `src/security/integrity.rs`
- [ ] Document payload scope in module docs
- [ ] Change `compute_bundle_checksum` to fail on any read error (`?` instead of `filter_map` + `if let Ok`)
- [ ] Ensure `manifest.yaml`, `manifest.sig`, `signing/public.key` excluded
- [ ] Add `IntegrityFormat` constant/version
- [ ] Update tests to verify fail-closed behavior

### `src/security/signing.rs`
- [ ] Add `canonicalize_for_signing(manifest: &Manifest) -> Result<Vec<u8>>`
- [ ] Implement deterministic JSON serialization with sorted keys
- [ ] Update `sign()` to accept canonical bytes (or compute internally)
- [ ] Update `verify()` to recompute canonical bytes from manifest
- [ ] Ensure `save_public_key()` is called during pack

### `src/security/crypto.rs`
- [ ] Document Argon2id parameters: `m=65536 (64MiB), t=3, p=4, salt_len=16, key_len=32`
- [ ] Add `CRYPTO_FORMAT_VERSION = 1` constant
- [ ] Ensure `encrypt_secrets`/`decrypt_secrets` use documented params
- [ ] Add format version to envelope header

### `src/application/pack_bundle.rs` (NEW or extend `run_bundle_impl.rs` pattern)
- [ ] Create `PackBundleRequest` / `PackBundleResult`
- [ ] Orchestrate: discover → stage → encrypt → integrity → manifest → sign → validate
- [ ] Call `signing::save_public_key()` after signing

### `src/commands/pack.rs`
- [ ] Remove inline `compute_bundle_checksum`, `sign_manifest`
- [ ] Construct `PackBundleRequest` from CLI args
- [ ] Call `application::pack_bundle::execute(request)`
- [ ] Print results

### `src/application/run_bundle_impl.rs`
- [ ] Change `launch.command` parsing to use `launch.args`
- [ ] Add `verify_bundle_integrity_and_signature` uses `integrity::verify_checksum` + `signing::verify_manifest_signature_with_pubkey`
- [ ] Ensure `--allow-unverified` behavior matches spec (§7)

### `src/commands/run.rs`
- [ ] Thin wrapper only (already done in staging)
- [ ] Pass `allow_unverified` through request

---

## 3. Compatibility Strategy

### Reading v0.1.x Bundles (No `payload/`, Schema 0.1/0.2)

```rust
fn resolve_payload_root(bundle_dir: &Path) -> PathBuf {
    if bundle_dir.join("payload").is_dir() {
        bundle_dir.join("payload")
    } else {
        bundle_dir.to_path_buf()  // v0.1.x layout
    }
}

fn compute_checksum(bundle_dir: &Path) -> Result<String> {
    let payload_root = resolve_payload_root(bundle_dir);
    // hash payload_root/agent, payload_root/secrets
}
```

### Writing Bundles (v0.1.x Layout for Now)

- Continue writing `agent/`, `secrets/` at bundle root
- Write `manifest.yaml`, `manifest.sig`, `signing/public.key` at bundle root
- Set `bundle_version: 1` (indicates v1 format conceptually)
- **Do not** create `payload/` wrapper until Bundle Format v2

### Manifest Schema Versioning

- Accept `schema_version: "0.1"` and `"0.2"` in validation
- Always write `"0.2"`
- New fields are optional with defaults for backward compatibility

---

## 4. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking existing bundles | Medium | High | Read-path compatibility layer; test with v0.1.x fixtures |
| Signature verification mismatch (YAML vs JSON) | High | High | Document current YAML signing; defer JSON to v0.2 |
| Checksum mismatch after migration | Medium | High | Golden master test: pack → compute → verify |
| `launch.args` breaking existing manifests | Medium | Medium | Default `args: []`; parse old string format on read |
| Argon2 param changes breaking decryption | Low | Critical | Document exact params; never change without version bump |

---

## 5. Test Updates Required

### New Tests to Add

| Test | Location |
|------|----------|
| Canonical JSON serialization deterministic | `manifest.rs` tests |
| Integrity fail-closed on read error | `integrity.rs` tests |
| Signature verification with bundled public key | `signing.rs` tests |
| `launch.args` parsing and execution | `run_bundle_impl.rs` tests |
| Full pack→verify→run cycle with fake Pi | `tests/integration/lifecycle_test.rs` |
| `--allow-unverified` bypass behavior | `run_bundle_impl.rs` tests |
| Cross-machine verification (simulated) | `tests/integration/` |

### Tests to Update

| Test | Change |
|------|--------|
| `manifest_roundtrip` | Include new fields |
| `default_pi_manifest_is_valid` | Check new fields populated |
| `checksum_excludes_manifest_and_signature` | Verify `signing/public.key` also excluded |
| `verify_signature` in `info.rs` | Use bundled public key, not local config |

---

## 6. Implementation Order (Phase B)

1. **Manifest schema** (`manifest.rs`) — foundation for everything
2. **Integrity model** (`integrity.rs`) — fail-closed, documented scope
3. **Signing model** (`signing.rs`) — canonical JSON, bundled pubkey
4. **Crypto format** (`crypto.rs`) — documented Argon2id params
5. **Application pack bundle** (`application/pack_bundle.rs`) — orchestration
6. **Commands pack/run** — thin wrappers
7. **Integration tests** — prove the full cycle
8. **Documentation updates** — README, SECURITY.md

---

## 7. Current Staging Branch Status

The staging branch already has:
- ✅ `--allow-unverified` flag in CLI and run flow
- ✅ Separated `run_bundle_impl.rs` from `commands/run.rs`
- ✅ Integrity scope clarified in docs (excludes manifest, sig, pubkey)
- ✅ `signing::save_public_key()` implemented
- ✅ Verification uses bundled public key
- ✅ Structured verification sequence in `run_bundle_impl.rs`

Completed in v0.1.2 (previously "Remaining for v0.1.1"):
- [x] Structured `launch.args` in manifest
- [x] Canonical JSON signing (canonical representation, not YAML)
- [x] Documented Argon2id parameters
- [x] Fail-closed integrity on read errors and symlinks
- [x] `crypto.format_version`, `integrity.format_version`, `compatibility` fields
- [x] Application layer pack orchestration
- [x] Full integration test suite (lifecycle, validation matrix, CLI black-box)

---

*These notes track the gap between current staging implementation and the canonical specification in `docs/bundle-format.md`. Each item should be addressed in Phase B implementation.*