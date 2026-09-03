# AgentPackNest Bundle Format Specification

**Version**: 1.0 (Bundle Format v1)
**Manifest Schema**: 0.2
**AgentPackNest Application**: 0.2.0

---

## 1. Directory Structure

A valid AgentPackNest bundle has the following canonical structure:

```
<bundle-root>/
│
├── manifest.yaml              # REQUIRED — Bundle metadata & integrity
├── manifest.sig               # REQUIRED — Ed25519 signature of manifest.yaml
│
├── signing/
│   └── public.key             # REQUIRED — Public verification key (32 bytes, raw Ed25519)
│
├── payload/
│   ├── agent/
│   │   ├── config/            # Agent configuration files
│   │   ├── skills/            # Installed skills
│   │   ├── extensions/        # Installed extensions
│   │   ├── themes/            # Installed themes
│   │   ├── memory/            # Session memory/state (portable)
│   │   └── workspace/         # Workspace files (optional)
│   │
│   └── secrets/
│       └── keys.enc           # Encrypted secrets (AES-256-GCM + Argon2id)
│
└── optional/                  # Future extensibility — not hashed
    └── ...
```

### Compatibility Note

The current implementation (v0.1.x) uses a slightly different layout at the bundle root:

```
<bundle-root>/
├── manifest.yaml
├── manifest.sig
├── agent/              # ← payload/agent/
├── secrets/            # ← payload/secrets/
└── signing/
    └── public.key
```

**Migration to v1.0**: The `payload/` wrapper is introduced in Bundle Format v1 to create an unambiguous integrity boundary. v0.1.x bundles without `payload/` are still readable; the integrity scope is computed over `agent/` and `secrets/` directories at the bundle root. This is a layout difference only — the conceptual payload boundary is identical.

---

## 2. Payload Definition

**The payload contains everything whose modification should change the portable environment.**

### Included in Payload (integrity-protected)

| Path | Description |
|------|-------------|
| `payload/agent/config/` | Agent configuration files |
| `payload/agent/skills/` | Skills |
| `payload/agent/extensions/` | Extensions |
| `payload/agent/themes/` | Themes |
| `payload/agent/memory/` | Portable session memory/state |
| `payload/agent/workspace/` | Workspace files (if any) |
| `payload/secrets/keys.enc` | Encrypted secrets blob |

### Excluded from Payload (not integrity-protected)

| Path | Reason |
|------|--------|
| `manifest.yaml` | Metadata — contains the integrity digest itself |
| `manifest.sig` | Signature — cannot be covered by its own signature |
| `signing/public.key` | Verification key — not part of the portable environment |
| `optional/` | Future extensibility — explicitly outside integrity boundary |
| `launch` (root) | Legacy placeholder from older `pn init` — never executed; `pn run` uses `manifest.launch` (not created since v0.1.2) |

### Harness-Specific Payload Rules

**Pi Harness (v0.1.x → v0.2 component model)**: the mapping below is declared
by `PiHarness::discover()` (`src/harness/pi/harness.rs`) and consumed by Core:
- `agent/config/` ← loose config files at the Pi agent root (`~/.pi/agent/settings.json`, …)
- `agent/memory/` ← `~/.pi/agent/sessions/` (portable subset)
- `agent/packages/extensions/` ← `~/.pi/agent/packages/extensions/`
- `agent/packages/skills/` ← `~/.pi/agent/packages/skills/`
- `agent/packages/themes/` ← `~/.pi/agent/packages/themes/`
- `secrets/keys.enc` ← encrypted by Core from Pi's declared secret sources:
  `auth.json` (JSON credentials), `secrets/` (key-per-file), and `.env`-style
  files at the agent root and under `config/` — never copied as plaintext

**Future harnesses** must define their portable component mapping explicitly in their
`Harness::discover()` implementation (`src/harness/traits.rs`).

---

## 3. Manifest Schema (schema_version: "0.2")

```yaml
# REQUIRED: Schema version this manifest conforms to
schema_version: "0.2"

# REQUIRED: AgentPackNest version that created this manifest
agentpacknest_version: "0.2.0"

# REQUIRED: Bundle format version (increments on structural changes)
bundle_version: 1

# REQUIRED: Bundle identity metadata
bundle:
  name: "my-agent"                    # Human-readable name
  id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"  # UUID v4
  created_at: "2025-01-15T12:34:56Z"  # ISO 8601 UTC
  created_by: "julius"                # Username/identifier
  description: "Optional description" # Optional

# REQUIRED: Harness identification
harness:
  name: "pi"                          # "pi" | future harness names
  version: "0.84.4"                   # Harness version at pack time
  source: "https://pi.dev"            # Optional: install source URL

# OPTIONAL: Platform where bundle was created
platform:
  os: "linux"                         # std::env::consts::OS
  arch: "x86_64"                      # std::env::consts::ARCH

# REQUIRED: What components are present in the payload
contents:
  config: true
  memory: false
  skills: true
  secrets: true

# OPTIONAL: Package inventory (extensions, skills, themes)
packages:
  extensions:
    - name: "ext-example"
      version: "1.0.0"
      source: "https://example.com"
      path: "extensions/ext-example"
  skills: []
  themes: []

# REQUIRED: Runtime requirements
runtime:
  required:
    - name: "pi-runtime"
      min_version: "0.1.0"

# REQUIRED: Launch specification (structured, no shell parsing)
launch:
  command: "pi"
  args: ["--agent-dir", "agent"]
  working_directory: "."

# REQUIRED: Security metadata
security:
  secrets_encrypted: true
  encryption: "aes-256-gcm/argon2id/v1"

# REQUIRED: Integrity metadata
integrity:
  algorithm: "sha256"
  checksum: "a1b2c3d4e5f6..."         # SHA-256 of canonical payload
  format_version: 1

# OPTIONAL: Crypto format version (for future migration)
crypto:
  format_version: 1

# OPTIONAL: Provenance / snapshot metadata
origin:
  origin_machine: "host.example.com"
  packed_at: "2025-01-15T12:34:56Z"
  source_state_hash: "abc123..."      # Hash of harness source at pack time

# OPTIONAL: Compatibility requirements
compatibility:
  min_agentpacknest_version: "0.1.0"
```

### Field Requirements

| Field | Required | Notes |
|-------|----------|-------|
| `schema_version` | ✅ | Must be "0.1" or "0.2" |
| `agentpacknest_version` | ✅ | Semantic version of `pn` that created this |
| `bundle_version` | ✅ | Integer, currently 1 |
| `bundle.name` | ✅ | Non-empty |
| `bundle.id` | ✅ | Valid UUID v4 (36 chars, 4 hyphens) |
| `bundle.created_at` | ✅ | ISO 8601 UTC, must contain 'T' and end with 'Z' |
| `bundle.created_by` | ✅ | Non-empty |
| `harness.name` | ✅ | Must be in known harnesses list ("pi" currently) |
| `harness.version` | ✅ | Non-empty |
| `launch.command` | ✅ | Non-empty (executable name) |
| `launch.args` | ✅ | Array of strings (may be empty) |
| `integrity.algorithm` | ✅ | Must be "sha256" |
| `integrity.checksum` | ⚠️ | Required after `pn pack` |
| `crypto.format_version` | ✅ | Integer, currently 1 |

---

## 4. Version Separation

The following version concepts are **independent** and must not be conflated:

| Concept | Field | Current Value | Purpose |
|---------|-------|---------------|---------|
| AgentPackNest Application | `agentpacknest_version` | "0.2.0" | Version of the `pn` binary |
| Bundle Format | `bundle_version` | 1 | Structural layout of bundle directory |
| Manifest Schema | `schema_version` | "0.2" | YAML schema of manifest.yaml |
| Integrity Format | `integrity.format_version` | 1 | How payload checksum is computed |
| Crypto Format | `crypto.format_version` / `security.encryption` | 1 / "aes-256-gcm/argon2id/v1" | Encryption algorithm & KDF params |
| Harness Version | `harness.version` | "0.84.4" | Version of the agent runtime |
| Compatibility | `compatibility.min_agentpacknest_version` | "0.1.0" | Minimum `pn` that can read this bundle |

**Rationale**: A bundle created by `pn v0.1.1` with Bundle Format v1, Schema v0.2, Integrity v1, Crypto v1 must be readable by `pn v0.1.2` without format changes, even if the application version bumped.

---

## 5. Integrity Model

### Scope

The integrity checksum covers **exactly the payload directories**:

```
payload/agent/              (recursive)
payload/secrets/keys.enc
```

### Excluded from Integrity

```
manifest.yaml
manifest.sig
signing/public.key
optional/
```

### Canonical Hashing Algorithm

```
payload_digest = SHA-256(
    for each file in payload in deterministic order:
        relative_path_from_bundle_root || NUL || file_contents
)
```

**Deterministic ordering**: Files sorted by relative path (UTF-8 byte order, `/` as separator).

**Path normalization**:
- Paths are relative to bundle root
- Use forward slash `/` as separator (even on Windows)
- No leading `./`
- No trailing slashes

**Encoding**:
- `relative_path` is UTF-8 encoded
- NUL byte (`0x00`) separates path from content
- Empty files contribute `path + NUL + empty`
- No additional delimiters between files

### Failure Behavior

| Condition | Behavior |
|-----------|----------|
| File unreadable (permission denied) | **Fail** — do not skip silently |
| Traversal error (I/O error) | **Fail** — do not skip silently |
| Malformed path (strip_prefix fails) | **Fail** — do not skip silently |
| Symlink encountered | **Fail** — symlinks rejected at pack time |
| Directory missing | **Skip** — directory may be absent (e.g., no memory) |

**Principle**: Integrity verification fails closed. Any inability to hash the complete declared payload is a verification failure.

### v0.1.2 Implementation Note

The code computes the checksum over `agent/` and `secrets/` at the bundle root (no `payload/` wrapper) — the v0.1.x payload boundary. Paths are canonicalized to forward slashes, files are sorted by canonical path, each file contributes `canonical_path ‖ NUL ‖ contents`, and any traversal/symlink/read error fails the computation. The `payload/` wrapper will be introduced in Bundle Format v2 with an identical scope.

---

## 6. Signing Model

### What is Signed

**The canonical manifest serialization** — NOT the manifest object, NOT the manifest.yaml file bytes directly.

### Canonical Manifest Serialization (for signing)

```
canonical_bytes = serialize_to_json(manifest, options={
    sort_keys: true,
    no_trailing_whitespace: true,
    utf8: true,
    deterministic_float: true
})
```

**Rationale**: YAML serialization is not guaranteed stable across libraries/versions. JSON with sorted keys is deterministic and cross-platform.

**Implemented in v0.1.2**: signing uses the canonical JSON representation described above. `Manifest::canonical_json()` serializes to JSON with recursively sorted object keys, which is deterministic across machines and serde versions. Verification (`pn run`, `pn info`) recomputes the canonical bytes from the parsed manifest and verifies them against the **bundled** public key (`signing/public.key`) — the verifier never needs the signer's private key.

### Signature Algorithm

| Component | Choice |
|-----------|--------|
| Algorithm | Ed25519 (pure, no pre-hashing) |
| Input | Canonical manifest bytes (as defined above) |
| Output | 64-byte signature (R || S) |
| Public key | 32-byte raw Ed25519 verifying key |
| Public key location | `signing/public.key` (in bundle, portable) |
| Private key location | `~/.config/agentpacknest/keypair` (NEVER in bundle) |

### Verification Process

1. Load `manifest.yaml` → parse → validate schema
2. Load `manifest.sig` → 64 bytes
3. Load `signing/public.key` → 32 bytes
4. Recompute canonical manifest bytes from parsed manifest
5. Verify `Ed25519.verify(canonical_bytes, signature, public_key)`
6. Return valid/invalid

### Trust Model

**Signature verification answers**: *"Was this manifest signed by the holder of the private key corresponding to this public key?"*

**Signature verification does NOT answer**:
- "Do I trust the signer?"
- "Is the bundle safe to run?"
- "Is the payload unmodified?" (that's integrity's job)

**For v0.1.x**: No PKI, no certificates, no trust network. The public key travels with the bundle for portability. Trust is a policy decision outside this specification.

---

## 7. Verification Sequence (pn run)

```
pn run <bundle>
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. LOCATE BUNDLE                                            │
│    - Resolve path (default: .)                              │
│    - Must be directory                                      │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. VALIDATE STRUCTURE                                       │
│    - manifest.yaml exists                                   │
│    - manifest.sig exists (required by default)              │
│    - signing/public.key exists (required by default)        │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. PARSE & VALIDATE MANIFEST                                │
│    - Parse YAML                                             │
│    - Validate schema_version ∈ {"0.1", "0.2"}               │
│    - Validate all required fields present                   │
│    - Validate UUID format, ISO 8601 format, known harness   │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. VERIFY PAYLOAD INTEGRITY                                 │
│    - Compute SHA-256 of payload (per §5)                    │
│    - Compare with manifest.integrity.checksum               │
│    - MISMATCH → FAIL (unless --allow-unverified)            │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. VERIFY MANIFEST SIGNATURE                                │
│    - Load signing/public.key                                │
│    - Load manifest.sig                                      │
│    - Recompute canonical manifest bytes                     │
│    - Verify Ed25519 signature                               │
│    - INVALID/MISSING → FAIL (unless --allow-unverified)     │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. CHECK COMPATIBILITY                                      │
│    - manifest.compatibility.min_agentpacknest_version       │
│    - Runtime requirements (e.g., node >= 20 for Pi)         │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. DECRYPT SECRETS (only after all above pass)              │
│    - Prompt for passphrase (or use --passphrase flag)       │
│    - Decrypt secrets/keys.enc with the Argon2id-derived     │
│      AES-256-GCM key (see §10 Secret Blob Format)           │
│    - Zeroize passphrase and plaintext after use             │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. BUILD ISOLATED ENVIRONMENT                               │
│    - env_clear()                                            │
│    - Inject whitelisted system vars (PATH, HOME, etc.)      │
│    - Inject AGENTPACKNEST_* vars                            │
│    - Inject decrypted secrets as env vars                   │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. EXECUTE                                                  │
│    - Command::new(launch.command).args(launch.args)         │
│    - No shell parsing                                       │
└─────────────────────────────────────────────────────────────┘
```

### Override Flag: `--allow-unverified`

| Condition | Default | With `--allow-unverified` |
|-----------|---------|---------------------------|
| Missing checksum | FAIL | WARN + continue |
| Checksum mismatch | FAIL | WARN + continue |
| Missing signature | FAIL | WARN + continue |
| Invalid signature | FAIL | WARN + continue |
| Missing public key | FAIL | WARN + continue |
| All verified | ✓ proceed | ✓ proceed |

**Warning message format**:
```
⚠ WARNING: --allow-unverified specified — <reason>
  the bundle may have been tampered with
  do not run bundles from untrusted sources
```

---

## 8. Secret Boundary

### Encrypted Secrets Location

`payload/secrets/keys.enc` — **inside the integrity-protected payload**

### Implications

| Action | Effect |
|--------|--------|
| Modify `keys.enc` | → Integrity check fails |
| Re-encrypt with different passphrase | → `keys.enc` changes → Integrity check fails |
| Rekey (`pn rekey`) | → Must recompute integrity checksum & re-sign manifest |

### Secret Plaintext Handling

| Must Never | Must Always |
|------------|-------------|
| Written to manifest.yaml | Encrypted with AES-256-GCM |
| Logged (any level) | Zeroized after use |
| Included in integrity metadata as plaintext | Protected by KEK/DEK envelope |
| Written to temporary files | In-memory only during run |

### Secret Blob Format (v0.1.2)

```
Passphrase
    │
    ▼
Argon2id(m=64MiB, t=3, p=4, salt=16B)
    │
    ▼
AES key (32B)
    │
    ▼
AES-256-GCM encrypts the secrets JSON
    │
    ▼
Stored: salt(16B) || nonce(12B) || ciphertext + GCM tag
```

- `crypto.format_version: 1` identifies this scheme; parameters MUST NOT
  change without incrementing it.
- `security.encryption: "aes-256-gcm/argon2id/v1"` (informational string).
- `pn rekey` rotates the passphrase by decrypting with the old passphrase and
  re-encrypting with the new one. The write is atomic (temp file + rename),
  so a wrong old passphrase or a crash mid-write never destroys the only
  decryptable copy.
- KEK/DEK envelope primitives exist in the codebase (unit-tested) but are not
  used for the v1 secret blob; they are reserved for a future format version
  that enables rotation without touching the ciphertext.

---

## 9. Launch Format

### Structured Launch Specification

```yaml
launch:
  command: "pi"              # Executable name (looked up in PATH)
  args:                      # Array of arguments (no shell parsing)
    - "--agent-dir"
    - "agent"
  working_directory: "."     # Relative to bundle root
```

### Execution

```rust
Command::new(&manifest.launch.command)
    .args(&manifest.launch.args)
    .current_dir(bundle_root.join(manifest.launch.working_directory.unwrap_or(".")))
    .env_clear()
    // ... inject env vars
```

**Rationale**: Avoids shell parsing ambiguity, injection risks, and platform differences.

---

## 10. Pack Creation Sequence (Canonical)

```
1. DISCOVER
   Detect harness installation (Pi, Aider, etc.)
   Read harness version, paths

2. STAGE
   Create bundle directory structure
   Copy portable components to payload/agent/
   (config, skills, extensions, themes, memory)

3. ENCRYPT SECRETS
   Scan harness for secrets (secrets/, .env files)
   Prompt for passphrase (with confirmation)
   Encrypt via KEK/DEK → payload/secrets/keys.enc

4. FINALIZE PAYLOAD
   Payload is now complete and immutable

5. COMPUTE INTEGRITY
   checksum = SHA-256(payload) per §5
   manifest.integrity.checksum = checksum

6. CONSTRUCT MANIFEST
   Fill all metadata fields
   Include: bundle, harness, platform, contents, packages,
            runtime, launch, security, integrity, origin, compatibility

7. CANONICAL SERIALIZATION
   canonical_bytes = JSON(manifest, sorted_keys=true)

8. SIGN
   signature = Ed25519.sign(canonical_bytes, private_key)
   Write manifest.sig
   Write signing/public.key (public key only)

9. VALIDATE
   Re-verify checksum on written bundle
   Re-verify signature on written manifest
   Only then declare success
```

### Critical Invariants

1. **Payload is frozen after step 4** — nothing in payload changes after integrity calculation
2. **Manifest is frozen after step 8** — manifest does not change after signing
3. **Verification reads exactly what was written** — no post-hoc modifications

---

## 11. Migration Notes (v0.1.x → Canonical v1.0)

### v0.1.2 Implementation Status

| Area | v0.1.2 state | Remaining for v1.0 |
|------|--------------|--------------------|
| Bundle layout | `agent/`, `secrets/` at bundle root, treated as the payload boundary | Add `payload/` wrapper (cosmetic — conceptual model identical) |
| Manifest signing | Canonical JSON (recursively sorted keys), verified with bundled public key | — |
| Integrity scope | `agent/` + `secrets/` (incl. `keys.enc`); deterministic, NUL-delimited, fail-closed | `payload/` wrapper (identical scope) |
| Launch format | Structured `launch.command` + `launch.args` (legacy string parsing still accepted on read) | — |
| Crypto format | Documented `argon2id/m=64MiB/t=3/p=4`, `crypto.format_version: 1` | KEK/DEK envelope in a future format version |
| Version fields | Separated (§4): schema, bundle, integrity, crypto, application | — |
| Verification | Strict: `pn run` refuses on any integrity/signature/structural failure | — |
| `--allow-unverified` | Bypasses trust verification only; never structural/format checks | — |

### Files to Update

### v0.1.2 state

| File | State |
|------|-------|
| `src/domain/manifest.rs` | ✅ `crypto.format_version`, `integrity.format_version`, `compatibility`, `launch.args`, `bundle_version`; strict validation incl. format versions and digest format |
| `src/application/pack_bundle.rs` | ✅ Canonical pack orchestration: stage → encrypt → checksum → manifest → canonical-JSON sign → `signing/public.key` → validate |
| `src/commands/pack.rs` | ✅ Thin wrapper delegating to the application layer |
| `src/application/run_bundle_impl.rs` | ✅ Strict verification sequence (§7); structured launch; compatibility + traversal checks |
| `src/security/integrity.rs` | ✅ Canonical NUL-delimited payload hashing; fail-closed incl. symlinks |
| `src/security/signing.rs` | ✅ Canonical JSON signing + bundled-public-key verification |
| `src/security/crypto.rs` | ✅ Documented Argon2id parameters; `CRYPTO_FORMAT_VERSION` constant |
| `src/cli.rs` | ✅ `--allow-unverified` boolean flag with documented boundaries |
| Tests | ✅ Integrity tamper matrix, signature attack matrix, schema validation matrix, CLI black-box tests |

### Compatibility Strategy

- **Read path**: Support both v0.1.x layout (no `payload/`) and v1.0 layout (with `payload/`) — the payload root is resolved per bundle
- **Write path**: Produce v0.1.x layout for now; add `payload/` in Bundle Format v2
- **Manifest**: Accept schema_version "0.1" and "0.2"; write "0.2"
- **Signing**: v0.1.2 signs and verifies canonical JSON (see §6)

---

## 12. Architecture Dependency Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI LAYER                                 │
│  src/cli.rs  ←  clap definitions, help text, argument parsing   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      COMMANDS LAYER                              │
│  src/commands/{init,pack,run,info,diff,unlock,rekey}.rs         │
│  • Parse CLI args → construct application requests              │
│  • Handle user interaction (prompts, confirmations)             │
│  • Print human-readable output                                  │
│  • NO business logic                                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                             │
│  src/application/{pack_bundle, run_bundle, run_bundle_impl}.rs  │
│  src/application/mod.rs                                         │
│  • Orchestrate use cases                                        │
│  • Coordinate domain, harness, infrastructure, security         │
│  • NO filesystem I/O directly (delegates to infrastructure)     │
│  • NO harness-specific logic (delegates to harness adapters)    │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌───────────────────────┐ ┌───────────────┐ ┌───────────────────────┐
│      DOMAIN           │ │  HARNESS      │ │    INFRASTRUCTURE     │
│  src/domain/          │ │  src/harness/ │ │  src/infrastructure/  │
│  • manifest.rs        │ │  • pi/        │ │  • filesystem.rs      │
│  • bundle.rs          │ │  • aider/     │ │  • archive.rs         │
│  • component.rs       │ │  • traits.rs  │ │  • ignore.rs          │
│  • environment.rs     │ │  • registry.rs│ │  • process.rs         │
│  • harness.rs         │ │               │ │  • bundle_store.rs    │
└───────────────────────┘ └───────────────┘ └───────────────────────┘
              │               │               │
              └───────────────┼───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY LAYER                                │
│  src/security/{crypto,secrets,signing,integrity}.rs             │
│  • Pure cryptographic primitives                                │
│  • No filesystem, no harness knowledge                          │
│  • Used by: application, harness (secrets), infrastructure      │
└─────────────────────────────────────────────────────────────────┘
```

### Dependency Rules

| Layer | May Depend On |
|-------|---------------|
| CLI | Commands (via dispatch) |
| Commands | Application, Domain (types only), Security (prompts) |
| Application | Domain, Harness (trait), Infrastructure, Security |
| Domain | **Nothing** (pure types) |
| Harness | Domain (types), Infrastructure (filesystem), Security (secrets) |
| Infrastructure | Domain (types), stdlib |
| Security | **Nothing** (pure crypto) |

**Resolved**:
- ~~`application/run_bundle_impl.rs` imports `commands::run` types~~ — `RunBundleRequest`/`RunResult` now live in the application layer.
- ~~`commands/pack.rs` calls `compute_bundle_checksum`/`sign_manifest` directly~~ — the pack sequence lives in `application/pack_bundle.rs`; commands delegate.
- ~~`harness/pi/` exposes Pi paths to application code~~ — Pi layout vocabulary is declared by `PiHarness::discover()` and consumed by Core as `PortableComponent`s; `harness/pi/` is the adapter and nothing outside `harness/` imports it.

Remaining command-layer deviations (init scaffolding, pack `--archive`, info/unlock/rekey) are tracked for v0.2 — see `docs/architecture.mmd`.

---

## 13. Test Requirements (Verification Gates)

### Integrity Tests
- [ ] Modify packed file → `pn info` / `pn run` reports checksum mismatch
- [ ] Modify `manifest.yaml` integrity.checksum → verification fails
- [ ] Remove `agent/config/file.json` → checksum fails
- [ ] Add file to `agent/` → checksum fails
- [ ] Modify `keys.enc` → checksum fails

### Signature Tests
- [ ] Valid signature → verification passes
- [ ] Modify `manifest.yaml` after signing → signature fails
- [ ] Corrupt `manifest.sig` → verification fails
- [ ] Replace `signing/public.key` → verification fails
- [ ] Missing `manifest.sig` → verification fails (default)
- [ ] Missing `signing/public.key` → verification fails (default)

### Secret Tests
- [ ] Pack secret `SUPER_SECRET` → not found in any bundle file (grep)
- [ ] `pn unlock --show` → reveals secret
- [ ] `pn unlock --env` → outputs `KEY=value`
- [ ] Wrong passphrase → decryption fails
- [ ] Rekey old→new → old fails, new succeeds, values identical

### Run Security Tests
- [ ] `pn run` without signature → FAIL
- [ ] `pn run` with invalid signature → FAIL
- [ ] `pn run --allow-unverified` → WARN + proceed
- [ ] `HOST_SECRET=xxx pn run` → `HOST_SECRET` not in child env
- [ ] `keys.enc` permissions = 0600 (Unix)

### Cross-Machine Test
- [ ] `pn init` + `pn pack` on Machine A
- [ ] Copy bundle to Machine B
- [ ] `pn info` on Machine B → signature valid
- [ ] `pn run` on Machine B → executes

---

## 14. Remaining Limitations (v0.1.1)

| Limitation | Tracking |
|------------|----------|
| Canonical JSON signing not yet implemented (signs YAML) | v0.2 |
| `payload/` wrapper directory not used | Bundle Format v2 |
| Aider harness skeleton only (no pack support) | Future |
| Windows detection not implemented | P2.3 |
| Archive encryption format not fully specified | v0.2 |
| No trust/PKI infrastructure | Out of scope |
| Reproducibility score not fully deterministic | v0.1.1 audit |
| `pn diff` compares against live harness, not bundle-to-bundle | Known |

---

*This document is the authoritative reference for the AgentPackNest bundle format. Implementation must match this specification. When in doubt, the specification wins.*