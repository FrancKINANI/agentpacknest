# Security Model

This document describes what agentpacknest protects against, what it does not,
and the exact semantics of the integrity, signature, and trust layers.

## The Security Chain

agentpacknest bundles are protected by two independent layers:

```text
PAYLOAD (agent/ + secrets/keys.enc)
   │
   │ SHA-256 (deterministic, canonical paths, NUL-delimited)
   ▼
PAYLOAD DIGEST ──stored in──▶ MANIFEST (manifest.yaml)
                                     │
                                     │ Ed25519 over canonical manifest JSON
                                     ▼
                                 SIGNATURE (manifest.sig)
```

- **The payload digest** covers every file in the payload — including
  `secrets/keys.enc` — so any modification to the packed environment is
  detected. It never covers `manifest.yaml`, `manifest.sig`, or
  `signing/public.key` (metadata/signature layers — circular otherwise).
- **The signature** covers the canonical JSON representation of the manifest
  (deterministic, sorted keys), which contains the payload digest.

## Integrity vs. Signature vs. Trust

These three questions are different, and agentpacknest answers only the first two:

| Question | Answered by | Layer |
|---|---|---|
| **Integrity** — "Has the payload changed since packing?" | Comparing the recomputed payload digest to `manifest.integrity.checksum` | Payload digest (SHA-256) |
| **Signature validity** — "Was this manifest signed by the holder of the private key matching this public key?" | Ed25519 verification of the canonical manifest against the **bundled** public key | Signature |
| **Trust** — "Do I trust the person who owns that key?" | **Not answered.** No PKI, certificates, key registry, or trust network exists in v0.1.2 | Out of scope |

A valid signature proves that the signer controlled the private key
corresponding to the bundled public key at signing time. It does NOT prove the
signer's real-world identity or "authorship" in a legal/editorial sense, and it
does NOT prove the bundle is safe to run or that the signer is trustworthy.
Cryptographic signer identity ≠ human identity. Decide whose public keys you
accept before running a bundle.

## Public-Key Portability

- The **private signing key** never enters the bundle. It stays in
  `~/.config/agentpacknest/keypair` on the signer's machine.
- The **public key** travels with the bundle at `signing/public.key`.
- Verification (in `pn run` and `pn info`) uses **only the bundled public
  key** — the verifier's machine never needs the signer's private key or
  keypair file.

## Protected Against

| Threat | Protection |
|---|---|
| **Bundle theft without passphrase** | Secrets encrypted with AES-256-GCM + Argon2id (m=64MiB, t=3, p=4, salt=16B). Without the passphrase, secrets are unreadable. |
| **Accidental secret exposure on disk** | `keys.enc` created with 0600 permissions (owner-only). Keypair stored with 0600 permissions. Plaintext secrets are never written to disk or to manifest.yaml. |
| **Secret-source files leaking as plaintext during pack** | Each harness declares its secret sources (`auth.json`, `.env`-style files, `secrets/` dirs) as `SecretSource` components; Core never copies secret-source files as plaintext (a filename-level policy backs this up) and writes only the encrypted `secrets/keys.enc`. |
| **Unauthorized bundle modification** | `pn run` refuses to execute unless payload integrity **and** the manifest signature verify. |
| **Payload tampering (config, skills, extensions, themes, memory, keys.enc)** | Every payload file is covered by the deterministic SHA-256 payload digest stored in the manifest. Add/modify/delete any payload file → digest mismatch → run refuses. |
| **Signature forgery / key swap** | Manifest signed with Ed25519 over the canonical manifest JSON. Modified manifest, corrupted signature, missing signature, replaced public key → verification fails → run refuses. |
| **Structure / format confusion attacks** | Schema version, bundle format version, integrity format version, and crypto format version are validated explicitly. Unsupported or unknown formats are refused — never silently reinterpreted. `--allow-unverified` cannot bypass these structural checks. |
| **Path traversal out of the bundle** | Symlinks are rejected when packing and when hashing. A manifest `launch.working_directory` must resolve inside the bundle. |
| **Secrets lingering in memory** | Derived keys and plaintext secret JSON are zeroized after use. |
| **Environment pollution during run** | The agent process runs with `env_clear()`: only a whitelist of system vars, `AGENTPACKNEST_*` vars, and intentionally injected secrets are present. |
| **Secret key-name injection** | Secret keys are validated against `[A-Za-z_][A-Za-z0-9_]*` before becoming environment variables. |
| **Passphrase in process list** | `--passphrase` is documented as insecure; the interactive (masked) prompt is the default. |
| **Stale bundle execution** | `pn run` warns when a bundle was packed more than 7 days ago; `pn diff` shows drift. |

## The `pn run` Security Policy (default)

`pn run <bundle>` refuses to launch unless ALL of the following hold:

1. Bundle structure is valid (directory, `manifest.yaml` present).
2. The manifest parses and passes schema validation (schema, bundle format,
   integrity format, crypto format, digest format, harness, UUID, timestamps).
3. The payload digest matches `manifest.integrity.checksum`.
4. The manifest signature verifies against the bundled `signing/public.key`.
5. The bundle's `compatibility.min_agentpacknest_version` is satisfied.
6. Runtime requirements are satisfiable on this machine.

Secrets are decrypted only after all verification passes, and only in memory.

### `--allow-unverified` boundaries

`pn run --allow-unverified <bundle>` is a real boolean flag (never a
positional argument). It bypasses **only trust verification** — the checks
whose failure means "this bundle's authenticity cannot be established":

- payload checksum mismatch (with a strong warning)
- missing signature
- invalid signature, including a signature whose bytes cannot even be parsed
  as an Ed25519 signature (malformed/unreadable signature material)
- missing `signing/public.key`, or a public key whose bytes cannot be parsed
  (malformed/unreadable key material)
- a bundled public key that does not match the signature

In every bypass case a strong warning is printed, and the override never
makes a **structurally invalid** bundle runnable: the manifest must still
parse and validate, formats must still be supported, and paths must still
stay inside the bundle — those checks run regardless of the flag.

It does **NOT** bypass structural validity or format compatibility:

- invalid YAML / unparseable manifest
- missing manifest
- schema validation failures
- unsupported schema / bundle format / integrity format / crypto format
- path traversal (e.g. a `launch.working_directory` escaping the bundle)
- impossible runtime specifications

The rule: *"--allow-unverified" bypasses trust verification, not structural
validity or format compatibility.*

## Not Protected Against

| Threat | Why |
|---|---|
| **Compromised host machine** | If the host is owned, all bets are off. Secrets in memory can be extracted. |
| **Malicious process with user privileges** | A process running as the user can read `keys.enc` (if it has the passphrase) or attach to the process memory. |
| **Malicious agent intentionally exfiltrating secrets** | Once secrets are injected as env vars, a compromised agent can send them anywhere. This is a fundamental limitation of env-based secret injection. |
| **Compromised dependency / runtime** | If Node.js (Pi) or another runtime is compromised, the agent process is compromised. |
| **Brute-force on keys.enc** | Argon2id makes this harder but not impossible. Use strong passphrases. |
| **Core dump / swap leakage** | If the OS writes process memory to disk (core dump, swap), zeroized buffers may still contain traces. Consider disabling core dumps for sensitive operations. |
| **Untrusted signers** | A bundle signed by an attacker's key verifies as valid. Signatures prove control of the matching private key, not identity or safety. Decide which keys you trust before running. |
| **Timing attacks on signature verification** | Ed25519 is constant-time by design, but the `verify()` wrapper does not guarantee constant-time comparison of the result. |

## Cryptographic Decisions

| Component | Choice | Rationale |
|---|---|---|
| Symmetric encryption | AES-256-GCM (12B nonce) | Authenticated encryption, widely analyzed, hardware-accelerated |
| Key derivation | Argon2id, m=64MiB, t=3, p=4, salt=16B | Memory-hard, OWASP-recommended baseline; parameters are versioned (`crypto.format_version: 1`) and MUST NOT change without a format bump |
| Digital signatures | Ed25519 over canonical manifest JSON | Fast, small keys, deterministic verification |
| Canonical signing input | Manifest serialized to JSON with recursively sorted keys | Deterministic across machines and library versions (YAML serialization is not stable) |
| Payload integrity | SHA-256 over `canonical_relative_path ‖ NUL ‖ contents`, files sorted by path | Deterministic, cross-platform, unambiguous path/content boundaries |
| Secret rotation (`pn rekey`) | Decrypt with old passphrase → re-encrypt with new passphrase, atomic temp-file + rename | Wrong old passphrase or a crash mid-write never destroys the only decryptable copy |
| Hash | SHA-256 | Bundle payload integrity checksum |

## Cryptographic Format Versions (never conflated)

| Concept | Where stored | Current |
|---|---|---|
| AgentPackNest application version | `agentpacknest_version` | 0.2.0 |
| Bundle format version | `bundle_version` | 1 |
| Manifest schema version | `schema_version` | "0.2" (accepts "0.1") |
| Integrity format version | `integrity.format_version` | 1 |
| Crypto format version | `crypto.format_version` | 1 |

Any value outside the supported set is refused explicitly.

## Recommendations for Users

1. **Use strong passphrases** — 12+ words, randomly generated
2. **Don't use `--passphrase` in scripts** — use the interactive prompt
3. **Don't store bundles with secrets on shared drives** without encryption
4. **Run `pn rekey` periodically** to rotate passphrases
5. **Never run `--allow-unverified`** on bundles you do not fully control
6. **Decide which signers you trust** — signatures prove private-key control, not identity or safety
7. **Check `pn info`** to inspect a bundle's integrity/signature status

## Reporting Security Issues

If you discover a security vulnerability, please report it privately via
GitHub Security Advisories rather than opening a public issue.
