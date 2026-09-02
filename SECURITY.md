# Security Model

This document describes what agentpacknest protects against and what it does not.

## Threat Model

### Protected Against

| Threat | Protection |
|---|---|
| **Bundle theft without passphrase** | Secrets encrypted with AES-256-GCM + Argon2 key derivation. Without the passphrase, secrets are unreadable. |
| **Accidental secret exposure on disk** | `keys.enc` created with 0600 permissions (owner-only). Keypair stored with 0600 permissions. |
| **Unauthorized bundle modification** | Ed25519 signature on manifest. Tampering is detectable (though not blocking by default). |
| **Secrets lingering in memory** | All sensitive buffers (derived keys, plaintext JSON, passphrases) are zeroized after use. |
| **Environment pollution during run** | `env_clear()` wipes all inherited env vars. Only whitelisted system vars + agent vars are injected. |
| **Symlink traversal during pack** | `follow_links(false)` on all WalkDir instances. Symlinks are rejected with an error. |
| **Malicious secret key names** | Env var keys validated against `[A-Za-z_][A-Za-z0-9_]*`. Invalid keys silently skipped. |
| **Passphrase in process list** | `--passphrase` flag is documented as insecure. Interactive prompt is the default. |
| **Stale bundle execution** | `pn run` warns if bundle was packed >7 days ago. `pn diff` shows drift. |

### Not Protected Against

| Threat | Why |
|---|---|
| **Compromised host machine** | If the host is owned, all bets are off. Secrets in memory can be extracted. |
| **Malicious process with user privileges** | A process running as the user can read `keys.enc` (if it has the passphrase) or attach to the process memory. |
| **Malicious agent intentionally exfiltrating secrets** | Once secrets are injected as env vars, a compromised agent can send them anywhere. This is a fundamental limitation of env-based secret injection. |
| **Compromised dependency / runtime** | If Node.js (Pi) or Python (Aider) is compromised, the agent process is compromised. |
| **Brute-force on keys.enc** | Argon2 makes this harder but not impossible. Use strong passphrases. |
| **Core dump / swap leakage** | If the OS writes process memory to disk (core dump, swap), zeroized buffers may still contain traces. Consider disabling core dumps for sensitive operations. |
| **Timing attacks on signature verification** | Ed25519 is constant-time by design, but the `verify()` wrapper does not guarantee constant-time comparison of the result. |

## Cryptographic Decisions

| Component | Choice | Rationale |
|---|---|---|
| Symmetric encryption | AES-256-GCM | Authenticated encryption, widely analyzed, hardware-accelerated |
| Key derivation | Argon2 (default params) | Memory-hard, OWASP-recommended minimum |
| Digital signatures | Ed25519 | Fast, small keys, no ceremony needed |
| Secret wrapping | KEK/DEK envelope | Enables passphrase rotation without re-encrypting data |
| Hash | SHA-256 | Bundle integrity checksum |

## Recommendations for Users

1. **Use strong passphrases** — 12+ words, randomly generated
2. **Don't use `--passphrase` in scripts** — use the interactive prompt
3. **Don't store bundles with secrets on shared drives** without encryption
4. **Run `pn rekey` periodically** to rotate passphrases
5. **Verify bundles before running** — check `pn info` for signature and checksum
6. **Don't trust bundles from unverified sources** — signatures prove authorship, not safety

## Reporting Security Issues

If you discover a security vulnerability, please report it privately via
GitHub Security Advisories rather than opening a public issue.
