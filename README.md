# agentpacknest

**Portable, reproducible environments for AI coding agents.**

`agentpacknest` (`pn`) captures an existing coding agent's configuration, skills, memory, and encrypted secrets into a self-contained bundle — then reproduces that environment on another machine with minimal friction.

> **This is NOT a new coding agent.** It's a packaging and runtime layer that sits on top of existing harnesses (Pi, Aider, and more to come).

## Why?

Every developer using AI coding agents accumulates a unique environment:

- Agent runtime (Pi, Aider, Claude Code, Codex…)
- Configuration and settings
- Skills, extensions, and themes
- Session memory and history
- API keys and secrets
- MCP server configs

Moving this environment to another machine — or sharing it with a teammate — is currently a manual, error-prone process.

**agentpacknest solves this** by treating the entire agent environment as a portable, versioned, signed bundle.

## Install

```bash
cargo install --path .
```

Requires Rust ≥ 1.75. Manage with [mise](https://mise.jdx.dev) or [rustup](https://rustup.rs).

## Quick start

```bash
# 1. Capture your Pi environment
pn init --harness pi --path ~/.pi --name my-agent

# 2. Pack config, skills, and secrets
pn pack --all --path ~/.pi

# 3. Inspect the bundle
pn info .

# 4. Run on another machine
pn run .
```

## Commands

| Command | What it does |
|---|---|
| `pn init` | Create a new bundle from a harness installation |
| `pn pack` | Copy config, memory, skills, secrets into the bundle |
| `pn run` | Launch the agent defined in the bundle |
| `pn info` | Display bundle metadata and reproducibility score |
| `pn diff` | Compare bundle with local harness state |
| `pn unlock` | Decrypt and inspect secrets (masked by default) |
| `pn rekey` | Rotate passphrase without re-packing |

### Examples

```bash
# Init with Aider harness
pn init --harness aider --name research-agent

# Pack everything and create encrypted archive
pn pack --all --archive --encrypt-archive --path ~/.pi

# Check bundle freshness
pn diff . --path ~/.pi/agent

# Rotate passphrase
pn rekey .
```

## Bundle structure

```
my-agent/
├── manifest.yaml          # Metadata, integrity, platform info
├── manifest.sig           # Ed25519 signature (tamper-evident)
├── agent/
│   ├── config/            # Agent configuration files
│   ├── memory/            # Session history and state
│   └── packages/
│       ├── extensions/    # Installed extensions
│       ├── skills/        # Agent skills
│       └── themes/        # UI themes
├── secrets/
│   └── keys.enc           # Encrypted secrets (AES-256-GCM)
└── launch                 # Launch script (placeholder)
```

## Security

agentpacknest takes security seriously. See [SECURITY.md](SECURITY.md) for the full threat model.

**Highlights:**
- Secrets encrypted with AES-256-GCM + Argon2 key derivation
- Ed25519 bundle signing (tamper-evident)
- KEK/DEK envelope for passphrase rotation without re-packing
- `env_clear()` prevents leaking host environment to agents
- Zeroization of sensitive buffers after use
- Restrictive file permissions (0600) on secrets

## Reproducibility

`pn info` includes a **reproducibility score** (0-100%) based on:

- Components packed (config, skills, memory, secrets)
- Integrity verification (checksum, signature)
- Platform metadata
- Runtime requirements
- Provenance tracking

```
  Reproducibility
  ────────────────────────────────────────────
  Score        85%
  ⚠ no memory packed — session history lost
  ⚠ unsigned bundle — authenticity unverified
```

## Supported harnesses

| Harness | Status | Notes |
|---|---|---|
| [Pi](https://pi.dev) | ✅ Full support | Detection, config, skills, memory, secrets |
| [Aider](https://aider.chat) | 🔨 Skeleton | Detection planned, pack not yet implemented |
| Claude Code | 📋 Planned | — |
| Codex | 📋 Planned | — |

## Roadmap

- **v0.1** — Pi harness rock-solid (current)
- **v0.2** — Harness trait abstraction
- **v0.3** — Second harness (Aider or Claude Code)
- **v0.4** — MCP config + dependency management
- **v0.5** — Trust chain + publish/pull

## Contributing

1. Fork the repo
2. Create a feature branch from `main`
3. Work on `staging`, merge to `main` after CI passes
4. All changes must pass: `cargo clippy -D warnings`, `cargo fmt --check`, `cargo test`

## License

MIT
