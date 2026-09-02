# agentpacknest

**Package coding agents into portable, reproducible bundles.**

`agentpacknest` (`pn`) is a CLI tool that takes an existing coding agent (currently [Pi](https://pi.dev)), packs its configuration, skills, memory, and encrypted secrets into a self-contained bundle, then lets you run or transfer that bundle to another machine with minimal friction.

> **This is NOT a new coding agent.** It's a packaging and runtime layer that sits on top of existing harnesses.

## Install

```bash
cargo install --path .
```

Requires Rust ≥ 1.75. Manage with [mise](https://mise.jdx.dev) or [rustup](https://rustup.rs).

## Quick start

```bash
# 1. Initialize a bundle from your local Pi installation
pn init --path ~/.pi --name my-agent

# 2. Pack everything into the bundle
pn pack --all --path ~/.pi

# 3. Inspect what was packed
pn info .

# 4. Run the agent
pn run .
```

## Commands

| Command | Purpose |
|---------|---------|
| `pn init` | Create a new bundle from a harness installation |
| `pn pack` | Copy config, skills, memory, and secrets into the bundle |
| `pn run` | Launch the agent defined in the bundle |
| `pn diff` | Compare a bundle with the local harness state |
| `pn info` | Display bundle metadata and contents |
| `pn unlock` | Decrypt and inspect secrets (never written to disk) |

### `pn init`

Creates the bundle skeleton — directory structure + `manifest.yaml`.

```bash
pn init --harness pi --path ~/.pi --name my-agent --output ./bundles/my-agent
```

**Flags:**
- `--harness <name>` — Harness to use (default: `pi`, only option for now)
- `-p, --path <path>` — Path to the harness installation
- `-n, --name <name>` — Bundle name
- `-o, --output <dir>` — Output directory

### `pn pack`

Copies files from the harness installation into the bundle and updates the manifest.

```bash
# Pack everything
pn pack --all --path ~/.pi

# Pack specific components
pn pack --with-config --with-skills --path ~/.pi

# Pack and create an archive
pn pack --all --archive --path ~/.pi
```

**Flags:**
- `--with-config` — Include configuration files
- `--with-memory` — Include session history
- `--with-skills` — Include extensions, skills, and themes
- `--with-secrets` — Encrypt and include secrets (prompts for passphrase)
- `--all` — Include everything above
- `--archive` — Create a `.tar.gz` alongside the bundle
- `--force` — Overwrite existing files

### `pn run`

Launches the agent. Decrypts secrets in memory only, sets up environment variables, and executes the command from `manifest.yaml`.

```bash
# Run normally
pn run .

# Preview without executing
pn run . --dry-run

# Custom working directory
pn run . --workdir /tmp/agent-workspace
```

**Security:** Secrets are never written to disk. The environment is cleared before execution — only essential system vars (`PATH`, `HOME`, etc.) and agent-specific vars are injected.

### `pn diff`

Compares the bundle's contents with the current state of the local harness. Shows files that are modified, added, or removed since the bundle was packed.

```bash
# Compare with auto-detected Pi installation
pn diff .

# Compare with specific path
pn diff . --path ~/.pi/agent
```

### `pn info`

Displays bundle metadata in a readable format.

```bash
pn info .
```

### `pn unlock`

Decrypts secrets and displays them. Values are masked by default.

```bash
# Masked (default)
pn unlock .

# Full values
pn unlock . --show

# KEY=value format (for sourcing)
pn unlock . --env
```

## Bundle structure

```
my-agent/
├── manifest.yaml          # Bundle metadata, checksums, config
├── launch                 # Entry point script
├── agent/
│   ├── config/            # Harness configuration
│   ├── memory/            # Session history (optional)
│   ├── packages/
│   │   ├── extensions/    # Installed extensions
│   │   ├── skills/        # Agent skills
│   │   └── themes/        # UI themes
│   └── workspace/         # Agent workspace
└── secrets/
    └── keys.enc           # AES-256-GCM encrypted secrets
```

## Security model

- **Secrets are always encrypted** at rest with AES-256-GCM (Argon2 key derivation)
- **No plaintext on disk** — secrets exist only in memory during `run` and `unlock`
- **Environment isolation** — `pn run` clears the inherited environment and injects only what's needed
- **Integrity verification** — SHA-256 checksum of the bundle is stored in the manifest
- **Snapshot provenance** — each pack records `origin_machine`, `packed_at`, and `source_state_hash` in the manifest
- **Stale bundle warning** — `pn run` warns if the bundle was packed more than 7 days ago
- **File permissions** — `keys.enc` is created with `0600` (owner-only) on Unix

## Example flow

```bash
# Create a bundle from a Pi installation
pn init --path ~/.pi --name coding-agent

# Pack configuration and skills
pn pack --with-config --with-skills --path ~/.pi

# Pack secrets (interactive passphrase prompt)
pn pack --with-secrets --path ~/.pi

# Verify the bundle
pn info .

# Preview execution
pn run . --dry-run

# Run it
pn run .

# Transfer to another machine
tar czf coding-agent.tar.gz coding-agent/
scp coding-agent.tar.gz remote:~/

# On the remote machine
tar xzf coding-agent.tar.gz
pn run coding-agent/
```

## Requirements

- **Node.js ≥ 20** (required by Pi harness — checked automatically at `pn run`)
- A Pi installation (detected from `~/.pi` or `PI_HOME` env var)

## Limitations

- **Only the `pi` harness is supported** in v0.1. Aider support is scaffolded but not yet functional.
- **No Windows Pi detection yet** — `~/.pi` is a Unix convention.
- **Archive is uncompressed tar.gz** — no encryption of the archive itself.
- **Secrets passphrase cannot be changed** after packing (re-pack with new passphrase).
- **No bundle signing** — integrity is checksum-based, not cryptographic signatures.
- **Snapshots, not sync** — agentpacknest creates explicit point-in-time snapshots. It does not automatically synchronize between machines. Use `pn diff` before re-packing to avoid overwriting newer state.

## License

MIT
