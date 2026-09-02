# agentpack

**Package coding agents into portable, reproducible bundles.**

`agentpack` (`agp`) is a CLI tool that takes an existing coding agent (currently [Pi](https://pi.dev)), packs its configuration, skills, memory, and encrypted secrets into a self-contained bundle, then lets you run or transfer that bundle to another machine with minimal friction.

> **This is NOT a new coding agent.** It's a packaging and runtime layer that sits on top of existing harnesses.

## Install

```bash
cargo install --path .
```

Requires Rust ≥ 1.75. Manage with [mise](https://mise.jdx.dev) or [rustup](https://rustup.rs).

## Quick start

```bash
# 1. Initialize a bundle from your local Pi installation
agp init --path ~/.pi --name my-agent

# 2. Pack everything into the bundle
agp pack --all --path ~/.pi

# 3. Inspect what was packed
agp info .

# 4. Run the agent
agp run .
```

## Commands

| Command | Purpose |
|---------|---------|
| `agp init` | Create a new bundle from a harness installation |
| `agp pack` | Copy config, skills, memory, and secrets into the bundle |
| `agp run` | Launch the agent defined in the bundle |
| `agp info` | Display bundle metadata and contents |
| `agp unlock` | Decrypt and inspect secrets (never written to disk) |

### `agp init`

Creates the bundle skeleton — directory structure + `manifest.yaml`.

```bash
agp init --harness pi --path ~/.pi --name my-agent --output ./bundles/my-agent
```

**Flags:**
- `--harness <name>` — Harness to use (default: `pi`, only option for now)
- `-p, --path <path>` — Path to the harness installation
- `-n, --name <name>` — Bundle name
- `-o, --output <dir>` — Output directory

### `agp pack`

Copies files from the harness installation into the bundle and updates the manifest.

```bash
# Pack everything
agp pack --all --path ~/.pi

# Pack specific components
agp pack --with-config --with-skills --path ~/.pi

# Pack and create an archive
agp pack --all --archive --path ~/.pi
```

**Flags:**
- `--with-config` — Include configuration files
- `--with-memory` — Include session history
- `--with-skills` — Include extensions, skills, and themes
- `--with-secrets` — Encrypt and include secrets (prompts for passphrase)
- `--all` — Include everything above
- `--archive` — Create a `.tar.gz` alongside the bundle
- `--force` — Overwrite existing files

### `agp run`

Launches the agent. Decrypts secrets in memory only, sets up environment variables, and executes the command from `manifest.yaml`.

```bash
# Run normally
agp run .

# Preview without executing
agp run . --dry-run

# Custom working directory
agp run . --workdir /tmp/agent-workspace
```

**Security:** Secrets are never written to disk. The environment is cleared before execution — only essential system vars (`PATH`, `HOME`, etc.) and agent-specific vars are injected.

### `agp info`

Displays bundle metadata in a readable format.

```bash
agp info .
```

### `agp unlock`

Decrypts secrets and displays them. Values are masked by default.

```bash
# Masked (default)
agp unlock .

# Full values
agp unlock . --show

# KEY=value format (for sourcing)
agp unlock . --env
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
- **Environment isolation** — `agp run` clears the inherited environment and injects only what's needed
- **Integrity verification** — SHA-256 checksum of the bundle is stored in the manifest

## Example flow

```bash
# Create a bundle from a Pi installation
agp init --path ~/.pi --name coding-agent

# Pack configuration and skills
agp pack --with-config --with-skills --path ~/.pi

# Pack secrets (interactive passphrase prompt)
agp pack --with-secrets --path ~/.pi

# Verify the bundle
agp info .

# Preview execution
agp run . --dry-run

# Run it
agp run .

# Transfer to another machine
tar czf coding-agent.tar.gz coding-agent/
scp coding-agent.tar.gz remote:~/

# On the remote machine
tar xzf coding-agent.tar.gz
agp run coding-agent/
```

## Requirements

- **Node.js ≥ 20** (required by Pi harness — checked automatically at `agp run`)
- A Pi installation (detected from `~/.pi` or `PI_HOME` env var)

## Limitations

- **Only the `pi` harness is supported** in v0.1. Other harnesses (Aider, etc.) will be added later.
- **No Windows Pi detection yet** — `~/.pi` is a Unix convention.
- **Archive is uncompressed tar.gz** — no encryption of the archive itself.
- **Secrets passphrase cannot be changed** after packing (re-pack with new passphrase).
- **No bundle signing** — integrity is checksum-based, not cryptographic signatures.

## License

MIT
