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
pn init --harness pi --path ~/.pi/agent --name my-agent

# 2. Pack config, skills, and secrets
pn pack --all --path ~/.pi/agent

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
| `pn run` | Launch the agent defined in the bundle (warns when the bundle is stale) |
| `pn info` | Display bundle metadata and reproducibility score |
| `pn diff` | Compare bundle with local harness state |
| `pn unlock` | Decrypt and inspect secrets (masked by default) |
| `pn decrypt` | Decrypt a `.tar.gz.enc` archive back to `.tar.gz` |
| `pn rekey` | Rotate passphrase without re-packing |

### Examples

```bash
# Init to a named output directory
pn init --harness pi --path ~/.pi/agent --name my-agent --output ./bundles/my-agent

# Pack everything and create a .tar.gz archive
pn pack --all --archive --path ~/.pi/agent

# Pack, archive, and ENCRYPT the whole archive (opt-in, prompts for a passphrase)
pn pack --all --archive --encrypt-archive --path ~/.pi/agent

# Decrypt the archive on the receiving machine, then extract it
pn decrypt my-agent.tar.gz.enc

# Check bundle freshness vs. the local harness
pn diff . --path ~/.pi/agent

# Rotate the secrets passphrase
pn rekey .

# Only warn when the bundle is older than 30 days
pn run . --max-age 30d
```

### Bundle freshness

`pn run` prints a warning (never blocks) when the bundle was packed longer
ago than the freshness threshold — **7 days by default**. Control the
threshold per run with `--max-age`, or globally with the
`AGENTPACKNEST_MAX_AGE` environment variable:

```bash
pn run . --max-age 30d                    # warn only after 30 days
AGENTPACKNEST_MAX_AGE=24h pn run .         # warn after 24 hours
```

Durations accept `7d` (days), `24h` (hours), `2w` (weeks), or a bare number
of days (`30`). The `--max-age` flag wins over the environment variable;
with neither set, 7 days is used. The warning is advisory — it never stops
execution — and `pn diff` shows what changed in the local harness.

## Bundle structure

```
my-agent/
├── manifest.yaml          # Metadata + payload integrity digest
├── manifest.sig           # Ed25519 signature over canonical manifest JSON
├── signing/
│   └── public.key         # Public verification key (travels with the bundle)
├── agent/                 # PAYLOAD — everything the digest covers
│   ├── config/            # Agent configuration files
│   ├── memory/            # Session history and state
│   └── packages/
│       ├── extensions/    # Installed extensions
│       ├── skills/        # Agent skills
│       └── themes/        # UI themes
├── secrets/
│   └── keys.enc           # Encrypted secrets (AES-256-GCM + Argon2id)
```

The **payload** (`agent/` + `secrets/keys.enc`) is hashed with a deterministic
SHA-256 digest stored in `manifest.yaml`; the manifest is signed with Ed25519
over a canonical JSON representation. Verification is **portable**: `pn run`
and `pn info` verify against the public key bundled in `signing/public.key` —
no local keypair is needed to verify a bundle.

How the agent starts is defined **in the manifest** (`launch.command` +
`launch.args` + `launch.working_directory`) — there is no launch script in the
bundle. `pn run` refuses to launch unless the payload digest and the manifest
signature verify.

## Excluding files from a bundle

Drop a `.agentpacknestignore` file in the **harness source directory** you
pack from (the `--path` given to `pn pack`, e.g.
`~/.pi/agent/.agentpacknestignore`) to keep bulky caches, logs, or other
non-portable files out of the bundle:

```gitignore
# .agentpacknestignore — .gitignore-style, one pattern per line
node_modules    # any file or directory named `node_modules`, at any depth
cache
*.log           # any file whose name ends in .log
/tmp            # leading / anchors the match to the top of a packed component
# comments and blank lines are ignored
```

Matching rules (a simplified `.gitignore`):

- A bare name (`cache`) matches any **file or directory segment** with that
  name at any depth.
- `*.ext` matches any file whose name ends in `.ext`.
- A leading `/` anchors the pattern to the top of a component's source
  directory.
- Patterns are matched against each file's path **within the component being
  packed** — files that land in `agent/memory/` are matched by their name
  there (e.g. `*.jsonl` skips old session dumps; a `sessions` pattern never
  matches because only *contents* of the source sessions dir are copied).

`pn pack` prints `Ignore: N pattern(s) from .agentpacknestignore` when the
file is present. Secret-source files (`auth.json`, `.env`, …) can never be
re-included by an ignore file — Core refuses to copy them as plaintext.

## Security

agentpacknest takes security seriously. See [SECURITY.md](SECURITY.md) for the full threat model.

**Highlights:**
- Secrets encrypted with AES-256-GCM + Argon2id (documented, versioned parameters)
- Optional **whole-archive encryption**: `pn pack --archive --encrypt-archive` wraps the entire `.tar.gz` (session memory included) in the *same* versioned AES-256-GCM + Argon2id envelope as bundle secrets — no second scheme; decrypt with `pn decrypt <file.enc>`. **Opt-in by default**: plain `.tar.gz` archives stay the default because encryption needs an interactive passphrase (breaking scripted `--archive` runs) and adds passphrase management — secrets are encrypted inside the archive either way
- Deterministic SHA-256 payload digest covering every payload file, including `secrets/keys.enc`
- Ed25519 signing over canonical manifest JSON; verification uses the bundled public key (portable)
- **`pn run` refuses to launch** unless payload integrity and the manifest signature verify
- `pn run --allow-unverified` bypasses trust checks only — never structural/format validation
- `env_clear()` prevents leaking host environment to agents
- Zeroization of sensitive buffers after use
- Restrictive file permissions (0600) on secrets
- Passphrase rotation (`pn rekey`) is atomic — a failure never destroys the existing secrets

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
| [Pi](https://pi.dev) | ✅ Full support | Detection, config, skills, memory, secrets (`auth.json`, `.env`, `secrets/`) |
| [Aider](https://aider.chat) | 🔨 Skeleton | Binary/config detection scaffolded; `init`/`pack`/`run` not yet wired up |
| Claude Code | 📋 Planned | — |
| Codex | 📋 Planned | — |

AgentPackNest drives every harness through one contract (`src/harness/traits.rs`):
`detect` (is it installed, where, what version) → `discover` (which resources
form its portable environment) → `prepare_runtime` (runtime prerequisites +
final launch spec). **Pi is the reference implementation** — it is fully wired
through `pn init`/`pn pack`/`pn run`/`pn diff` on this abstraction, and all Pi
layout knowledge (config/memory/packages/secret sources, Node ≥ 20) is declared
by the Pi harness, never hardcoded in the application layer. The Core copies
and encrypts only what harnesses describe, and validates every declared
destination so nothing can be written outside the bundle.

Aider exists as a detection-only skeleton implementing the same contract
(`discover`/`prepare_runtime` return clean "not implemented" errors). It is
**not** wired through `init`/`pack`/`run` — that remains future work.

## Roadmap

- **v0.1** — Pi harness rock-solid (released)
- **v0.1.2** — Format, integrity & trust foundation (released): canonical bundle format, deterministic payload integrity, portable signature verification, strict `pn run` enforcement, schema failure matrix
- **v0.2** — Harness architecture (current): Pi fully migrated behind the single `Harness` contract; Core owns generic bundle/security behavior, harnesses describe their environments
- **Next** — Wire a second harness (Aider) end-to-end through `init`/`pack`/`run` on the existing contract
- **v0.3** — MCP config + dependency management
- **v0.4** — Trust chain + publish/pull

The v0.1.x bundle format, integrity model, and security boundaries are **frozen**
as of v0.1.2 — v0.2 changed nothing about them.

## Contributing

1. Fork the repo
2. Create a feature branch from `main`
3. Work on `staging`, merge to `main` after CI passes
4. All changes must pass: `cargo clippy -D warnings`, `cargo fmt --check`, `cargo test`

## License

MIT
