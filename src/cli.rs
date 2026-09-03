use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "pn",
    about = "Package coding agents into portable, reproducible bundles",
    long_about = "agentpacknest (pn) makes coding agents portable.\n\n\
        Take an existing coding agent (currently Pi), pack its configuration,\n\
        skills, memory, and encrypted secrets into a self-contained bundle,\n\
        then run or transfer that bundle to another machine with minimal friction.\n\n\
        This is NOT a new coding agent — it's a packaging and runtime layer\n\
        that sits on top of existing harnesses.",
    version,
    propagate_version = true,
    after_help = "EXAMPLES:\n\
        \n  Initialize a bundle from a local Pi installation (agent dir):\n    \
            pn init --harness pi --path ~/.pi/agent --name my-agent\n\
        \n  Pack config, skills, and secrets into the bundle:\n    \
            pn pack --all --path ~/.pi/agent\n\
        \n  Inspect the bundle:\n    \
            pn info .\n\
        \n  Preview what 'run' would do:\n    \
            pn run . --dry-run\n\
        \n  Run the agent:\n    \
            pn run .\n\
        \n  Run with --allow-unverified (not recommended):\n    \
            pn run . --allow-unverified\n\
        \n  Inspect encrypted secrets (masked):\n    \
            pn unlock ."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new agent bundle from a harness installation
    #[command(after_help = "EXAMPLES:\n\
        \n  Init with default name in current directory:\n    \
            pn init --path ~/.pi/agent\n\
        \n  Init with a specific name and output directory:\n    \
            pn init --harness pi --path ~/.pi/agent --name my-agent --output ./bundles/my-agent")]
    Init {
        /// Harness to use (currently only "pi")
        #[arg(long, default_value = "pi")]
        harness: String,

        /// Path to the harness installation to detect
        #[arg(short = 'p', long)]
        path: Option<String>,

        /// Name of the agent bundle (default: current directory name)
        #[arg(short = 'n', long)]
        name: Option<String>,

        /// Output directory for the bundle (default: ./<name>)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Copy files from a harness installation into the bundle
    #[command(after_help = "EXAMPLES:\n\
        \n  Pack everything (config + memory + skills + secrets):\n    \
            pn pack --all --path ~/.pi/agent\n\
        \n  Pack only config and skills:\n    \
            pn pack --with-config --with-skills --path ~/.pi/agent\n\
        \n  Pack and create a .tar.gz archive:\n    \
            pn pack --all --archive --path ~/.pi/agent\n\
        \n  Pack, archive, and encrypt the whole archive:\n    \
            pn pack --all --archive --encrypt-archive --path ~/.pi/agent\n\
        \n  Force overwrite existing files:\n    \
            pn pack --with-config --path ~/.pi/agent --force")]
    Pack {
        /// Path to the bundle directory (default: current dir)
        bundle: Option<String>,

        /// Path to the harness installation to copy from
        #[arg(short = 'p', long)]
        path: Option<String>,

        /// Include configuration files
        #[arg(long)]
        with_config: bool,

        /// Include memory / session history
        #[arg(long)]
        with_memory: bool,

        /// Include skills, extensions and themes
        #[arg(long)]
        with_skills: bool,

        /// Include secrets (will be encrypted with a passphrase)
        #[arg(long)]
        with_secrets: bool,

        /// Include everything (config + memory + skills + secrets)
        #[arg(long)]
        all: bool,

        /// Also create a .tar.gz archive of the bundle
        #[arg(long)]
        archive: bool,

        /// Encrypt the archive with AES-256-GCM (requires --archive)
        #[arg(long)]
        encrypt_archive: bool,

        /// Overwrite existing files in the bundle
        #[arg(long)]
        force: bool,
    },

    /// Decrypt an encrypted archive produced by `pn pack --archive --encrypt-archive`
    #[command(after_help = "EXAMPLES:\n\
        \n  Decrypt an encrypted archive back to .tar.gz:\n    \
            pn decrypt my-agent.tar.gz.enc\n\
        \n  Then extract it:\n    \
            tar xzf my-agent.tar.gz")]
    Decrypt {
        /// Path to the encrypted archive (.tar.gz.enc)
        file: String,
    },

    /// Launch the agent defined in the bundle
    #[command(after_help = "EXAMPLES:\n\
        \n  Run with default settings:\n    \
            pn run .\n\
        \n  Preview without executing:\n    \
            pn run . --dry-run\n\
        \n  Warn only when the bundle is older than 30 days:\n    \
            pn run . --max-age 30d\n\
        \n  Run with a custom working directory:\n    \
            pn run . --workdir /tmp/agent-workspace\n\
        \n  Pass the passphrase via flag (less secure):\n    \
            pn run . --passphrase my-secret\n\
        \n  Run without integrity/sig verification (not recommended):\n    \
            pn run . --allow-unverified")]
    Run {
        /// Path to the bundle directory (default: current dir)
        bundle: Option<String>,

        /// Passphrase for decrypting secrets (WARNING: visible in process list — prefer interactive prompt)
        #[arg(short = 'p', long, visible_alias = "pass")]
        passphrase: Option<String>,

        /// Working directory override for the agent
        #[arg(long)]
        workdir: Option<String>,

        /// Show what would be executed without running
        #[arg(long)]
        dry_run: bool,

        /// Allow running without integrity/sig verification (NOT RECOMMENDED)
        #[arg(long)]
        allow_unverified: bool,

        /// Maximum bundle age before pn run warns — 7d, 24h, 2w, or a bare number of days (default: 7d; AGENTPACKNEST_MAX_AGE also works)
        #[arg(long, value_name = "DURATION")]
        max_age: Option<String>,

        /// Extra arguments passed to the agent command
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Compare a bundle with the local harness state
    #[command(after_help = "EXAMPLES:\n\
        \n  Compare current bundle with local Pi:\n    \
            pn diff .\n\
        \n  Compare with a specific harness path:\n    \
            pn diff . --path ~/.pi/agent")]
    Diff {
        /// Path to the bundle directory (default: current dir)
        bundle: Option<String>,

        /// Path to the local harness installation
        #[arg(short = 'p', long)]
        path: Option<String>,
    },

    /// Display bundle metadata and contents
    #[command(after_help = "EXAMPLES:\n\
        \n  Show info for current directory:\n    \
            pn info .\n\
        \n  Show info for a specific bundle:\n    \
            pn info ./bundles/my-agent")]
    Info {
        /// Path to the bundle directory (default: current dir)
        #[arg(default_value = ".")]
        bundle: String,
    },

    /// Decrypt and inspect secrets stored in the bundle
    #[command(after_help = "EXAMPLES:\n\
        \n  Show secrets with masked values:\n    \
            pn unlock .\n\
        \n  Show full secret values:\n    \
            pn unlock . --show\n\
        \n  Output as KEY=value for sourcing:\n    \
            pn unlock . --env")]
    Unlock {
        /// Path to the bundle directory (default: current dir)
        bundle: Option<String>,

        /// Show secret values in full (default: masked)
        #[arg(long)]
        show: bool,

        /// Output as KEY=value lines (for sourcing into shell)
        #[arg(long)]
        env: bool,
    },

    /// Change the passphrase for encrypted secrets without re-packing
    #[command(after_help = "EXAMPLES:\n\
        \n  Rotate passphrase for current bundle:\n    \
            pn rekey .\n\
        \n  Rotate passphrase for a specific bundle:\n    \
            pn rekey ./bundles/my-agent")]
    Rekey {
        /// Path to the bundle directory (default: current dir)
        bundle: Option<String>,
    },
}

pub fn parse() -> Cli {
    Cli::parse()
}
