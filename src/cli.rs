use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "hh",
    about = "Package coding agents into portable, reproducible bundles",
    long_about = "hitchhike (hh) makes coding agents portable.\n\n\
        Take an existing coding agent (currently Pi), pack its configuration,\n\
        skills, memory, and encrypted secrets into a self-contained bundle,\n\
        then run or transfer that bundle to another machine with minimal friction.\n\n\
        This is NOT a new coding agent — it's a packaging and runtime layer\n\
        that sits on top of existing harnesses.",
    version,
    propagate_version = true,
    after_help = "EXAMPLES:\n\
        \n  Initialize a bundle from a local Pi installation:\n    \
            hh init --harness pi --path ~/.pi --name my-agent\n\
        \n  Pack config, skills, and secrets into the bundle:\n    \
            hh pack --all --path ~/.pi\n\
        \n  Inspect the bundle:\n    \
            hh info .\n\
        \n  Preview what 'run' would do:\n    \
            hh run . --dry-run\n\
        \n  Run the agent:\n    \
            hh run .\n\
        \n  Inspect encrypted secrets (masked):\n    \
            hh unlock ."
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
            hh init --path ~/.pi\n\
        \n  Init with a specific name and output directory:\n    \
            hh init --harness pi --path ~/.pi --name my-agent --output ./bundles/my-agent")]
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
            hh pack --all --path ~/.pi\n\
        \n  Pack only config and skills:\n    \
            hh pack --with-config --with-skills --path ~/.pi\n\
        \n  Pack and create a .tar.gz archive:\n    \
            hh pack --all --archive --path ~/.pi\n\
        \n  Force overwrite existing files:\n    \
            hh pack --with-config --path ~/.pi --force")]
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

        /// Overwrite existing files in the bundle
        #[arg(long)]
        force: bool,
    },

    /// Launch the agent defined in the bundle
    #[command(after_help = "EXAMPLES:\n\
        \n  Run with default settings:\n    \
            hh run .\n\
        \n  Preview without executing:\n    \
            hh run . --dry-run\n\
        \n  Run with a custom working directory:\n    \
            hh run . --workdir /tmp/agent-workspace\n\
        \n  Pass the passphrase via flag (less secure):\n    \
            hh run . --passphrase my-secret")]
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

        /// Extra arguments passed to the agent command
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Compare a bundle with the local harness state
    #[command(after_help = "EXAMPLES:\n\
        \n  Compare current bundle with local Pi:\n    \
            hh diff .\n\
        \n  Compare with a specific harness path:\n    \
            hh diff . --path ~/.pi/agent")]
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
            hh info .\n\
        \n  Show info for a specific bundle:\n    \
            hh info ./bundles/my-agent")]
    Info {
        /// Path to the bundle directory (default: current dir)
        #[arg(default_value = ".")]
        bundle: String,
    },

    /// Decrypt and inspect secrets stored in the bundle
    #[command(after_help = "EXAMPLES:\n\
        \n  Show secrets with masked values:\n    \
            hh unlock .\n\
        \n  Show full secret values:\n    \
            hh unlock . --show\n\
        \n  Output as KEY=value for sourcing:\n    \
            hh unlock . --env")]
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
}

pub fn parse() -> Cli {
    Cli::parse()
}
