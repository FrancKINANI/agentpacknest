pub mod init;
pub mod pack;
pub mod run;
pub mod diff;
pub mod info;
pub mod unlock;
pub mod rekey;

use crate::cli::{Cli, Commands};
use anyhow::Result;

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init { harness, path, name, output } => {
            init::execute(harness, path, name, output)
        }
        Commands::Pack {
            bundle, path,
            with_config, with_memory, with_skills, with_secrets,
            all, archive, encrypt_archive, force,
        } => {
            pack::execute(
                bundle, path,
                with_config, with_memory, with_skills, with_secrets,
                all, archive, encrypt_archive, force,
            )
        }
        Commands::Run { bundle, passphrase, workdir, dry_run, args } => {
            run::execute(bundle, passphrase, workdir, dry_run, args)
        }
        Commands::Diff { bundle, path } => {
            diff::execute(bundle, path)
        }
        Commands::Info { bundle } => info::execute(bundle),
        Commands::Unlock { bundle, show, env } => {
            unlock::execute(bundle, show, env)
        }
        Commands::Rekey { bundle } => {
            rekey::execute(bundle)
        }
    }
}
