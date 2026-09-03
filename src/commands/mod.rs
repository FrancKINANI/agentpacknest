pub mod decrypt;
pub mod diff;
pub mod info;
pub mod init;
pub mod pack;
pub mod rekey;
pub mod run;
pub mod unlock;

use crate::application::run_bundle::RunResult;
use crate::cli::{Cli, Commands};
use anyhow::Result;

pub fn dispatch(cli: Cli) -> Result<Option<RunResult>> {
    match cli.command {
        Commands::Init {
            harness,
            path,
            name,
            output,
        } => {
            init::execute(harness, path, name, output)?;
            Ok(None)
        }
        Commands::Pack {
            bundle,
            path,
            with_config,
            with_memory,
            with_skills,
            with_secrets,
            all,
            archive,
            encrypt_archive,
            force,
        } => {
            pack::execute(
                bundle,
                path,
                with_config,
                with_memory,
                with_skills,
                with_secrets,
                all,
                archive,
                encrypt_archive,
                force,
            )?;
            Ok(None)
        }
        Commands::Run {
            bundle,
            passphrase,
            workdir,
            dry_run,
            allow_unverified,
            max_age,
            args,
        } => {
            let result = run::execute(
                bundle,
                passphrase,
                workdir,
                dry_run,
                allow_unverified,
                args,
                max_age,
            )?;
            Ok(Some(result))
        }
        Commands::Decrypt { file } => {
            decrypt::execute(file)?;
            Ok(None)
        }
        Commands::Diff { bundle, path } => {
            diff::execute(bundle, path)?;
            Ok(None)
        }
        Commands::Info { bundle } => {
            info::execute(bundle)?;
            Ok(None)
        }
        Commands::Unlock { bundle, show, env } => {
            unlock::execute(bundle, show, env)?;
            Ok(None)
        }
        Commands::Rekey { bundle } => {
            rekey::execute(bundle)?;
            Ok(None)
        }
    }
}
