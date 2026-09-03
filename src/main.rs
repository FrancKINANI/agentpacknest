use anyhow::Result;

fn main() -> Result<()> {
    let cli = agentpacknest::cli::parse();
    let result = agentpacknest::commands::dispatch(cli)?;

    // If dispatch returns a RunResult, use its exit code
    if let Some(run_result) = result {
        std::process::exit(run_result.exit_code);
    }

    Ok(())
}
