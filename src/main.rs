use anyhow::Result;

fn main() -> Result<()> {
    let cli = agentpacknest::cli::parse();
    agentpacknest::commands::dispatch(cli)
}
