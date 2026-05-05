mod cli;
mod logging;
mod runtime;

use anyhow::Result;
use clap::Parser;
use cli::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    logging::init(args.verbose);
    hush_core::os::raise_nofile_soft_limit_to_hard()?;
    runtime::run(args).await
}
