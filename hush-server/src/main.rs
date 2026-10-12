mod cli;
mod logging;
mod runtime;

use anyhow::Result;
use cli::Args;

fn main() -> Result<()> {
    let mut raw_args = std::env::args();
    let _program = raw_args.next();
    if raw_args.next().as_deref() == Some(hush_core::filecopy::WORKER_ARG) {
        let user = raw_args
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing worker user"))?;
        if raw_args.next().is_some() {
            anyhow::bail!("unexpected file-copy worker argument");
        }
        let info = hush_core::os::drop_privileges_to_user(&user)?;
        std::env::set_current_dir(&info.home)?;
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(hush_core::filecopy::run_worker());
    }

    let args = Args::parse();
    logging::init(args.verbose);
    hush_core::os::raise_nofile_soft_limit_to_hard()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(runtime::run(args))
}
