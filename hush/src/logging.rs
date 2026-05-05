pub(crate) fn init(verbose: bool) {
    if verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "hush=debug,hush_core=debug,quinn=info".into()),
            )
            .init();
    }
}
