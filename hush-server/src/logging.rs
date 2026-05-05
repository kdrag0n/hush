pub(crate) fn init(verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "hush_server=debug,hush_core=debug,quinn=info".into())
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "hush_server=info,hush_core=info,quinn=warn".into())
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
