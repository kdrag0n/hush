use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "hush-server",
    version,
    about = "Server for hush, an SSH-like remote shell over QUIC",
    long_about = "hush-server listens for QUIC connections, authenticates clients with Ed25519 SSH keys, and runs remote shell sessions.\n\nServer files live under the data directory's server/ subdirectory. The default config path is $DATA_DIR/server/config.toml, and the default host certificate and key are $DATA_DIR/server/host_cert.der and $DATA_DIR/server/host_key.der. When running as root, the default data directory is /etc/hush. Command-line flags override config file values."
)]
pub(crate) struct Args {
    /// Enable verbose server logging.
    #[arg(short, long)]
    pub(crate) verbose: bool,

    /// Base data directory. Server files live under DIR/server.
    #[arg(long, value_name = "DIR", help_heading = "Configuration")]
    pub(crate) data_dir: Option<PathBuf>,

    /// UDP listen address.
    #[arg(short, long, value_name = "ADDR", default_value = "[::]:4433")]
    pub(crate) listen: SocketAddr,

    /// Path to server/config.toml.
    #[arg(short, long, value_name = "PATH", help_heading = "Configuration")]
    pub(crate) config: Option<PathBuf>,

    /// DER-encoded TLS host certificate path.
    #[arg(long, value_name = "PATH", help_heading = "Configuration")]
    pub(crate) host_cert: Option<PathBuf>,

    /// DER-encoded TLS host private key path.
    #[arg(long, value_name = "PATH", help_heading = "Configuration")]
    pub(crate) host_key: Option<PathBuf>,

    /// authorized_keys file to use instead of the target user's default.
    #[arg(long, value_name = "PATH", help_heading = "Configuration")]
    pub(crate) authorized_keys: Option<PathBuf>,

    /// Restrict logins to this username. May be repeated.
    #[arg(long, value_name = "USER", help_heading = "Configuration")]
    pub(crate) allow_user: Vec<String>,

    /// Disable local and remote TCP forwarding.
    #[arg(long)]
    pub(crate) disable_tcp_forwarding: bool,

    /// Maximum concurrent QUIC connections.
    #[arg(long, value_name = "N", help_heading = "Limits")]
    pub(crate) max_connections: Option<usize>,

    /// Maximum shell sessions accepted per QUIC connection.
    #[arg(long, value_name = "N", help_heading = "Limits")]
    pub(crate) max_sessions_per_connection: Option<usize>,

    /// Maximum remote -R listeners accepted before the session starts.
    #[arg(long, value_name = "N", help_heading = "Limits")]
    pub(crate) max_forwards_per_connection: Option<usize>,

    /// Maximum concurrent local-forward streams per connection.
    #[arg(long, value_name = "N", help_heading = "Limits")]
    pub(crate) max_forward_streams_per_connection: Option<usize>,
}
