pub mod agent;
pub mod auth;
pub mod client;
pub mod config;
pub mod defaults;
pub mod endpoint;
pub mod filecopy;
pub mod forwarding;
pub mod net;
pub mod os;
pub mod paths;
pub mod priority;
pub mod protocol;
pub mod server;
pub(crate) mod session;
pub mod tls;

// hush/2: connections must authenticate with a `StreamOpen::Authenticate`
// handshake before any other stream, and requests no longer carry a user.
pub const ALPN: &[u8] = b"hush/2";
