pub mod agent;
pub mod auth;
pub mod config;
pub mod defaults;
pub mod endpoint;
pub mod fastsock;
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

// hush/3: the client certificate carries the username it claims, the server
// authenticates the connection from the TLS handshake alone (no Authenticate
// stream), and requests do not carry a user.
pub const ALPN: &[u8] = b"hush/3";
