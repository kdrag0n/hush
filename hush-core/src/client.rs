//! Client side of the connection authentication handshake.

use crate::{
    priority::{StreamPriority, set_stream_priority},
    protocol::{StreamOpen, StreamResponse, read_frame, write_frame},
};
use anyhow::{Result, bail};
use quinn::Connection;

/// Authenticate a fresh connection as `user`. This must complete before any
/// other stream is opened: the server refuses everything else until the
/// connection is authenticated, and all later requests act as this user.
pub async fn authenticate(conn: &Connection, user: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    set_stream_priority(&send, StreamPriority::Shell);
    write_frame(
        &mut send,
        &StreamOpen::Authenticate {
            user: user.to_owned(),
        },
    )
    .await?;
    send.finish()?;
    match read_frame::<StreamResponse>(&mut recv).await? {
        StreamResponse::Ok => Ok(()),
        StreamResponse::Error(err) => bail!("{err}"),
        other => bail!("unexpected authentication response: {other:?}"),
    }
}
