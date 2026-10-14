//! Keeping a client's path to its server alive across network changes.
//!
//! QUIC lets a server follow a client to a new address, but only once the
//! client's packets reach it. A client whose source address is gone (its
//! connected socket then fails every send) or whose packets a NAT silently
//! drops (a broken mapping that keepalives keep from expiring) has to move to
//! a new socket itself. Like mosh, the client hops to a fresh socket, with a
//! new source port and the source address the system picks now, whenever
//! what it sent goes unanswered, and right away when its socket reports that
//! it cannot send or a network change gives the server a different source
//! address.

use crate::netmon::NetworkMonitor;
use hush_core::fastsock::{QuicSocket, is_dead_socket_error};
use quinn::{
    AsyncUdpSocket, Connection, ConnectionStats, Endpoint, UdpPoller, WeakConnectionHandle,
    udp::{RecvMeta, Transmit},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    sync::Notify,
    time::{Duration, Instant, MissedTickBehavior},
};

/// How often the connection's counters are checked.
const WATCH_INTERVAL: Duration = Duration::from_secs(1);
/// Packets that need an acknowledgement may go unanswered this long, or for
/// `SILENCE_RTTS` round trips on slow paths, before the client hops.
const MIN_SILENCE: Duration = Duration::from_secs(3);
const SILENCE_RTTS: u32 = 8;
/// While hopping does not help (the network is down, or the server is gone),
/// hops back off up to this interval.
const MAX_HOP_BACKOFF: Duration = Duration::from_secs(30);
/// Hops requested by the socket or the network are at least this far apart.
const MIN_HOP_INTERVAL: Duration = Duration::from_secs(1);

/// The kind of socket a client endpoint uses.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Transport {
    /// A BSD socket `connect()`ed to the server.
    Bsd,
    /// A Network.framework flow (`HUSH_NW=1`).
    #[cfg(target_os = "macos")]
    Network,
}

impl Transport {
    pub(crate) fn from_env() -> Self {
        #[cfg(target_os = "macos")]
        if std::env::var_os("HUSH_NW").is_some() {
            return Self::Network;
        }
        Self::Bsd
    }

    /// A new socket to `addr`, from a fresh port. `trouble` is notified when
    /// the socket finds it cannot send anymore.
    /// Whether the socket stays on the source address it started from, so
    /// network changes have to be watched for it.
    fn pins_source_address(self) -> bool {
        match self {
            Self::Bsd => true,
            #[cfg(target_os = "macos")]
            Self::Network => false,
        }
    }

    pub(crate) fn open(
        self,
        addr: SocketAddr,
        trouble: &Arc<Notify>,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        match self {
            Self::Bsd => Ok(Arc::new(ClientSocket::new(
                connected_socket(addr)?,
                Arc::clone(trouble),
            )?)),
            #[cfg(target_os = "macos")]
            Self::Network => {
                let trouble = Arc::clone(trouble);
                Ok(Arc::new(hush_core::nwsock::NwSocket::connect(
                    addr,
                    move || trouble.notify_one(),
                )?))
            }
        }
    }
}

/// A UDP socket of `addr`'s family, bound to an ephemeral port and connected
/// to `addr`. On macOS an unconnected datagram send costs several times more
/// kernel time per packet than a connected one, which is the difference
/// between a few hundred Mbps and line rate for file copies.
fn connected_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let (domain, local): (Domain, SocketAddr) = match addr {
        SocketAddr::V4(_) => (Domain::IPV4, (Ipv4Addr::UNSPECIFIED, 0).into()),
        SocketAddr::V6(_) => (Domain::IPV6, (Ipv6Addr::UNSPECIFIED, 0).into()),
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    hush_core::os::set_recv_buffer(&socket);
    socket.bind(&local.into())?;
    socket.connect(&addr.into())?;
    Ok(socket.into())
}

/// A client's connected UDP socket.
#[derive(Debug)]
struct ClientSocket {
    socket: QuicSocket,
    trouble: Arc<Notify>,
}

impl ClientSocket {
    fn new(socket: std::net::UdpSocket, trouble: Arc<Notify>) -> io::Result<Self> {
        Ok(Self {
            socket: QuicSocket::new(socket)?,
            trouble,
        })
    }
}

impl AsyncUdpSocket for ClientSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(quinn::UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.socket.writable().await }
        }))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        match self.socket.try_send(transmit) {
            // This socket cannot send again, such as after the address it is
            // connected from went away. Ask for a new one, and drop the
            // datagram like any other loss: a send error would stop the
            // connection's driver for good.
            Err(e) if is_dead_socket_error(&e) => {
                tracing::debug!(%e, "client socket cannot send");
                self.trouble.notify_one();
                Ok(())
            }
            other => other,
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.socket.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }
}

/// Watch `conn`'s path in the background, and move `endpoint` to a fresh
/// socket when the path stops working. The watcher ends with the connection
/// and does not keep it open.
pub(crate) fn keep_path(
    endpoint: Endpoint,
    conn: &Connection,
    transport: Transport,
    trouble: Arc<Notify>,
) {
    tokio::spawn(watch_path(endpoint, conn.weak_handle(), transport, trouble));
}

async fn watch_path(
    endpoint: Endpoint,
    conn: WeakConnectionHandle,
    transport: Transport,
    mut trouble: Arc<Notify>,
) {
    let mut tick = tokio::time::interval(WATCH_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut monitor = transport
        .pins_source_address()
        .then(|| {
            NetworkMonitor::new()
                .inspect_err(|err| tracing::debug!(%err, "cannot watch for network changes"))
                .ok()
        })
        .flatten();
    let mut watch = PathWatch::default();
    loop {
        let event = tokio::select! {
            _ = tick.tick() => Event::Tick,
            _ = trouble.notified() => Event::SocketTrouble,
            changed = next_change(&mut monitor) => {
                if let Err(err) = changed {
                    tracing::debug!(%err, "stopped watching for network changes");
                    monitor = None;
                }
                Event::NetworkChanged
            }
        };
        if !conn.is_alive() {
            return;
        }
        let (Some(stats), Some(rtt), Some(remote)) =
            (conn.stats(), conn.rtt(), conn.remote_address())
        else {
            return;
        };
        let now = Instant::now();
        let silence = (rtt * SILENCE_RTTS).clamp(MIN_SILENCE, MAX_HOP_BACKOFF);
        let reason = if event == Event::SocketTrouble {
            if !watch.may_hop_now(now) {
                continue;
            }
            "socket lost its path"
        } else if event == Event::NetworkChanged {
            let Ok(source) = preferred_source(remote) else {
                // No route to the server right now; a later change brings one.
                continue;
            };
            let current = endpoint.local_addr().ok().map(|local| local.ip());
            if current == Some(source) || !watch.may_hop_now(now) {
                continue;
            }
            "network changed"
        } else if watch.observe(
            now,
            stats.frame_rx.acks,
            ack_eliciting_frames_sent(&stats),
            silence,
        ) {
            "sent packets went unanswered"
        } else {
            continue;
        };
        watch.hopped(now, silence);
        // Each socket reports to its own `Notify`: quinn keeps the previous
        // socket for late packets, and its complaints no longer matter.
        let next_trouble = Arc::new(Notify::new());
        match transport
            .open(remote, &next_trouble)
            .and_then(|socket| endpoint.rebind_abstract(socket))
        {
            Ok(()) => {
                trouble = next_trouble;
                tracing::debug!(
                    %remote,
                    local = ?endpoint.local_addr().ok(),
                    reason,
                    "moved to a new socket"
                );
            }
            Err(err) => tracing::debug!(%remote, %err, reason, "could not open a new socket"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Event {
    Tick,
    SocketTrouble,
    NetworkChanged,
}

/// The next network change, or never without a monitor.
async fn next_change(monitor: &mut Option<NetworkMonitor>) -> io::Result<()> {
    match monitor {
        Some(monitor) => monitor.changed().await,
        None => std::future::pending().await,
    }
}

/// The source address the system would send from to `remote` now.
fn preferred_source(remote: SocketAddr) -> io::Result<IpAddr> {
    let unspecified: IpAddr = match remote {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    // Connecting a datagram socket only picks a route and source address;
    // nothing is sent.
    let probe = UdpSocket::bind((unspecified, 0))?;
    probe.connect(remote)?;
    Ok(probe.local_addr()?.ip())
}

/// Frames sent that the peer must acknowledge: every kind but ACK itself
/// (PADDING is not counted). CONNECTION_CLOSE ends the watch anyway.
fn ack_eliciting_frames_sent(stats: &ConnectionStats) -> u64 {
    let f = &stats.frame_tx;
    f.ack_frequency
        + f.crypto
        + f.data_blocked
        + f.datagram
        + u64::from(f.handshake_done)
        + f.immediate_ack
        + f.max_data
        + f.max_stream_data
        + f.max_streams_bidi
        + f.max_streams_uni
        + f.new_connection_id
        + f.new_token
        + f.path_challenge
        + f.path_response
        + f.ping
        + f.reset_stream
        + f.retire_connection_id
        + f.stream_data_blocked
        + f.streams_blocked_bidi
        + f.streams_blocked_uni
        + f.stop_sending
        + f.stream
}

/// Decides from a connection's counters when its path has stopped working.
///
/// The path works while the peer acknowledges what the client sends. Data
/// arriving from the peer is not enough: with the client's packets lost on
/// the way, the server keeps retransmitting to the old address, which may
/// still reach the client.
#[derive(Debug, Default)]
struct PathWatch {
    /// ACK frames received so far.
    acks: u64,
    /// Ack-eliciting frames sent as of the last new ACK.
    sent_at_last_ack: u64,
    /// When frames sent after the last ACK were first seen.
    unanswered_since: Option<Instant>,
    last_hop: Option<Instant>,
    /// How long after the last hop another one may follow; zero until a hop.
    backoff: Duration,
}

impl PathWatch {
    /// Record the connection's counters, and return whether the client
    /// should hop: what it sent has gone unanswered for `silence`, and the
    /// last hop, if any, did not help for long enough.
    fn observe(
        &mut self,
        now: Instant,
        acks: u64,
        ack_eliciting_sent: u64,
        silence: Duration,
    ) -> bool {
        if acks != self.acks {
            self.acks = acks;
            self.sent_at_last_ack = ack_eliciting_sent;
            self.unanswered_since = None;
            self.backoff = Duration::ZERO;
            return false;
        }
        if ack_eliciting_sent == self.sent_at_last_ack {
            return false;
        }
        let since = *self.unanswered_since.get_or_insert(now);
        now.duration_since(since) >= silence
            && self
                .last_hop
                .is_none_or(|hop| now.duration_since(hop) >= self.backoff)
    }

    /// Whether a hop the socket asked for may happen now.
    fn may_hop_now(&self, now: Instant) -> bool {
        self.last_hop
            .is_none_or(|hop| now.duration_since(hop) >= MIN_HOP_INTERVAL)
    }

    fn hopped(&mut self, now: Instant, silence: Duration) {
        self.last_hop = Some(now);
        self.backoff = (self.backoff * 2).max(silence).min(MAX_HOP_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SILENCE: Duration = Duration::from_secs(3);

    fn secs(start: Instant, s: u64) -> Instant {
        start + Duration::from_secs(s)
    }

    #[test]
    fn answered_sends_never_hop() {
        let start = Instant::now();
        let mut watch = PathWatch::default();
        for s in 0..60 {
            assert!(!watch.observe(secs(start, s), s, s, SILENCE));
        }
    }

    #[test]
    fn idle_connection_never_hops() {
        let start = Instant::now();
        let mut watch = PathWatch::default();
        assert!(!watch.observe(start, 5, 7, SILENCE));
        for s in 1..60 {
            assert!(!watch.observe(secs(start, s), 5, 7, SILENCE));
        }
    }

    #[test]
    fn unacknowledged_only_acks_never_hop() {
        // ACK-only packets elicit nothing, so the counter of frames that need
        // an acknowledgement stays put however many the client sends.
        let start = Instant::now();
        let mut watch = PathWatch::default();
        assert!(!watch.observe(start, 5, 7, SILENCE));
        assert!(!watch.observe(secs(start, 10), 5, 7, SILENCE));
    }

    #[test]
    fn unanswered_sends_hop_after_silence() {
        let start = Instant::now();
        let mut watch = PathWatch::default();
        assert!(!watch.observe(start, 5, 7, SILENCE));
        assert!(!watch.observe(secs(start, 1), 5, 8, SILENCE));
        assert!(!watch.observe(secs(start, 3), 5, 8, SILENCE));
        assert!(watch.observe(secs(start, 4), 5, 9, SILENCE));
    }

    #[test]
    fn hops_back_off_while_unanswered_and_reset_on_ack() {
        let start = Instant::now();
        let mut watch = PathWatch::default();
        assert!(!watch.observe(start, 5, 7, SILENCE));
        assert!(!watch.observe(secs(start, 1), 5, 8, SILENCE));
        assert!(watch.observe(secs(start, 4), 5, 8, SILENCE));
        watch.hopped(secs(start, 4), SILENCE);
        // Next hop after `silence`, then twice that.
        assert!(!watch.observe(secs(start, 6), 5, 9, SILENCE));
        assert!(watch.observe(secs(start, 7), 5, 9, SILENCE));
        watch.hopped(secs(start, 7), SILENCE);
        assert!(!watch.observe(secs(start, 12), 5, 10, SILENCE));
        assert!(watch.observe(secs(start, 13), 5, 10, SILENCE));
        watch.hopped(secs(start, 13), SILENCE);
        // An acknowledgement means the path works again.
        assert!(!watch.observe(secs(start, 14), 6, 10, SILENCE));
        assert!(!watch.observe(secs(start, 15), 6, 11, SILENCE));
        assert!(watch.observe(secs(start, 18), 6, 11, SILENCE));
    }

    #[test]
    fn backoff_is_capped() {
        let start = Instant::now();
        let mut watch = PathWatch::default();
        for s in 0..10 {
            watch.hopped(secs(start, s), SILENCE);
        }
        assert_eq!(watch.backoff, MAX_HOP_BACKOFF);
    }

    #[test]
    fn socket_hops_are_rate_limited() {
        let start = Instant::now();
        let mut watch = PathWatch::default();
        assert!(watch.may_hop_now(start));
        watch.hopped(start, SILENCE);
        assert!(!watch.may_hop_now(start + Duration::from_millis(500)));
        assert!(watch.may_hop_now(secs(start, 1)));
    }
}
