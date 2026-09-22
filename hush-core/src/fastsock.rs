//! UDP sockets for QUIC endpoints that keep per-packet kernel cost low.
//!
//! Sending on an unconnected datagram socket costs several times more kernel
//! time per packet than on a connected one on macOS (route lookup and policy
//! evaluation happen per send), and with QUIC's ~1.4 KB datagrams that is the
//! difference between a few hundred Mbps and line rate. Clients connect their
//! socket outright. A server has one listening socket shared by every peer,
//! so [`MultiSocket`] adds a private socket per connection, bound to the same
//! port as the listener but to the specific local address and connected to
//! the peer. The kernel delivers that peer's packets to the most specific
//! socket, so nothing changes on the wire or for firewalls: the server keeps
//! using its one listening port.
//!
//! The listener is bound with `SO_REUSEADDR` so the private sockets can share
//! its port. On macOS another user cannot bind alongside a socket that has
//! it set, so this opens the port to nothing but the server's own user.

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit, UdpSocketState},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker, ready},
};
use tokio::io::Interest;

/// One UDP socket driven by tokio with quinn's platform-specific datapath.
#[derive(Debug)]
pub struct QuicSocket {
    io: tokio::net::UdpSocket,
    state: UdpSocketState,
}

impl QuicSocket {
    pub fn new(socket: std::net::UdpSocket) -> io::Result<Self> {
        Ok(Self {
            state: UdpSocketState::new((&socket).into())?,
            io: tokio::net::UdpSocket::from_std(socket)?,
        })
    }
}

impl AsyncUdpSocket for QuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(quinn::UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.state.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(res) => return Poll::Ready(Ok(res)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    tracing::debug!(%e, local = ?self.io.local_addr().ok(), "recv failed");
                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }
}

/// A private socket sharing the listening port, connected to one peer.
///
/// The socket is created lazily by the first send to the peer, on the thread
/// doing that send. On macOS an unconnected send temporarily connects the
/// listener's control block to the peer; creating the connected socket
/// while such a send is in flight collides on the 4-tuple and the kernel
/// then quietly disables the new socket. Sends to one peer are serialized by
/// its connection driver, so creating the socket inside a send is safe.
#[derive(Debug)]
struct PrivateSocket {
    peer: SocketAddr,
    local_ip: IpAddr,
    socket: Mutex<Option<Arc<QuicSocket>>>,
    /// Set when the socket could not be opened or the kernel refused to
    /// send on it; the listener serves the peer from then on.
    failed: AtomicBool,
}

impl PrivateSocket {
    fn socket(&self) -> Option<Arc<QuicSocket>> {
        self.socket.lock().unwrap().clone()
    }
}

/// A server endpoint's listening socket plus private per-connection sockets.
#[derive(Debug)]
pub struct MultiSocket {
    main: Arc<QuicSocket>,
    privates: RwLock<Vec<Arc<PrivateSocket>>>,
    /// The endpoint's receive task. It only re-polls the sockets when woken,
    /// so a newly opened private socket must wake it to get registered.
    recv_waker: Mutex<Option<Waker>>,
}

impl MultiSocket {
    /// Wrap a listening socket. It must have been bound with `SO_REUSEADDR`
    /// (see [`crate::os::bind_udp_socket`]) for private sockets to share its
    /// port; without that they fail to open and the listener serves alone.
    pub fn new(listen: std::net::UdpSocket) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            main: Arc::new(QuicSocket::new(listen)?),
            privates: RwLock::new(Vec::new()),
            recv_waker: Mutex::new(None),
        }))
    }

    /// Give the connection from `peer`, which reached us on `local_ip`, its
    /// own socket, opened by the next send to it. Dropping the guard closes
    /// the socket; from then on the peer's packets reach the listener again.
    pub fn adopt(self: &Arc<Self>, local_ip: IpAddr, peer: SocketAddr) -> PrivateSocketGuard {
        let private = Arc::new(PrivateSocket {
            peer,
            local_ip,
            socket: Mutex::new(None),
            failed: AtomicBool::new(false),
        });
        self.privates.write().unwrap().push(Arc::clone(&private));
        PrivateSocketGuard {
            sockets: Arc::clone(self),
            private,
        }
    }

    /// Open the socket for `private`: the listener's family and port, the
    /// specific local address, connected to the peer.
    fn open_private(&self, private: &PrivateSocket) -> io::Result<Arc<QuicSocket>> {
        let main_addr = self.main.local_addr()?;
        // An IPv4 peer of a dual-stack listener gets a plain IPv4 socket: macOS
        // will not send (EPIPE) from an IPv6 socket bound to an IPv4-mapped
        // address. quinn keeps seeing the peer in the listener's mapped form.
        let unmap = |ip: IpAddr| match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let (domain, local_ip, connect_to) = match unmap(private.peer.ip()) {
            IpAddr::V4(peer_v4) => (
                Domain::IPV4,
                unmap(private.local_ip),
                SocketAddr::new(IpAddr::V4(peer_v4), private.peer.port()),
            ),
            IpAddr::V6(_) => (Domain::IPV6, private.local_ip, private.peer),
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        crate::os::set_recv_buffer(&socket);
        socket.bind(&SocketAddr::new(local_ip, main_addr.port()).into())?;
        socket.connect(&connect_to.into())?;
        // Some macOS hosts refuse sends on a connected socket that shares
        // the listener's port, right from connect(). Find out now rather
        // than after quinn has queued packets on it.
        if let Err(err) = socket.send(b"") {
            return Err(io::Error::new(err.kind(), format!("probe send: {err}")));
        }
        let std_socket: std::net::UdpSocket = socket.into();
        let state = UdpSocketState::new((&std_socket).into())?;
        let io = tokio::net::UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(QuicSocket { io, state });
        tracing::debug!(peer = %private.peer, local = %socket.local_addr()?, "private socket opened");
        Ok(socket)
    }

    fn close_private(&self, private: &Arc<PrivateSocket>) {
        self.privates
            .write()
            .unwrap()
            .retain(|p| !Arc::ptr_eq(p, private));
    }
}

impl AsyncUdpSocket for MultiSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.main).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let private = self
            .privates
            .read()
            .unwrap()
            .iter()
            .find(|p| p.peer == transmit.destination && !p.failed.load(Ordering::Relaxed))
            .cloned();
        if let Some(private) = private {
            let socket = match private.socket() {
                Some(socket) => Some(socket),
                None => match self.open_private(&private) {
                    Ok(socket) => {
                        *private.socket.lock().unwrap() = Some(Arc::clone(&socket));
                        // Get the receive task to register the new socket.
                        if let Some(waker) = self.recv_waker.lock().unwrap().as_ref() {
                            waker.wake_by_ref();
                        }
                        Some(socket)
                    }
                    Err(err) => {
                        tracing::debug!(peer = %private.peer, %err, "no private socket for peer");
                        private.failed.store(true, Ordering::Relaxed);
                        None
                    }
                },
            };
            if let Some(socket) = socket {
                // The socket is bound to one address already, so no source hint.
                match socket.try_send(&Transmit {
                    destination: transmit.destination,
                    ecn: transmit.ecn,
                    contents: transmit.contents,
                    segment_size: transmit.segment_size,
                    src_ip: None,
                }) {
                    Err(e) if e.raw_os_error() == Some(libc::EPIPE) => {
                        // The kernel has shut this socket down. Back to the
                        // listener for this peer.
                        tracing::debug!(peer = %private.peer, "private socket refused sends; closing it");
                        private.failed.store(true, Ordering::Relaxed);
                        *private.socket.lock().unwrap() = None;
                    }
                    other => return other,
                }
            }
        }
        match self.main.try_send(transmit) {
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => {
                tracing::warn!(%e, "listener send failed");
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
        {
            let mut waker = self.recv_waker.lock().unwrap();
            if !waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                *waker = Some(cx.waker().clone());
            }
        }
        if let Poll::Ready(res) = self.main.poll_recv(cx, bufs, meta) {
            return Poll::Ready(res);
        }
        let privates = self.privates.read().unwrap().clone();
        for private in privates {
            let Some(socket) = private.socket() else {
                continue;
            };
            if let Poll::Ready(res) = socket.poll_recv(cx, bufs, meta) {
                if let Ok(count) = &res {
                    // A connected socket may report the peer in a different
                    // form (bare IPv4 rather than IPv4-mapped IPv6) than the
                    // listening socket did. QUIC treats any change as a
                    // migration, so present the address quinn knows, and keep
                    // the local address it learned on the listener.
                    for m in &mut meta[..*count] {
                        m.addr = private.peer;
                        m.dst_ip = None;
                    }
                }
                return Poll::Ready(res);
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.main.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.main.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.main.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.main.max_receive_segments()
    }
}

/// Keeps a private socket open; dropping it closes the socket.
#[derive(Debug)]
pub struct PrivateSocketGuard {
    sockets: Arc<MultiSocket>,
    private: Arc<PrivateSocket>,
}

impl Drop for PrivateSocketGuard {
    fn drop(&mut self) {
        tracing::debug!(peer = %self.private.peer, "private socket closed");
        self.sockets.close_private(&self.private);
    }
}
