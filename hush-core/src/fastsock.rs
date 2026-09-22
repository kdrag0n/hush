//! UDP sockets for QUIC endpoints that keep per-packet kernel cost low.
//!
//! Sending on an unconnected datagram socket costs several times more kernel
//! time per packet than on a connected one on macOS (route lookup and policy
//! evaluation happen per send), and with QUIC's ~1.4 KB datagrams that is the
//! difference between a few hundred Mbps and line rate. Clients connect their
//! socket outright. A server has one listening socket shared by every peer,
//! so [`MultiSocket`] adds private sockets on ephemeral ports: a connection
//! that wants one is told the port, moves there, and the private socket is
//! connected to the peer as soon as its first packet arrives.

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit, UdpSocketState},
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{
    io::{self, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
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

    /// Connect to `peer`, after which sends omit the destination and only
    /// datagrams from `peer` are received.
    fn connect(&self, peer: SocketAddr) -> io::Result<()> {
        SockRef::from(&self.io).connect(&peer.into())?;
        self.state.set_connected(true);
        Ok(())
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
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
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

/// A private socket on an ephemeral port, connected to its peer once the
/// peer's first packet arrives.
#[derive(Debug)]
struct PrivateSocket {
    socket: Arc<QuicSocket>,
    peer: Mutex<Option<SocketAddr>>,
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
    pub fn new(listen: std::net::UdpSocket) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            main: Arc::new(QuicSocket::new(listen)?),
            privates: RwLock::new(Vec::new()),
            recv_waker: Mutex::new(None),
        }))
    }

    /// Open a private socket of the listening socket's address family. The
    /// returned guard closes it; the port is what the peer should send to.
    pub fn open_private(self: &Arc<Self>) -> io::Result<PrivateSocketGuard> {
        let (domain, local): (Domain, SocketAddr) = if self.main.local_addr()?.is_ipv6() {
            (Domain::IPV6, (Ipv6Addr::UNSPECIFIED, 0).into())
        } else {
            (Domain::IPV4, (Ipv4Addr::UNSPECIFIED, 0).into())
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if domain == Domain::IPV6 {
            socket.set_only_v6(false)?;
        }
        crate::os::set_recv_buffer(&socket);
        socket.bind(&local.into())?;
        let socket = Arc::new(QuicSocket::new(socket.into())?);
        let port = socket.local_addr()?.port();
        let private = Arc::new(PrivateSocket {
            socket,
            peer: Mutex::new(None),
        });
        self.privates.write().unwrap().push(Arc::clone(&private));
        if let Some(waker) = self.recv_waker.lock().unwrap().as_ref() {
            waker.wake_by_ref();
        }
        Ok(PrivateSocketGuard {
            sockets: Arc::clone(self),
            private,
            port,
        })
    }

    fn close_private(&self, private: &Arc<PrivateSocket>) {
        self.privates
            .write()
            .unwrap()
            .retain(|p| !Arc::ptr_eq(p, private));
    }

    /// Learn a private socket's peer from its first packet and connect it.
    /// Returns the peer address in the form first seen.
    fn adopt_peer(private: &PrivateSocket, peer: SocketAddr) -> SocketAddr {
        let mut current = private.peer.lock().unwrap();
        if let Some(current) = *current {
            return current;
        }
        tracing::debug!(%peer, "adopting private socket peer");
        match private.socket.connect(peer) {
            Ok(()) => *current = Some(peer),
            Err(err) => tracing::warn!(%peer, %err, "connect private socket failed"),
        }
        peer
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
            .find(|p| *p.peer.lock().unwrap() == Some(transmit.destination))
            .cloned();
        match private {
            Some(private) => private.socket.try_send(transmit),
            None => self.main.try_send(transmit),
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
            if let Poll::Ready(res) = private.socket.poll_recv(cx, bufs, meta) {
                if let Ok(count) = &res
                    && *count > 0
                {
                    let peer = Self::adopt_peer(&private, meta[0].addr);
                    // A connected dual-stack socket may report the same peer
                    // in a different form (bare IPv4 rather than
                    // IPv4-mapped IPv6) than it did before connecting. QUIC
                    // treats any change as a migration, so present one form.
                    for m in &mut meta[..*count] {
                        m.addr = peer;
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
    port: u16,
}

impl PrivateSocketGuard {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for PrivateSocketGuard {
    fn drop(&mut self) {
        self.sockets.close_private(&self.private);
    }
}
