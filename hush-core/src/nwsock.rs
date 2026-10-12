//! A quinn datagram transport on Network.framework UDP (macOS).
//!
//! Network.framework runs its own user-space datapath and tracks a flow per
//! peer, so a server can send to every client cheaply from one listening
//! port. A shared BSD socket costs about four times the kernel time per
//! packet for the same sends, and per-peer connected BSD sockets sharing the
//! port are refused on some macOS hosts. One handle is either a listener
//! whose peers become flows, or a single client flow.
//!
//! ECN is not yet handled (quinn disables it after validation fails).

use quinn::{
    AsyncUdpSocket, UdpPollHelper, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::{HashMap, VecDeque},
    ffi::{CString, c_void},
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[repr(C)]
struct Handle {
    _private: [u8; 0],
}

type FlowCb = extern "C" fn(*mut c_void, u64, *const libc::sockaddr, *const libc::sockaddr);
type RecvCb = extern "C" fn(*mut c_void, u64, *const u8, usize);
type CloseCb = extern "C" fn(*mut c_void, u64);

unsafe extern "C" {
    fn nwudp_create(
        ctx: *mut c_void,
        on_flow: FlowCb,
        on_recv: RecvCb,
        on_close: CloseCb,
    ) -> *mut Handle;
    fn nwudp_listen(
        h: *mut Handle,
        host: *const libc::c_char,
        port: u16,
        max_unprotected_flows: usize,
    ) -> i32;
    fn nwudp_connect(h: *mut Handle, host: *const libc::c_char, port: u16) -> u64;
    fn nwudp_send(h: *mut Handle, flow: u64, data: *const u8, len: usize, seg: usize) -> i32;
    fn nwudp_close_flow(h: *mut Handle, flow: u64);
    fn nwudp_protect_flow(h: *mut Handle, flow: u64) -> i32;
}

/// Bytes of received datagrams held before the endpoint reads them.
const INBOX_LIMIT: usize = 16 << 20;

/// Received datagrams with their peer, and the bytes they hold in total.
type Inbox = (VecDeque<(SocketAddr, Vec<u8>)>, usize);

struct Inner {
    handle: *mut Handle,
    /// Peer address, in the form the local address family prefers, to flow id
    flows: Mutex<HashMap<SocketAddr, u64>>,
    peers: Mutex<HashMap<u64, SocketAddr>>,
    inbox: Mutex<Inbox>,
    waker: Mutex<Option<Waker>>,
    local: Mutex<SocketAddr>,
    ipv6: bool,
}

// SAFETY: the handle is only used through its thread-safe C API.
unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

fn sockaddr_to_addr(sa: *const libc::sockaddr) -> Option<SocketAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: sa points at a sockaddr of the family it declares.
    unsafe {
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let sin = &*(sa as *const libc::sockaddr_in);
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))),
                    u16::from_be(sin.sin_port),
                ))
            }
            libc::AF_INET6 => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                    u16::from_be(sin6.sin6_port),
                ))
            }
            _ => None,
        }
    }
}

impl Inner {
    /// The form quinn expects addresses in for this endpoint's family.
    fn canonical(&self, addr: SocketAddr) -> SocketAddr {
        match (self.ipv6, addr) {
            (true, SocketAddr::V4(v4)) => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            (false, SocketAddr::V6(v6)) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
                None => addr,
            },
            _ => addr,
        }
    }
}

extern "C" fn on_flow(
    ctx: *mut c_void,
    flow: u64,
    remote: *const libc::sockaddr,
    local: *const libc::sockaddr,
) {
    // SAFETY: ctx is the Arc<Inner> pointer registered in `new`, kept alive for
    // the program's lifetime.
    let inner = unsafe { &*(ctx as *const Inner) };
    if let Some(remote) = sockaddr_to_addr(remote) {
        let remote = inner.canonical(remote);
        inner.flows.lock().unwrap().insert(remote, flow);
        inner.peers.lock().unwrap().insert(flow, remote);
    }
    if let Some(local) = sockaddr_to_addr(local) {
        let mut current = inner.local.lock().unwrap();
        if current.port() == 0 {
            *current = inner.canonical(local);
        }
    }
}

extern "C" fn on_recv(ctx: *mut c_void, flow: u64, data: *const u8, len: usize) {
    // SAFETY: as in on_flow; data is valid for len bytes during the call.
    let inner = unsafe { &*(ctx as *const Inner) };
    let Some(peer) = inner.peers.lock().unwrap().get(&flow).copied() else {
        return;
    };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    {
        let mut inbox = inner.inbox.lock().unwrap();
        if inbox.1 + len > INBOX_LIMIT {
            return;
        }
        inbox.1 += len;
        inbox.0.push_back((peer, bytes));
    }
    if let Some(waker) = inner.waker.lock().unwrap().take() {
        waker.wake();
    }
}

extern "C" fn on_close(ctx: *mut c_void, flow: u64) {
    // SAFETY: as in on_flow.
    let inner = unsafe { &*(ctx as *const Inner) };
    let Some(peer) = inner.peers.lock().unwrap().remove(&flow) else {
        return;
    };
    let mut flows = inner.flows.lock().unwrap();
    if flows.get(&peer) == Some(&flow) {
        flows.remove(&peer);
    }
}

/// A quinn socket backed by Network.framework.
#[derive(Debug)]
pub struct NwSocket {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").finish()
    }
}

impl NwSocket {
    fn new(ipv6: bool, local: SocketAddr) -> Self {
        let inner = Arc::new(Inner {
            handle: std::ptr::null_mut(),
            flows: Mutex::new(HashMap::new()),
            peers: Mutex::new(HashMap::new()),
            inbox: Mutex::new((VecDeque::new(), 0)),
            waker: Mutex::new(None),
            local: Mutex::new(local),
            ipv6,
        });
        // The shim keeps a raw pointer to Inner; leak one reference so it
        // stays valid for the process lifetime (experimental transport).
        let ctx = Arc::into_raw(Arc::clone(&inner)) as *mut c_void;
        // SAFETY: the callbacks match the shim's expected signatures.
        let handle = unsafe { nwudp_create(ctx, on_flow, on_recv, on_close) };
        // SAFETY: Inner is behind an Arc we own; handle set once here.
        unsafe { (*(Arc::as_ptr(&inner) as *mut Inner)).handle = handle };
        Self { inner }
    }

    /// Listen on `addr`; an unspecified address means every address.
    pub fn listen(addr: SocketAddr, max_unprotected_flows: usize) -> io::Result<Self> {
        let socket = Self::new(addr.is_ipv6(), addr);
        let host = (!addr.ip().is_unspecified())
            .then(|| CString::new(addr.ip().to_string()))
            .transpose()
            .map_err(io::Error::other)?;
        let host_ptr = host.as_ref().map_or(std::ptr::null(), |h| h.as_ptr());
        // SAFETY: valid handle; host is NULL or a C string alive for the call.
        if unsafe {
            nwudp_listen(
                socket.inner.handle,
                host_ptr,
                addr.port(),
                max_unprotected_flows,
            )
        } != 0
        {
            return Err(io::Error::other("nw listener failed"));
        }
        Ok(socket)
    }

    /// A single flow to `addr`.
    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let socket = Self::new(
            addr.is_ipv6(),
            SocketAddr::new(
                if addr.is_ipv6() {
                    Ipv6Addr::UNSPECIFIED.into()
                } else {
                    Ipv4Addr::UNSPECIFIED.into()
                },
                0,
            ),
        );
        let host = CString::new(addr.ip().to_string()).map_err(io::Error::other)?;
        // SAFETY: valid handle and C string.
        let flow = unsafe { nwudp_connect(socket.inner.handle, host.as_ptr(), addr.port()) };
        socket.inner.flows.lock().unwrap().insert(addr, flow);
        socket.inner.peers.lock().unwrap().insert(flow, addr);
        Ok(socket)
    }

    /// Protect an authenticated peer's flow from the short unauthenticated
    /// idle timeout. Dropping the guard closes the flow immediately.
    pub fn adopt(self: &Arc<Self>, peer: SocketAddr) -> io::Result<NwFlowGuard> {
        let peer = self.inner.canonical(peer);
        let flow = self
            .inner
            .flows
            .lock()
            .unwrap()
            .get(&peer)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "peer flow is gone"))?;
        // SAFETY: the handle remains alive with `inner` and the flow id came
        // from that handle's callback.
        if unsafe { nwudp_protect_flow(self.inner.handle, flow) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "peer flow closed before authentication completed",
            ));
        }
        Ok(NwFlowGuard {
            inner: Arc::clone(&self.inner),
            flow,
        })
    }
}

#[derive(Debug)]
pub struct NwFlowGuard {
    inner: Arc<Inner>,
    flow: u64,
}

impl Drop for NwFlowGuard {
    fn drop(&mut self) {
        // SAFETY: the handle remains alive with `inner`; closing an already
        // closed flow is explicitly harmless in the shim.
        unsafe { nwudp_close_flow(self.inner.handle, self.flow) };
    }
}

impl AsyncUdpSocket for NwSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpPollHelper::new(|| std::future::ready(Ok(()))))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let flow = self
            .inner
            .flows
            .lock()
            .unwrap()
            .get(&transmit.destination)
            .copied();
        let Some(flow) = flow else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("no flow to {}", transmit.destination),
            ));
        };
        let seg = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        // SAFETY: the buffer is valid for the call; the shim copies it.
        let rc = unsafe {
            nwudp_send(
                self.inner.handle,
                flow,
                transmit.contents.as_ptr(),
                transmit.contents.len(),
                seg,
            )
        };
        if rc != 0 {
            return Err(io::Error::other("nw send failed"));
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut inbox = self.inner.inbox.lock().unwrap();
        let mut count = 0;
        while count < bufs.len().min(meta.len()) {
            let Some((peer, data)) = inbox.0.pop_front() else {
                break;
            };
            inbox.1 -= data.len();
            let len = data.len().min(bufs[count].len());
            bufs[count][..len].copy_from_slice(&data[..len]);
            meta[count] = RecvMeta {
                addr: peer,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            count += 1;
        }
        if count > 0 {
            return Poll::Ready(Ok(count));
        }
        *self.inner.waker.lock().unwrap() = Some(cx.waker().clone());
        // Something may have arrived between the check and the registration.
        if !inbox.0.is_empty() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(*self.inner.local.lock().unwrap())
    }

    fn max_transmit_segments(&self) -> usize {
        10
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
