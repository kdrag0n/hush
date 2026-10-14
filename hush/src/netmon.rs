//! Notifications that the host's addresses or routes changed.
//!
//! A client socket connected to its server keeps the source address it was
//! connected from, so after a network change it fails every send, or keeps
//! sending over the old interface while a better one is up. These
//! notifications tell the client to check which source address the system
//! would pick now. macOS (and the BSDs) report changes on a routing socket,
//! Linux on a netlink socket.

use std::io::{self, Read};
use tokio::io::{Interest, unix::AsyncFd};

pub(crate) struct NetworkMonitor {
    socket: AsyncFd<socket2::Socket>,
}

impl NetworkMonitor {
    pub(crate) fn new() -> io::Result<Self> {
        let socket = open()?;
        socket.set_nonblocking(true)?;
        // SAFETY: the AsyncFd owns the socket, which stays open and is never
        // replaced until the AsyncFd is dropped.
        let socket = unsafe { AsyncFd::register_with_interest(socket, Interest::READABLE) }?;
        Ok(Self { socket })
    }

    /// Wait for a change that may affect which source address or interface
    /// reaches a peer. All messages queued by then are consumed, so a burst
    /// of them (a network switch sends many) wakes the caller once or twice.
    pub(crate) async fn changed(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let mut guard = self.socket.readable().await?;
            let mut relevant = false;
            loop {
                match guard.try_io(|socket| socket.get_ref().read(&mut buf)) {
                    Ok(Ok(0)) => break,
                    Ok(Ok(len)) => relevant |= is_relevant(&buf[..len]),
                    // The kernel dropped messages for lack of buffer space:
                    // something changed, but what is unknown.
                    Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => relevant = true,
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => break,
                }
            }
            if relevant {
                return Ok(());
            }
        }
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn open() -> io::Result<socket2::Socket> {
    // socket2 sets close-on-exec (and SO_NOSIGPIPE on macOS) on creation.
    socket2::Socket::new(
        socket2::Domain::from(libc::PF_ROUTE),
        socket2::Type::RAW,
        None,
    )
}

/// Address, interface and route changes. Routes the kernel clones per
/// destination or for link-layer neighbors come and go with ordinary
/// traffic, so they do not count.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn is_relevant(msg: &[u8]) -> bool {
    // Every routing message starts with its length (u16), version (u8) and
    // type (u8); route messages (struct rt_msghdr) carry their flags at
    // offset 8, after the interface index and padding.
    let Some(&kind) = msg.get(3) else {
        return false;
    };
    match i32::from(kind) {
        libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO => true,
        libc::RTM_ADD | libc::RTM_DELETE | libc::RTM_CHANGE => {
            let Some(flags) = msg.get(8..12) else {
                return false;
            };
            let flags = i32::from_ne_bytes(flags.try_into().unwrap());
            flags & (libc::RTF_WASCLONED | libc::RTF_LLINFO) == 0
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn open() -> io::Result<socket2::Socket> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: plain socket creation; the descriptor is owned right away.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_nl is plain data, valid when zeroed.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = (libc::RTMGRP_LINK
        | libc::RTMGRP_IPV4_IFADDR
        | libc::RTMGRP_IPV6_IFADDR
        | libc::RTMGRP_IPV4_ROUTE
        | libc::RTMGRP_IPV6_ROUTE) as u32;
    // SAFETY: addr is a valid sockaddr_nl of the given size.
    let rc = unsafe {
        libc::bind(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket2::Socket::from(fd))
}

/// The socket only joins link, address and route groups.
#[cfg(target_os = "linux")]
fn is_relevant(_msg: &[u8]) -> bool {
    true
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux"
)))]
fn open() -> io::Result<socket2::Socket> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux"
)))]
fn is_relevant(_msg: &[u8]) -> bool {
    false
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::is_relevant;

    /// A routing message header of type `kind`, with `flags` where route
    /// messages carry them.
    fn message(kind: i32, flags: i32) -> Vec<u8> {
        let mut msg = vec![0u8; 92];
        msg[0..2].copy_from_slice(&92u16.to_ne_bytes());
        msg[2] = libc::RTM_VERSION as u8;
        msg[3] = kind as u8;
        msg[8..12].copy_from_slice(&flags.to_ne_bytes());
        msg
    }

    #[test]
    fn address_and_interface_changes_are_relevant() {
        for kind in [libc::RTM_NEWADDR, libc::RTM_DELADDR, libc::RTM_IFINFO] {
            assert!(is_relevant(&message(kind, 0)), "{kind}");
        }
    }

    #[test]
    fn route_changes_are_relevant_unless_cloned() {
        let gateway = libc::RTF_UP | libc::RTF_GATEWAY | libc::RTF_STATIC;
        for kind in [libc::RTM_ADD, libc::RTM_DELETE, libc::RTM_CHANGE] {
            assert!(is_relevant(&message(kind, gateway)), "{kind}");
            assert!(!is_relevant(&message(kind, gateway | libc::RTF_WASCLONED)));
            assert!(!is_relevant(&message(
                kind,
                libc::RTF_UP | libc::RTF_LLINFO
            )));
        }
    }

    #[test]
    fn other_and_truncated_messages_are_not() {
        assert!(!is_relevant(&message(libc::RTM_MISS, 0)));
        assert!(!is_relevant(&message(libc::RTM_GET, 0)));
        assert!(!is_relevant(&[]));
        assert!(!is_relevant(&message(libc::RTM_ADD, 0)[..6]));
    }
}
