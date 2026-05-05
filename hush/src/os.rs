use anyhow::{Result, bail};
use hush_core::protocol::{RemoteSignal, TermSize};
use std::{
    io::IsTerminal,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
};
use tokio::io::unix::AsyncFd;

pub(crate) const STDIN_FD: RawFd = libc::STDIN_FILENO;
pub(crate) const STDOUT_FD: RawFd = libc::STDOUT_FILENO;
pub(crate) const STDERR_FD: RawFd = libc::STDERR_FILENO;

#[derive(Clone)]
pub(crate) struct AsyncStdioFd {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AsyncStdioFd {
    pub(crate) fn duplicate(fd: RawFd) -> Result<Self> {
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            bail!("dup stdio fd failed: {}", std::io::Error::last_os_error());
        }
        set_nonblocking(dup)?;
        Ok(Self {
            fd: Arc::new(AsyncFd::new(unsafe { OwnedFd::from_raw_fd(dup) })?),
        })
    }

    pub(crate) async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), buf)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => continue,
            }
        }
    }

    pub(crate) async fn write_all(&self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| write_fd(inner.get_ref().as_raw_fd(), buf)) {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => buf = &buf[n..],
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        bail!("fcntl(F_GETFL) failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        bail!("fcntl(F_SETFL) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if rc >= 0 {
        Ok(rc as usize)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    let rc = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if rc >= 0 {
        Ok(rc as usize)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match write_fd(fd, buf) {
            Ok(0) => break,
            Ok(n) => buf = &buf[n..],
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

const TERMINAL_CLEANUP_SEQUENCES: &[u8] = concat!(
    "\x1b[<u",  // pop one kitty keyboard protocol stack entry
    "\x1b[=0u", // force kitty keyboard protocol flags to the default
    "\x1b[?9;1000;1001;1002;1003;1005;1006;1015;1016l", // mouse reporting/encodings
    "\x1b[?1004l", // focus reporting
    "\x1b[?2004;2005;2006l", // bracketed paste and paste quoting/literal modes
    "\x1b[?2026l", // synchronized output
    "\x1b[?1l", // application cursor keys
    "\x1b[?5l", // reverse video
    "\x1b[?6l", // origin mode
    "\x1b[?7h", // autowrap
    "\x1b[?12l", // blinking cursor
    "\x1b[?25h", // visible cursor
    "\x1b[?47;1047;1048;1049l", // alternate screen and saved cursor variants
    "\x1b[?66l", // application keypad
    "\x1b[0 q", // default cursor style
    "\x1b[0m",  // default graphics rendition
)
.as_bytes();

fn terminal_cleanup_sequences() -> &'static [u8] {
    TERMINAL_CLEANUP_SEQUENCES
}

fn cleanup_terminal_features() {
    if stdout_is_terminal() {
        let _ = write_all_fd(STDOUT_FD, terminal_cleanup_sequences());
    }
}

pub(crate) fn terminal_size() -> TermSize {
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(STDIN_FD, libc::TIOCGWINSZ, &mut ws);
    }
    TermSize {
        rows: ws.ws_row.max(1),
        cols: ws.ws_col.max(1),
        width_px: ws.ws_xpixel,
        height_px: ws.ws_ypixel,
    }
}

pub(crate) fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

pub(crate) fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

pub(crate) fn self_terminate_with_signal(signal: RemoteSignal) -> ! {
    let signal = signal.as_raw();
    unsafe {
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
        libc::_exit(128 + signal);
    }
}

pub(crate) async fn watch_resize(
    tx: tokio::sync::mpsc::Sender<hush_core::protocol::StreamOpen>,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigwinch = signal(SignalKind::window_change())?;
    while sigwinch.recv().await.is_some() {
        let _ = tx
            .send(hush_core::protocol::StreamOpen::Resize(terminal_size()))
            .await;
    }
    Ok(())
}

pub(crate) async fn watch_signals(
    tx: tokio::sync::mpsc::Sender<hush_core::protocol::StreamOpen>,
    local_tx: tokio::sync::mpsc::Sender<RemoteSignal>,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;
    loop {
        let signal = tokio::select! {
            _ = sigint.recv() => RemoteSignal::SIGINT,
            _ = sigterm.recv() => RemoteSignal::SIGTERM,
            _ = sighup.recv() => RemoteSignal::SIGHUP,
            _ = sigquit.recv() => RemoteSignal::SIGQUIT,
            _ = sigusr1.recv() => RemoteSignal::SIGUSR1,
            _ = sigusr2.recv() => RemoteSignal::SIGUSR2,
        };
        let _ = tx
            .send(hush_core::protocol::StreamOpen::Signal(signal))
            .await;
        let _ = local_tx.send(signal).await;
    }
}

pub(crate) struct RawModeGuard {
    saved: libc::termios,
    active: bool,
}

impl RawModeGuard {
    pub(crate) fn enable_if_terminal() -> Result<Self> {
        if !stdin_is_terminal() {
            return Ok(Self {
                saved: unsafe { std::mem::zeroed() },
                active: false,
            });
        }
        let mut saved = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(STDIN_FD, &mut saved) } != 0 {
            bail!("tcgetattr failed: {}", std::io::Error::last_os_error());
        }
        let mut raw = saved;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(STDIN_FD, libc::TCSANOW, &raw) } != 0 {
            bail!("tcsetattr failed: {}", std::io::Error::last_os_error());
        }
        Ok(Self {
            saved,
            active: true,
        })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            cleanup_terminal_features();
            unsafe {
                libc::tcsetattr(STDIN_FD, libc::TCSANOW, &self.saved);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_cleanup_disables_interactive_modes_without_ris() {
        let seq = terminal_cleanup_sequences();
        assert!(seq.starts_with(b"\x1b[<u\x1b[=0u"));
        assert!(seq_contains(
            seq,
            b"\x1b[?9;1000;1001;1002;1003;1005;1006;1015;1016l"
        ));
        assert!(seq_contains(seq, b"\x1b[?1004l"));
        assert!(seq_contains(seq, b"\x1b[?2004;2005;2006l"));
        assert!(seq_contains(seq, b"\x1b[?2026l"));
        assert!(seq_contains(seq, b"\x1b[?47;1047;1048;1049l"));
        assert!(seq_contains(seq, b"\x1b[?25h"));
        assert!(seq.ends_with(b"\x1b[0 q\x1b[0m"));
        assert!(!seq_contains(seq, b"\x1bc"));
    }

    fn seq_contains(seq: &[u8], needle: &[u8]) -> bool {
        seq.windows(needle.len()).any(|window| window == needle)
    }
}
