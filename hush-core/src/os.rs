use crate::protocol::{ProcessExit, RemoteSignal, TermSize};
use anyhow::{Context, Result, bail};
use std::{
    ffi::{CStr, CString},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::process::ExitStatusExt,
    },
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd},
    process::Command,
};

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn current_username() -> String {
    current_username_from_passwd()
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .unwrap_or_else(|| unsafe { libc::geteuid() }.to_string())
}

fn current_username_from_passwd() -> Option<String> {
    unsafe {
        let uid = libc::geteuid();
        let mut pwd = std::mem::zeroed::<libc::passwd>();
        let mut result = std::ptr::null_mut();
        let size = libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX);
        let mut buf = vec![0 as libc::c_char; if size > 0 { size as usize } else { 16 * 1024 }];
        let rc = libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result);
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned())
    }
}

pub fn home_for_user(user: &str) -> Result<Option<PathBuf>> {
    Ok(passwd_string_for_user(user, |pwd| pwd.pw_dir)?.map(PathBuf::from))
}

pub fn shell_for_user(user: &str) -> Option<String> {
    passwd_string_for_user(user, |pwd| pwd.pw_shell)
        .ok()
        .flatten()
}

fn passwd_string_for_user(
    user: &str,
    field: impl FnOnce(&libc::passwd) -> *mut libc::c_char,
) -> Result<Option<String>> {
    unsafe {
        let c_user = CString::new(user).context("username contains NUL")?;
        let pwd = libc::getpwnam(c_user.as_ptr());
        if pwd.is_null() {
            return Ok(None);
        }
        let ptr = field(&*pwd);
        if ptr.is_null() {
            return Ok(None);
        }
        Ok(Some(CStr::from_ptr(ptr).to_string_lossy().into_owned()))
    }
}

pub fn raise_nofile_soft_limit_to_hard() -> Result<()> {
    let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
        bail!(
            "getrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if limit.rlim_cur >= limit.rlim_max {
        return Ok(());
    }

    limit.rlim_cur = limit.rlim_max;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } < 0 {
        bail!(
            "setrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

pub fn remote_signal_as_raw(signal: RemoteSignal) -> i32 {
    match signal {
        RemoteSignal::SIGABRT => libc::SIGABRT,
        RemoteSignal::SIGALRM => libc::SIGALRM,
        RemoteSignal::SIGFPE => libc::SIGFPE,
        RemoteSignal::SIGHUP => libc::SIGHUP,
        RemoteSignal::SIGILL => libc::SIGILL,
        RemoteSignal::SIGINT => libc::SIGINT,
        RemoteSignal::SIGKILL => libc::SIGKILL,
        RemoteSignal::SIGPIPE => libc::SIGPIPE,
        RemoteSignal::SIGQUIT => libc::SIGQUIT,
        RemoteSignal::SIGSEGV => libc::SIGSEGV,
        RemoteSignal::SIGTERM => libc::SIGTERM,
        RemoteSignal::SIGUSR1 => libc::SIGUSR1,
        RemoteSignal::SIGUSR2 => libc::SIGUSR2,
    }
}

pub fn remote_signal_from_raw(signal: i32) -> Option<RemoteSignal> {
    match signal {
        libc::SIGABRT => Some(RemoteSignal::SIGABRT),
        libc::SIGALRM => Some(RemoteSignal::SIGALRM),
        libc::SIGFPE => Some(RemoteSignal::SIGFPE),
        libc::SIGHUP => Some(RemoteSignal::SIGHUP),
        libc::SIGILL => Some(RemoteSignal::SIGILL),
        libc::SIGINT => Some(RemoteSignal::SIGINT),
        libc::SIGKILL => Some(RemoteSignal::SIGKILL),
        libc::SIGPIPE => Some(RemoteSignal::SIGPIPE),
        libc::SIGQUIT => Some(RemoteSignal::SIGQUIT),
        libc::SIGSEGV => Some(RemoteSignal::SIGSEGV),
        libc::SIGTERM => Some(RemoteSignal::SIGTERM),
        libc::SIGUSR1 => Some(RemoteSignal::SIGUSR1),
        libc::SIGUSR2 => Some(RemoteSignal::SIGUSR2),
        _ => None,
    }
}

pub fn process_exit_from_status(status: std::process::ExitStatus) -> ProcessExit {
    if let Some(code) = status.code() {
        ProcessExit::Code(code)
    } else if let Some(signal) = status.signal().and_then(remote_signal_from_raw) {
        ProcessExit::Signal(signal)
    } else {
        ProcessExit::Code(255)
    }
}

pub fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        bail!("fcntl(F_GETFL) failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        bail!("fcntl(F_SETFL) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_cloexec(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        bail!("fcntl(F_GETFD) failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        bail!("fcntl(F_SETFD) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_fd(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    let rc = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if rc >= 0 {
        Ok(rc as usize)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[derive(Clone)]
pub struct AsyncPty {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AsyncPty {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            fd: Arc::new(AsyncFd::new(fd)?),
        })
    }

    pub fn resize(&self, size: &TermSize) -> Result<()> {
        set_winsize(self.fd.get_ref().as_raw_fd(), size)
    }
}

impl AsyncRead for AsyncPty {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = std::task::ready!(self.fd.poll_read_ready(cx))?;
            let result = guard.try_io(|inner| {
                let unfilled = buf.initialize_unfilled();
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if n >= 0 {
                    Ok(n as usize)
                } else {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EIO) {
                        Ok(0)
                    } else {
                        Err(err)
                    }
                }
            });

            match result {
                Ok(Ok(0)) => return Poll::Ready(Ok(())),
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncPty {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = std::task::ready!(self.fd.poll_write_ready(cx))?;
            let result = guard.try_io(|inner| write_fd(inner.get_ref().as_raw_fd(), data));
            match result {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct OpenPty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

pub fn open_pty(size: &TermSize) -> Result<OpenPty> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.width_px,
        ws_ypixel: size.height_px,
    };
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut winsize,
        )
    };
    if rc < 0 {
        bail!("openpty failed: {}", std::io::Error::last_os_error());
    }
    let pty = OpenPty {
        master: unsafe { OwnedFd::from_raw_fd(master) },
        slave: unsafe { OwnedFd::from_raw_fd(slave) },
    };
    set_cloexec(pty.master.as_raw_fd())?;
    set_cloexec(pty.slave.as_raw_fd())?;
    configure_pty_slave(pty.slave.as_raw_fd())?;
    Ok(pty)
}

fn configure_pty_slave(fd: RawFd) -> Result<()> {
    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut termios) } < 0 {
        bail!(
            "tcgetattr pty slave failed: {}",
            std::io::Error::last_os_error()
        );
    }
    termios.c_iflag |= libc::BRKINT | libc::ICRNL | libc::IXON;
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        termios.c_iflag |= libc::IUTF8;
    }
    termios.c_oflag |= libc::OPOST | libc::ONLCR;
    termios.c_cflag |= libc::CREAD | libc::CS8;
    termios.c_lflag |=
        libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ICANON | libc::IEXTEN | libc::ISIG;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } < 0 {
        bail!(
            "tcsetattr pty slave failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

pub fn tty_name(fd: RawFd) -> Option<String> {
    let mut buf = [0 as libc::c_char; 1024];
    if unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) } != 0 {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn set_winsize(fd: RawFd, size: &TermSize) -> Result<()> {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.width_px,
        ws_ypixel: size.height_px,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) } < 0 {
        bail!(
            "ioctl(TIOCSWINSZ) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

pub fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        bail!("dup failed: {}", std::io::Error::last_os_error());
    }
    Ok(dup)
}

pub fn configure_child_pre_exec(cmd: &mut Command, controlling_tty: bool, term: Option<String>) {
    let term = term.map(|term| CString::new(term).expect("TERM contains NUL"));
    let term_key = CString::new("TERM").expect("TERM key contains NUL");
    unsafe {
        cmd.pre_exec(move || {
            reset_child_signal_state()?;
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if controlling_tty && libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(term) = &term {
                if libc::setenv(term_key.as_ptr(), term.as_ptr(), 1) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn reset_child_signal_state() -> std::io::Result<()> {
    unsafe {
        for signo in [
            libc::SIGCHLD,
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGALRM,
            libc::SIGPIPE,
            libc::SIGTTIN,
            libc::SIGTTOU,
        ] {
            if libc::signal(signo, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
        }
        let mut empty_set = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut empty_set);
        if libc::sigprocmask(libc::SIG_SETMASK, &empty_set, std::ptr::null_mut()) == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn send_process_group_signal(pid: i32, signal: RemoteSignal) -> Result<()> {
    let rc = unsafe { libc::kill(-pid, remote_signal_as_raw(signal)) };
    if rc < 0 {
        bail!(
            "kill process group failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}
