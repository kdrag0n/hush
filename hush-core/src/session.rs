use crate::{
    auth,
    config::ServerRuntimeConfig,
    net::{copy_quic_to_writer, copy_reader_to_quic},
    protocol::{
        ControlRequest, ControlResponse, EnvVar, OpenSession, ProcessExit, RemoteSignal,
        SessionMode, StreamOpen, TermSize, read_frame, write_frame,
    },
};
use anyhow::{Context, Result, bail};
use quinn::{Connection, RecvStream, SendStream};
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
};
use tokio::sync::Semaphore;
use tokio::{io::unix::AsyncFd, process::Command};

pub async fn run_server_session(
    conn: Connection,
    mut control_send: SendStream,
    mut control_recv: RecvStream,
    request: OpenSession,
    peer_key: ssh_key::PublicKey,
    config: ServerRuntimeConfig,
) -> Result<ProcessExit> {
    let peer_fp = auth::public_key_fingerprint(&peer_key).unwrap_or_else(|_| "unknown".into());
    tracing::info!(user = %request.user, key = %peer_fp, "auth attempt");
    if !config.allow_users.is_empty()
        && !config.allow_users.iter().any(|user| user == &request.user)
    {
        let msg = format!("user {} is not allowed by server config", request.user);
        tracing::warn!(user = %request.user, key = %peer_fp, reason = %msg, "auth rejected");
        send_control_error(&mut control_send, &msg).await;
        bail!("{msg}");
    }
    if !auth::can_login_as(&request.user) {
        let msg = format!(
            "server is not root; only {} may log in",
            auth::current_username()
        );
        tracing::warn!(user = %request.user, key = %peer_fp, reason = %msg, "auth rejected");
        send_control_error(&mut control_send, &msg).await;
        bail!("{msg}");
    }
    let authorized = auth::is_authorized(
        &request.user,
        &peer_key,
        config.authorized_keys_path.as_deref(),
    );
    match authorized {
        Ok(true) => tracing::info!(user = %request.user, key = %peer_fp, "auth accepted"),
        Ok(false) => {
            let msg = format!(
                "public key {peer_fp} is not authorized for {}",
                request.user
            );
            tracing::warn!(user = %request.user, key = %peer_fp, reason = %msg, "auth rejected");
            send_control_error(&mut control_send, &msg).await;
            bail!("{msg}");
        }
        Err(err) => {
            tracing::warn!(user = %request.user, key = %peer_fp, reason = %err, "auth rejected");
            send_control_error(&mut control_send, &err.to_string()).await;
            return Err(err);
        }
    };

    let (stream_tx, mut stream_rx) = tokio::sync::mpsc::channel(4);
    let (resize_tx, resize_rx) = tokio::sync::mpsc::channel(16);
    let (signal_tx, signal_rx) = tokio::sync::mpsc::channel(16);
    let accept_conn = conn.clone();
    let forward_slots = Arc::new(Semaphore::new(config.max_forward_streams_per_connection));
    let accept_task = tokio::spawn(async move {
        while let Ok((send, mut recv)) = accept_conn.accept_bi().await {
            let header = match read_frame::<StreamOpen>(&mut recv).await {
                Ok(header) => header,
                Err(err) => {
                    tracing::warn!(%err, "failed to read stream header");
                    continue;
                }
            };
            match header {
                StreamOpen::LocalTcpForward { target } if config.allow_tcp_forwarding => {
                    let Ok(permit) = forward_slots.clone().try_acquire_owned() else {
                        tracing::warn!(
                            "rejected local forward stream because forward stream limit is reached"
                        );
                        continue;
                    };
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) =
                            crate::forwarding::serve_local_forward_stream(target, send, recv).await
                        {
                            tracing::warn!(%err, "local forward stream failed");
                        }
                    });
                }
                StreamOpen::LocalTcpForward { .. } => {
                    tracing::warn!("rejected local forward stream because forwarding is disabled");
                }
                other => {
                    if stream_tx.send((other, send, recv)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let control_task = tokio::spawn(async move {
        while let Ok(request) = read_frame::<ControlRequest>(&mut control_recv).await {
            match request {
                ControlRequest::Resize(size) => {
                    let _ = resize_tx.send(size).await;
                }
                ControlRequest::Signal(signal) => {
                    let _ = signal_tx.send(signal).await;
                }
                ControlRequest::Close => break,
                ControlRequest::OpenSession(_) | ControlRequest::OpenRemoteForward(_) => {}
            }
        }
    });

    let mut resize_rx = Some(resize_rx);
    let mut signal_rx = Some(signal_rx);
    while let Some((header, send, recv)) = stream_rx.recv().await {
        match (&request.mode, header) {
            (SessionMode::Pty { term, size }, StreamOpen::SessionPtyData) => {
                write_frame(&mut control_send, &ControlResponse::SessionReady).await?;
                let status = match run_pty(
                    &request.user,
                    &request.command,
                    term,
                    size.clone(),
                    request.use_shell,
                    send,
                    recv,
                    resize_rx.take().context("resize channel already used")?,
                    signal_rx.take().context("signal channel already used")?,
                    &request.env,
                )
                .await
                {
                    Ok(status) => status,
                    Err(err) => {
                        send_control_error(&mut control_send, &err.to_string()).await;
                        return Err(err);
                    }
                };
                write_frame(&mut control_send, &ControlResponse::ExitStatus(status)).await?;
                control_send.finish()?;
                let _ = control_send.stopped().await;
                accept_task.abort();
                control_task.abort();
                return Ok(status);
            }
            (SessionMode::Pipes, StreamOpen::SessionStdIo) => {
                write_frame(&mut control_send, &ControlResponse::SessionReady).await?;
                let mut err_send = conn.open_uni().await?;
                write_frame(&mut err_send, &StreamOpen::SessionStderr).await?;
                let status = match run_pipes(
                    &request.user,
                    &request.command,
                    request.use_shell,
                    send,
                    recv,
                    err_send,
                    signal_rx.take().context("signal channel already used")?,
                    &request.env,
                )
                .await
                {
                    Ok(status) => status,
                    Err(err) => {
                        send_control_error(&mut control_send, &err.to_string()).await;
                        return Err(err);
                    }
                };
                write_frame(&mut control_send, &ControlResponse::ExitStatus(status)).await?;
                control_send.finish()?;
                let _ = control_send.stopped().await;
                accept_task.abort();
                control_task.abort();
                return Ok(status);
            }
            _ => bail!("unexpected stream for requested session mode"),
        }
    }
    bail!("connection closed before session stream opened")
}

async fn send_control_error(send: &mut SendStream, msg: &str) {
    let _ = write_frame(send, &ControlResponse::Error(msg.to_owned())).await;
    let _ = send.finish();
    let _ = send.stopped().await;
}

async fn run_pipes(
    user: &str,
    command: &[String],
    use_shell: bool,
    send: SendStream,
    recv: RecvStream,
    err_send: SendStream,
    mut signal_rx: tokio::sync::mpsc::Receiver<RemoteSignal>,
    env: &[EnvVar],
) -> Result<ProcessExit> {
    let mut cmd = command_for_user(user, command, false, use_shell, env)?;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawn remote command")?;
    let child_pid = child.id().context("child pid missing")? as i32;
    let stdin = child.stdin.take().context("child stdin missing")?;
    let stdout = child.stdout.take().context("child stdout missing")?;
    let stderr = child.stderr.take().context("child stderr missing")?;

    let in_task = tokio::spawn(copy_quic_to_writer(recv, stdin));
    let out_task = tokio::spawn(copy_reader_to_quic(stdout, send));
    let err_task = tokio::spawn(copy_reader_to_quic(stderr, err_send));
    let status = loop {
        tokio::select! {
            status = child.wait() => break status.context("wait for remote command")?,
            Some(signal) = signal_rx.recv() => send_process_group_signal(child_pid, signal)?,
        }
    };
    in_task.await.ok();
    out_task.await.ok();
    err_task.await.ok();
    Ok(process_exit_from_status(status))
}

async fn run_pty(
    user: &str,
    command: &[String],
    term: &str,
    size: TermSize,
    use_shell: bool,
    send: SendStream,
    recv: RecvStream,
    mut resize_rx: tokio::sync::mpsc::Receiver<TermSize>,
    mut signal_rx: tokio::sync::mpsc::Receiver<RemoteSignal>,
    env: &[EnvVar],
) -> Result<ProcessExit> {
    let argv = pty_argv(user, command, use_shell)?;
    let pty = open_pty(&size)?;
    set_nonblocking(pty.master.as_raw_fd())?;
    let fd = Arc::new(AsyncFd::new(pty.master)?);
    let mut cmd = command_from_argv(&argv)?;
    apply_session_env(&mut cmd, env);
    cmd.env("TERM", term);
    let stdin_fd = dup_fd(pty.slave.as_raw_fd())?;
    let stdout_fd = dup_fd(pty.slave.as_raw_fd())?;
    let stderr_fd = pty.slave.into_raw_fd();
    cmd.stdin(unsafe { Stdio::from_raw_fd(stdin_fd) })
        .stdout(unsafe { Stdio::from_raw_fd(stdout_fd) })
        .stderr(unsafe { Stdio::from_raw_fd(stderr_fd) });
    configure_child_pre_exec(&mut cmd, true, Some(term.to_owned()));
    let mut child = cmd.spawn().context("spawn remote pty command")?;
    let child_pid = child.id().context("child pid missing")? as i32;
    let resize_fd = fd.clone();
    let resize_task = tokio::spawn(async move {
        while let Some(size) = resize_rx.recv().await {
            if let Err(err) = set_winsize(resize_fd.get_ref().as_raw_fd(), &size) {
                tracing::warn!(%err, "failed to resize pty");
            }
        }
    });
    let in_task = tokio::spawn(copy_quic_to_pty(recv, fd.clone()));
    let out_task = tokio::spawn(copy_pty_to_quic(fd, send));
    let status = loop {
        tokio::select! {
            status = child.wait() => break status.context("wait for remote pty command")?,
            Some(signal) = signal_rx.recv() => send_process_group_signal(child_pid, signal)?,
        }
    };
    resize_task.abort();
    in_task.abort();
    let _ = in_task.await;
    match tokio::time::timeout(std::time::Duration::from_secs(2), out_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(err))) => tracing::warn!(%err, "pty output copy failed"),
        Ok(Err(err)) => tracing::warn!(%err, "pty output task failed"),
        Err(_) => tracing::warn!("pty output copy timed out"),
    }
    Ok(process_exit_from_status(status))
}

async fn copy_pty_to_quic(fd: Arc<AsyncFd<OwnedFd>>, mut send: SendStream) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), &mut buf)) {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => send.write_all(&buf[..n]).await?,
            Ok(Err(err)) if err.raw_os_error() == Some(libc::EIO) => break,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => continue,
        }
    }
    send.finish()?;
    let _ = send.stopped().await;
    Ok(())
}

async fn copy_quic_to_pty(mut recv: RecvStream, fd: Arc<AsyncFd<OwnedFd>>) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    loop {
        let n = recv.read(&mut buf).await?.unwrap_or(0);
        if n == 0 {
            return Ok(());
        }
        let mut written = 0;
        while written < n {
            let mut guard = fd.writable().await?;
            match guard.try_io(|inner| write_fd(inner.get_ref().as_raw_fd(), &buf[written..n])) {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(m)) => written += m,
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => continue,
            }
        }
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

fn process_exit_from_status(status: std::process::ExitStatus) -> ProcessExit {
    if let Some(code) = status.code() {
        ProcessExit::Code(code)
    } else if let Some(signal) = status.signal().and_then(RemoteSignal::from_raw) {
        ProcessExit::Signal(signal)
    } else {
        ProcessExit::Code(255)
    }
}

struct OpenPty {
    master: OwnedFd,
    slave: OwnedFd,
}

fn open_pty(size: &TermSize) -> Result<OpenPty> {
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

fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        bail!("dup failed: {}", std::io::Error::last_os_error());
    }
    Ok(dup)
}

fn command_from_argv(argv: &[CString]) -> Result<Command> {
    let program = argv.first().context("empty argv")?.to_string_lossy();
    let mut cmd = Command::new(program.as_ref());
    for arg in &argv[1..] {
        cmd.arg(arg.to_string_lossy().as_ref());
    }
    Ok(cmd)
}

fn command_for_user(
    user: &str,
    command: &[String],
    login_shell: bool,
    use_shell: bool,
    env: &[EnvVar],
) -> Result<Command> {
    let root_switch = unsafe { libc::geteuid() == 0 } && user != auth::current_username();
    if root_switch {
        let mut cmd = Command::new("su");
        cmd.arg("-l").arg(user);
        if !command.is_empty() {
            if use_shell {
                cmd.arg("-c").arg(shell_words::join(command));
            } else {
                cmd.arg("-c").arg(exec_argv_command(command));
            }
        }
        apply_session_env(&mut cmd, env);
        configure_child_pre_exec(&mut cmd, false, None);
        return Ok(cmd);
    }

    if !use_shell && !command.is_empty() {
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..]);
        apply_session_env(&mut cmd, env);
        configure_child_pre_exec(&mut cmd, false, None);
        return Ok(cmd);
    }

    let shell = shell_for_user(user)
        .unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()));
    let mut cmd = Command::new(&shell);
    if command.is_empty() {
        if login_shell {
            let argv0 = format!(
                "-{}",
                PathBuf::from(&shell)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            cmd.arg0(argv0);
        }
    } else {
        cmd.arg("-lc").arg(shell_words::join(command));
    }
    apply_session_env(&mut cmd, env);
    configure_child_pre_exec(&mut cmd, false, None);
    Ok(cmd)
}

fn apply_session_env(cmd: &mut Command, env: &[EnvVar]) {
    for var in env {
        if allowed_env_key(&var.key) && !var.key.contains('\0') && !var.value.contains('\0') {
            cmd.env(&var.key, &var.value);
        }
    }
}

fn allowed_env_key(key: &str) -> bool {
    key == "TERM" || key == "LANG" || key.starts_with("LC_")
}

fn configure_child_pre_exec(cmd: &mut Command, controlling_tty: bool, term: Option<String>) {
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

fn pty_argv(user: &str, command: &[String], use_shell: bool) -> Result<Vec<CString>> {
    let root_switch = unsafe { libc::geteuid() == 0 } && user != auth::current_username();
    let args = if root_switch && command.is_empty() {
        #[cfg(target_os = "macos")]
        let args = vec!["login".to_string(), "-fp".to_string(), user.to_string()];
        #[cfg(target_os = "linux")]
        let args = vec![
            "login".to_string(),
            "-p".to_string(),
            "-f".to_string(),
            user.to_string(),
        ];
        args
    } else if root_switch {
        vec![
            "su".to_string(),
            "-l".to_string(),
            user.to_string(),
            "-c".to_string(),
            if use_shell {
                shell_words::join(command)
            } else {
                exec_argv_command(command)
            },
        ]
    } else {
        let shell = shell_for_user(user)
            .unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()));
        if command.is_empty() {
            vec![shell]
        } else if !use_shell {
            command.to_vec()
        } else {
            vec![shell, "-lc".to_string(), shell_words::join(command)]
        }
    };
    args.into_iter()
        .map(|s| CString::new(s).context("argument contains NUL"))
        .collect()
}

fn exec_argv_command(command: &[String]) -> String {
    let mut script = String::from("exec");
    for arg in command {
        script.push(' ');
        script.push_str(&shell_words::quote(arg));
    }
    script
}

fn send_process_group_signal(pid: i32, signal: RemoteSignal) -> Result<()> {
    let rc = unsafe { libc::kill(-pid, signal.as_raw()) };
    if rc < 0 {
        bail!(
            "kill process group failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn shell_for_user(user: &str) -> Option<String> {
    unsafe {
        let c_user = CString::new(user).ok()?;
        let pwd = libc::getpwnam(c_user.as_ptr());
        if pwd.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr((*pwd).pw_shell)
                .to_string_lossy()
                .into_owned(),
        )
    }
}
