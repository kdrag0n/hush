use crate::{
    auth,
    config::ServerRuntimeConfig,
    net::{copy_quic_to_writer, copy_reader_to_quic},
    os::{
        AsyncPty, configure_child_pre_exec, dup_fd, open_pty, process_exit_from_status,
        send_process_group_signal, set_nonblocking, shell_for_user, tty_name,
    },
    protocol::{
        EnvVar, OpenSession, ProcessExit, RemoteSignal, SessionMode, StreamOpen, StreamResponse,
        TermSize, read_frame, write_frame,
    },
};
use anyhow::{Context, Result, bail};
use quinn::{Connection, RecvStream, SendStream};
use std::{
    ffi::CString,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    path::PathBuf,
    process::Stdio,
    sync::Arc,
};
use tokio::process::Command;
use tokio::sync::Semaphore;

struct ConnectionEnv {
    ssh_client: String,
    ssh_connection: String,
}

const AUTH_FAILURE_MESSAGE: &str = "unauthorized";

impl ConnectionEnv {
    fn from_connection(conn: &Connection, server_addr: SocketAddr) -> Self {
        let remote = conn.remote_address();
        let local_ip = conn.local_ip().unwrap_or_else(|| server_addr.ip());
        let local_port = server_addr.port();
        Self {
            ssh_client: format!("{} {} {}", remote.ip(), remote.port(), local_port),
            ssh_connection: format!(
                "{} {} {} {}",
                remote.ip(),
                remote.port(),
                local_ip,
                local_port
            ),
        }
    }
}

pub async fn run_server_session(
    conn: Connection,
    mut session_send: SendStream,
    session_recv: RecvStream,
    request: OpenSession,
    peer_key: ssh_key::PublicKey,
    config: ServerRuntimeConfig,
    server_addr: SocketAddr,
) -> Result<ProcessExit> {
    let connection_env = ConnectionEnv::from_connection(&conn, server_addr);
    let peer_fp = auth::public_key_fingerprint(&peer_key).unwrap_or_else(|_| "unknown".into());
    tracing::info!(user = %request.user, key = %peer_fp, "auth attempt");
    if !config.allow_users.is_empty()
        && !config.allow_users.iter().any(|user| user == &request.user)
    {
        tracing::warn!(
            user = %request.user,
            key = %peer_fp,
            reason = "user is not allowed by server config",
            "auth rejected"
        );
        send_auth_failure(&mut session_send).await;
        bail!(AUTH_FAILURE_MESSAGE);
    }
    if !auth::can_login_as(&request.user) {
        tracing::warn!(
            user = %request.user,
            key = %peer_fp,
            current_user = %auth::current_username(),
            "auth rejected because server is not root and requested user differs"
        );
        send_auth_failure(&mut session_send).await;
        bail!(AUTH_FAILURE_MESSAGE);
    }
    let authorized = auth::is_authorized(
        &request.user,
        &peer_key,
        config.authorized_keys_path.as_deref(),
    );
    match authorized {
        Ok(true) => tracing::info!(user = %request.user, key = %peer_fp, "auth accepted"),
        Ok(false) => {
            tracing::warn!(
                user = %request.user,
                key = %peer_fp,
                "auth rejected because public key is not authorized"
            );
            send_auth_failure(&mut session_send).await;
            bail!(AUTH_FAILURE_MESSAGE);
        }
        Err(err) => {
            tracing::warn!(user = %request.user, key = %peer_fp, reason = %err, "auth rejected");
            send_auth_failure(&mut session_send).await;
            bail!(AUTH_FAILURE_MESSAGE);
        }
    };

    let (resize_tx, resize_rx) = tokio::sync::mpsc::channel(16);
    let (signal_tx, signal_rx) = tokio::sync::mpsc::channel(16);
    let accept_bi_conn = conn.clone();
    let forward_slots = Arc::new(Semaphore::new(config.max_forward_streams_per_connection));
    let accept_task = tokio::spawn(async move {
        while let Ok((send, mut recv)) = accept_bi_conn.accept_bi().await {
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
                    drop(send);
                    drop(recv);
                    tracing::warn!(?other, "unexpected bidirectional stream during session");
                }
            }
        }
    });

    let accept_uni_conn = conn.clone();
    let side_task = tokio::spawn(async move {
        while let Ok(mut recv) = accept_uni_conn.accept_uni().await {
            match read_frame::<StreamOpen>(&mut recv).await {
                Ok(StreamOpen::Resize(size)) => {
                    let _ = resize_tx.send(size).await;
                }
                Ok(StreamOpen::Signal(signal)) => {
                    let _ = signal_tx.send(signal).await;
                }
                Ok(other) => tracing::warn!(?other, "unexpected unidirectional stream"),
                Err(err) => tracing::warn!(%err, "failed to read side stream header"),
            }
        }
    });

    let status = match &request.mode {
        SessionMode::Pty { term, size } => {
            write_frame(&mut session_send, &StreamResponse::SessionReady).await?;
            run_pty(
                &request.user,
                &request.command,
                term,
                size.clone(),
                request.use_shell,
                session_send,
                session_recv,
                resize_rx,
                signal_rx,
                &request.env,
                &connection_env,
            )
            .await
        }
        SessionMode::Pipes => {
            write_frame(&mut session_send, &StreamResponse::SessionReady).await?;
            let mut err_send = conn.open_uni().await?;
            write_frame(&mut err_send, &StreamOpen::SessionStderr).await?;
            run_pipes(
                &request.user,
                &request.command,
                request.use_shell,
                session_send,
                session_recv,
                err_send,
                signal_rx,
                &request.env,
                &connection_env,
            )
            .await
        }
    };
    accept_task.abort();
    side_task.abort();
    match status {
        Ok(status) => {
            send_session_end(&conn, StreamOpen::SessionExitStatus(status)).await?;
            Ok(status)
        }
        Err(err) => {
            let _ = send_session_end(&conn, StreamOpen::SessionError(err.to_string())).await;
            Err(err)
        }
    }
}

async fn send_response_error(send: &mut SendStream, msg: &str) {
    let _ = write_frame(send, &StreamResponse::Error(msg.to_owned())).await;
    let _ = send.finish();
    let _ = send.stopped().await;
}

async fn send_auth_failure(send: &mut SendStream) {
    send_response_error(send, AUTH_FAILURE_MESSAGE).await;
}

async fn send_session_end(conn: &Connection, header: StreamOpen) -> Result<()> {
    let mut send = conn.open_uni().await?;
    write_frame(&mut send, &header).await?;
    send.finish()?;
    let _ = send.stopped().await;
    Ok(())
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
    connection_env: &ConnectionEnv,
) -> Result<ProcessExit> {
    let env = session_env(env, connection_env, None);
    let mut cmd = command_for_user(user, command, false, use_shell, &env)?;
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
    connection_env: &ConnectionEnv,
) -> Result<ProcessExit> {
    let argv = pty_argv(user, command, use_shell)?;
    let pty = open_pty(&size)?;
    let ssh_tty = tty_name(pty.slave.as_raw_fd());
    let env = session_env(env, connection_env, ssh_tty.as_deref());
    set_nonblocking(pty.master.as_raw_fd())?;
    let pty_master = AsyncPty::new(pty.master)?;
    let mut cmd = command_from_argv(&argv)?;
    apply_session_env(&mut cmd, &env);
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
    let resize_pty = pty_master.clone();
    let resize_task = tokio::spawn(async move {
        while let Some(size) = resize_rx.recv().await {
            if let Err(err) = resize_pty.resize(&size) {
                tracing::warn!(%err, "failed to resize pty");
            }
        }
    });
    let in_task = tokio::spawn(copy_quic_to_pty(recv, pty_master.clone()));
    let out_task = tokio::spawn(copy_pty_to_quic(pty_master, send));
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

async fn copy_pty_to_quic(mut pty: AsyncPty, mut send: SendStream) -> Result<()> {
    tokio::io::copy(&mut pty, &mut send).await?;
    send.finish()?;
    // The exit-status side stream is the application-level completion signal.
    // Waiting for QUIC read completion here adds visible logout latency.
    Ok(())
}

async fn copy_quic_to_pty(mut recv: RecvStream, mut pty: AsyncPty) -> Result<()> {
    tokio::io::copy(&mut recv, &mut pty).await?;
    Ok(())
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
    let root_switch = crate::os::is_root() && user != auth::current_username();
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
        if !var.key.contains('\0') && !var.value.contains('\0') {
            cmd.env(&var.key, &var.value);
        }
    }
}

fn session_env(
    client_env: &[EnvVar],
    connection_env: &ConnectionEnv,
    ssh_tty: Option<&str>,
) -> Vec<EnvVar> {
    let mut env = Vec::new();
    for var in client_env {
        if allowed_env_key(&var.key) {
            env.push(var.clone());
        }
    }
    env.push(EnvVar {
        key: "SSH_CLIENT".to_owned(),
        value: connection_env.ssh_client.clone(),
    });
    env.push(EnvVar {
        key: "SSH_CONNECTION".to_owned(),
        value: connection_env.ssh_connection.clone(),
    });
    if let Some(ssh_tty) = ssh_tty {
        env.push(EnvVar {
            key: "SSH_TTY".to_owned(),
            value: ssh_tty.to_owned(),
        });
    }
    env
}

fn allowed_env_key(key: &str) -> bool {
    key == "TERM" || key == "LANG" || key.starts_with("LC_")
}

fn pty_argv(user: &str, command: &[String], use_shell: bool) -> Result<Vec<CString>> {
    let args = pty_argv_strings(
        crate::os::is_root(),
        &auth::current_username(),
        user,
        command,
        use_shell,
    )?;
    args.into_iter()
        .map(|s| CString::new(s).context("argument contains NUL"))
        .collect()
}

fn pty_argv_strings(
    is_root: bool,
    current_user: &str,
    user: &str,
    command: &[String],
    use_shell: bool,
) -> Result<Vec<String>> {
    let root_switch = is_root && user != current_user;
    if is_root && command.is_empty() {
        #[cfg(target_os = "macos")]
        {
            return Ok(vec![
                "login".to_string(),
                "-fp".to_string(),
                user.to_string(),
            ]);
        }
        #[cfg(target_os = "linux")]
        {
            return Ok(vec![
                "login".to_string(),
                "-p".to_string(),
                "-f".to_string(),
                user.to_string(),
            ]);
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            bail!("user switching is unsupported on this platform");
        }
    }

    if root_switch {
        return Ok(vec![
            "su".to_string(),
            "-l".to_string(),
            user.to_string(),
            "-c".to_string(),
            if use_shell {
                shell_words::join(command)
            } else {
                exec_argv_command(command)
            },
        ]);
    }

    let shell = shell_for_user(user)
        .unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()));
    if command.is_empty() {
        Ok(vec![shell])
    } else if !use_shell {
        Ok(command.to_vec())
    } else {
        Ok(vec![shell, "-lc".to_string(), shell_words::join(command)])
    }
}

fn exec_argv_command(command: &[String]) -> String {
    let mut script = String::from("exec");
    for arg in command {
        script.push(' ');
        script.push_str(&shell_words::quote(arg));
    }
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_pty_login_shell_uses_login_even_for_root_user() {
        let argv = pty_argv_strings(true, "root", "root", &[], true).unwrap();

        #[cfg(target_os = "linux")]
        assert_eq!(argv, ["login", "-p", "-f", "root"]);

        #[cfg(target_os = "macos")]
        assert_eq!(argv, ["login", "-fp", "root"]);
    }
}
