use crate::{
    auth,
    config::ServerRuntimeConfig,
    net::{copy_quic_to_writer, copy_reader_to_quic},
    os::{
        AsyncPty, configure_child_pre_exec, dup_fd, open_pty, process_exit_from_status,
        send_process_group_signal, set_nonblocking, shell_for_user, spawn_lock, tty_name,
    },
    priority::{StreamPriority, set_stream_priority},
    protocol::{
        EnvVar, OpenSession, ProcessExit, RemoteSignal, SessionMode, StreamOpen, StreamResponse,
        TermSize, read_frame, write_frame,
    },
};
use anyhow::{Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use std::{
    ffi::CString,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    path::PathBuf,
    process::Stdio,
    sync::Arc,
};
use tokio::process::{Child, Command};
use tokio::sync::Semaphore;

struct ConnectionEnv {
    ssh_client: String,
    ssh_connection: String,
    auth_sock: Option<String>,
}

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
            auth_sock: None,
        }
    }
}

/// Run the session a client requested on its authenticated connection. The
/// session acts as the connection's authenticated user; `request` cannot name
/// one.
pub(crate) async fn run_server_session(
    auth: &crate::server::AuthenticatedConnection,
    mut session_send: SendStream,
    session_recv: RecvStream,
    request: OpenSession,
) -> Result<ProcessExit> {
    let conn = auth.conn().clone();
    let user = auth.user().to_owned();
    let config = auth.config().clone();
    set_stream_priority(&session_send, StreamPriority::Shell);
    let mut connection_env = ConnectionEnv::from_connection(&conn, auth.server_addr());

    let forward_slots = Arc::new(Semaphore::new(config.max_forward_streams_per_connection));
    let agent_forward = if request.forward_agent {
        start_session_agent_forward(&conn, &user, &config, forward_slots.clone())
    } else {
        None
    };
    connection_env.auth_sock = agent_forward
        .as_ref()
        .map(|guard| guard.socket_path().to_string_lossy().into_owned());

    let (resize_tx, resize_rx) = tokio::sync::mpsc::channel(16);
    let (signal_tx, signal_rx) = tokio::sync::mpsc::channel(16);
    let accept_bi_conn = conn.clone();
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
                &user,
                &request.command,
                term,
                size.clone(),
                request.use_shell,
                session_send,
                session_recv,
                resize_rx,
                signal_rx,
                &request.env,
                &request.set_env,
                &connection_env,
            )
            .await
        }
        SessionMode::Pipes => {
            write_frame(&mut session_send, &StreamResponse::SessionReady).await?;
            let mut err_send = conn.open_uni().await?;
            set_stream_priority(&err_send, StreamPriority::Shell);
            write_frame(&mut err_send, &StreamOpen::SessionStderr).await?;
            run_pipes(
                &user,
                &request.command,
                request.use_shell,
                session_send,
                session_recv,
                err_send,
                signal_rx,
                &request.env,
                &request.set_env,
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

/// Set up agent forwarding for an authenticated session. Failures degrade to a
/// session without forwarding rather than aborting it, matching OpenSSH.
fn start_session_agent_forward(
    conn: &Connection,
    user: &str,
    config: &ServerRuntimeConfig,
    slots: Arc<Semaphore>,
) -> Option<crate::agent::AgentForwardGuard> {
    if !config.allow_agent_forwarding {
        tracing::info!(user = %user, "agent forwarding request denied by server config");
        return None;
    }
    let owner = if crate::os::is_root() && user != auth::current_username() {
        match crate::os::uid_gid_for_user(user) {
            Ok(Some(ids)) => Some(ids),
            Ok(None) => {
                tracing::warn!(user = %user, "agent forwarding unavailable: unknown user");
                return None;
            }
            Err(err) => {
                tracing::warn!(user = %user, %err, "agent forwarding unavailable");
                return None;
            }
        }
    } else {
        None
    };
    match crate::agent::start_agent_forward(conn, config.agent_signer.as_deref(), owner, slots) {
        Ok(guard) => Some(guard),
        Err(err) => {
            tracing::warn!(%err, "failed to start agent forwarding");
            None
        }
    }
}

async fn send_session_end(conn: &Connection, header: StreamOpen) -> Result<()> {
    let mut send = conn.open_uni().await?;
    set_stream_priority(&send, StreamPriority::Shell);
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
    set_env: &[EnvVar],
    connection_env: &ConnectionEnv,
) -> Result<ProcessExit> {
    let privileged_switch = crate::os::is_root() && user != auth::current_username();
    let env = session_env(env, set_env, connection_env, None, privileged_switch);
    let mut cmd = command_for_user(user, command, false, use_shell, &env)?;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = {
        let _spawn_guard = spawn_lock();
        cmd.spawn().context("spawn remote command")?
    };
    let child_pid = child.id().context("child pid missing")? as i32;
    let stdin = child.stdin.take().context("child stdin missing")?;
    let stdout = child.stdout.take().context("child stdout missing")?;
    let stderr = child.stderr.take().context("child stderr missing")?;

    let in_task = tokio::spawn(copy_quic_to_writer(recv, stdin));
    let out_task = tokio::spawn(copy_reader_to_quic(stdout, send));
    let err_task = tokio::spawn(copy_reader_to_quic(stderr, err_send));
    let status = wait_for_child(&mut child, child_pid, &mut signal_rx).await?;
    // The client's stdin may never reach EOF (e.g. an idle terminal), and the
    // child can no longer read it anyway.
    in_task.abort();
    let _ = in_task.await;
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
    set_env: &[EnvVar],
    connection_env: &ConnectionEnv,
) -> Result<ProcessExit> {
    let _spawn_guard = spawn_lock();
    let argv = pty_argv(user, command, use_shell)?;
    let pty = open_pty(&size)?;
    let ssh_tty = tty_name(pty.slave.as_raw_fd());
    let privileged_switch = crate::os::is_root() && user != auth::current_username();
    let env = session_env(
        env,
        set_env,
        connection_env,
        ssh_tty.as_deref(),
        privileged_switch,
    );
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
    configure_child_pre_exec(&mut cmd, true);
    let mut child = cmd.spawn().context("spawn remote pty command")?;
    drop(_spawn_guard);
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
    let status = wait_for_child(&mut child, child_pid, &mut signal_rx).await?;
    // Command retains the parent's slave handles for subsequent spawns. Close
    // them before draining output so the master can reach EOF. Keep them until
    // child exit because login may close and reopen the slave during startup.
    drop(cmd);
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
        let mut cmd = Command::new(trusted_system_program("su"));
        cmd.arg("-l").arg(user);
        if !command.is_empty() {
            if use_shell {
                cmd.arg("-c").arg(shell_words::join(command));
            } else {
                cmd.arg("-c").arg(exec_argv_command(command));
            }
        }
        apply_session_env(&mut cmd, env);
        configure_child_pre_exec(&mut cmd, false);
        return Ok(cmd);
    }

    if !use_shell && !command.is_empty() {
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..]);
        apply_session_env(&mut cmd, env);
        configure_child_pre_exec(&mut cmd, false);
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
    configure_child_pre_exec(&mut cmd, false);
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
    set_env: &[EnvVar],
    connection_env: &ConnectionEnv,
    ssh_tty: Option<&str>,
    privileged_switch: bool,
) -> Vec<EnvVar> {
    let mut env = Vec::new();
    for var in client_env {
        if allowed_env_key(&var.key) {
            env.push(var.clone());
        }
    }
    for var in set_env {
        if valid_env_key(&var.key) && (!privileged_switch || allowed_env_key(&var.key)) {
            push_or_replace_env(&mut env, var.clone());
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
    if let Some(auth_sock) = &connection_env.auth_sock {
        push_or_replace_env(
            &mut env,
            EnvVar {
                key: "SSH_AUTH_SOCK".to_owned(),
                value: auth_sock.clone(),
            },
        );
    }
    env
}

fn allowed_env_key(key: &str) -> bool {
    key == "TERM" || key == "LANG" || key.starts_with("LC_")
}

fn valid_env_key(key: &str) -> bool {
    !key.is_empty() && !key.contains('=')
}

fn push_or_replace_env(env: &mut Vec<EnvVar>, var: EnvVar) {
    env.retain(|existing| existing.key != var.key);
    env.push(var);
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
                trusted_system_program("login")
                    .to_string_lossy()
                    .into_owned(),
                "-fp".to_string(),
                user.to_string(),
            ]);
        }
        #[cfg(target_os = "linux")]
        {
            return Ok(vec![
                trusted_system_program("login")
                    .to_string_lossy()
                    .into_owned(),
                "-p".to_string(),
                "-f".to_string(),
                user.to_string(),
            ]);
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            anyhow::bail!("user switching is unsupported on this platform");
        }
    }

    if root_switch {
        return Ok(vec![
            trusted_system_program("su").to_string_lossy().into_owned(),
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

fn trusted_system_program(name: &str) -> PathBuf {
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("/usr/bin").join(name)
}

async fn wait_for_child(
    child: &mut Child,
    child_pid: i32,
    signal_rx: &mut tokio::sync::mpsc::Receiver<RemoteSignal>,
) -> Result<std::process::ExitStatus> {
    loop {
        tokio::select! {
            status = child.wait() => return status.context("wait for remote command"),
            signal = signal_rx.recv() => match signal {
                Some(signal) => send_process_group_signal(child_pid, signal)?,
                None => return terminate_child_group(child, child_pid).await,
            },
        }
    }
}

async fn terminate_child_group(
    child: &mut Child,
    child_pid: i32,
) -> Result<std::process::ExitStatus> {
    let _ = send_process_group_signal(child_pid, RemoteSignal::SIGHUP);
    match tokio::time::timeout(std::time::Duration::from_secs(2), child.wait()).await {
        Ok(status) => status.context("wait for disconnected remote command"),
        Err(_) => {
            let _ = send_process_group_signal(child_pid, RemoteSignal::SIGKILL);
            child.wait().await.context("reap remote command")
        }
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
        assert_eq!(argv, ["/usr/bin/login", "-p", "-f", "root"]);

        #[cfg(target_os = "macos")]
        assert_eq!(argv, ["/usr/bin/login", "-fp", "root"]);
    }

    #[test]
    fn privileged_switch_rejects_arbitrary_set_env() {
        let env = session_env(
            &[],
            &[
                EnvVar {
                    key: "PATH".into(),
                    value: "/tmp".into(),
                },
                EnvVar {
                    key: "LANG".into(),
                    value: "C".into(),
                },
            ],
            &ConnectionEnv {
                ssh_client: "client".into(),
                ssh_connection: "connection".into(),
                auth_sock: None,
            },
            None,
            true,
        );
        assert!(!env.iter().any(|var| var.key == "PATH"));
        assert!(env.iter().any(|var| var.key == "LANG" && var.value == "C"));
    }
}
