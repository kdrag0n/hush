use std::{
    fs,
    net::{TcpListener, UdpSocket},
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

static BUILD_SERVER: OnceLock<()> = OnceLock::new();

struct TestEnv {
    temp: tempfile::TempDir,
    home: PathBuf,
    data: PathBuf,
    authorized_keys: PathBuf,
    server: Option<Child>,
    port: u16,
}

impl TestEnv {
    fn new() -> Self {
        ensure_server_built();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let ssh = home.join(".ssh");
        let data = temp.path().join("data");
        fs::create_dir_all(&ssh).unwrap();
        fs::create_dir_all(&data).unwrap();
        let key = ssh.join("id_ed25519");
        run(Command::new("ssh-keygen")
            .arg("-q")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&key)
            .arg("-C")
            .arg("hush-test"));
        let authorized_keys = temp.path().join("authorized_keys");
        fs::copy(ssh.join("id_ed25519.pub"), &authorized_keys).unwrap();
        Self {
            temp,
            home,
            data,
            authorized_keys,
            server: None,
            port: free_udp_port(),
        }
    }

    fn start_server(&mut self) {
        self.start_server_with(&[]);
    }

    fn start_server_with(&mut self, extra_args: &[&str]) {
        let child = Command::new(server_bin())
            .env_remove("SSH_AUTH_SOCK")
            .arg("--data-dir")
            .arg(&self.data)
            .arg("--authorized-keys")
            .arg(&self.authorized_keys)
            .arg("-l")
            .arg(format!("127.0.0.1:{}", self.port))
            .args(extra_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.server = Some(child);
        thread::sleep(Duration::from_millis(350));
    }

    fn start_server_from_config(&mut self) {
        let server_dir = self.data.join("server");
        fs::create_dir_all(&server_dir).unwrap();
        let authorized_keys = self.authorized_keys.to_str().unwrap();
        fs::write(
            server_dir.join("config.toml"),
            format!(
                "listen = \"127.0.0.1:{}\"\nauthorized_keys_path = {authorized_keys:?}\n",
                self.port
            ),
        )
        .unwrap();
        let child = Command::new(server_bin())
            .arg("--data-dir")
            .arg(&self.data)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.server = Some(child);
        thread::sleep(Duration::from_millis(350));
    }

    fn stop_server(&mut self) {
        if let Some(mut server) = self.server.take() {
            let _ = server.kill();
            let _ = server.wait();
        }
    }

    fn hush(&self) -> Command {
        let mut cmd = Command::new(hush_bin());
        cmd.env("HOME", &self.home)
            .env_remove("SSH_AUTH_SOCK")
            .arg("--data-dir")
            .arg(self.home.join(".hush"))
            .arg("-p")
            .arg(self.port.to_string());
        cmd
    }

    fn hcp(&self) -> Command {
        let mut cmd = Command::new(hush_bin());
        cmd.arg("cp")
            .env("HOME", &self.home)
            .env_remove("SSH_AUTH_SOCK")
            .arg("--data-dir")
            .arg(self.home.join(".hush"))
            .arg("-p")
            .arg(self.port.to_string());
        cmd
    }

    fn hcp_argv0(&self) -> Command {
        let hcp = self.temp.path().join("hcp");
        #[cfg(unix)]
        std::os::unix::fs::symlink(hush_bin(), &hcp).unwrap();
        let mut cmd = Command::new(hcp);
        cmd.env("HOME", &self.home)
            .env_remove("SSH_AUTH_SOCK")
            .arg("--data-dir")
            .arg(self.home.join(".hush"))
            .arg("-p")
            .arg(self.port.to_string());
        cmd
    }

    fn target(&self) -> String {
        self.target_for_host("127.0.0.1")
    }

    fn target_for_host(&self, host: &str) -> String {
        format!("{}@{host}", hush_core::auth::current_username())
    }

    /// Generate an ECDSA identity of the given curve size, authorize its public
    /// key, and return the private key path.
    fn ecdsa_identity(&self, bits: u32) -> PathBuf {
        let key = self.home.join(".ssh").join(format!("id_ecdsa{bits}"));
        run(Command::new("ssh-keygen")
            .arg("-q")
            .arg("-t")
            .arg("ecdsa")
            .arg("-b")
            .arg(bits.to_string())
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&key)
            .arg("-C")
            .arg("hush-test"));
        let pubkey = fs::read_to_string(key.with_extension("pub")).unwrap();
        let mut authorized = fs::read_to_string(&self.authorized_keys).unwrap_or_default();
        if !authorized.ends_with('\n') && !authorized.is_empty() {
            authorized.push('\n');
        }
        authorized.push_str(&pubkey);
        fs::write(&self.authorized_keys, authorized).unwrap();
        key
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(mut server) = self.server.take() {
            let _ = server.kill();
            let _ = server.wait();
        }
    }
}

#[test]
fn propagates_exit_status() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("echo exit-status-ok; exit 7")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "exit-status-ok"
    );
}

#[test]
fn server_uses_server_subdir_for_config_and_host_key() {
    let mut env = TestEnv::new();
    env.start_server_from_config();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("printf server-subdir-ok")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "server-subdir-ok");
    assert!(env.data.join("server/host_cert.der").exists());
    assert!(env.data.join("server/host_key.der").exists());
    assert!(!env.data.join("host_cert.der").exists());
    assert!(!env.data.join("host_key.der").exists());
}

#[test]
fn forced_pty_works() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-t")
        .arg(env.target())
        .arg("--")
        .arg("/bin/echo")
        .arg("pty-ok")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("pty-ok"));
}

#[test]
fn domain_name_target_works() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target_for_host("localhost"))
        .arg("--")
        .arg("/bin/echo")
        .arg("domain-ok")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "domain-ok");
}

#[test]
fn stateless_reset_after_server_restart_closes_client() {
    use std::io::{Read, Write};

    let mut env = TestEnv::new();
    env.start_server();
    let mut client = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    client
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"before\n")
        .unwrap();
    let mut before = [0u8; 7];
    client
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut before)
        .unwrap();
    assert_eq!(&before, b"before\n");

    env.stop_server();
    env.start_server();
    let _ = client.stdin.as_mut().unwrap().write_all(b"after\n");
    let status = wait_for_child_exit(&mut client, Duration::from_secs(5)).unwrap_or_else(|| {
        let _ = client.kill();
        let _ = client.wait();
        panic!("client did not exit after server restart");
    });
    assert!(!status.success(), "{status:?}");
}

#[test]
fn no_shell_preserves_argv() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg("-S")
        .arg(env.target())
        .arg("--")
        .arg("/bin/echo")
        .arg("$HOME")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "$HOME");
}

#[test]
fn selected_environment_is_propagated() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .env("LANG", "C.UTF-8")
        .env("TERM", "vt100")
        .arg("-t")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-lc")
        .arg("printf '%s|%s' \"$TERM\" \"$LANG\"")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "vt100|C.UTF-8");
}

#[test]
fn ssh_config_set_env_overrides_selected_environment() {
    let mut env = TestEnv::new();
    env.start_server();
    fs::write(
        env.home.join(".ssh/config"),
        format!(
            "Host edge\n    HostName 127.0.0.1\n    User {}\n    SetEnv TERM=xterm-hush LANG=C.UTF-8 HUSH_SETENV=ok\n",
            hush_core::auth::current_username()
        ),
    )
    .unwrap();
    let out = env
        .hush()
        .env("LANG", "local.UTF-8")
        .env("TERM", "vt100")
        .arg("-t")
        .arg("edge")
        .arg("--")
        .arg("/bin/sh")
        .arg("-lc")
        .arg("printf '%s|%s|%s' \"$TERM\" \"$LANG\" \"$HUSH_SETENV\"")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "xterm-hush|C.UTF-8|ok"
    );
}

#[test]
fn openssh_connection_environment_is_set() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("printf '%s\n%s\n%s\n' \"$SSH_CLIENT\" \"$SSH_CONNECTION\" \"${SSH_TTY-unset}\"")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{out:?}");
    let client: Vec<_> = lines[0].split_whitespace().collect();
    assert_eq!(client.len(), 3, "{out:?}");
    assert_eq!(client[0], "127.0.0.1", "{out:?}");
    assert_eq!(client[2], env.port.to_string(), "{out:?}");
    let connection: Vec<_> = lines[1].split_whitespace().collect();
    assert_eq!(connection.len(), 4, "{out:?}");
    assert_eq!(connection[0], "127.0.0.1", "{out:?}");
    assert_eq!(connection[1], client[1], "{out:?}");
    assert_eq!(connection[2], "127.0.0.1", "{out:?}");
    assert_eq!(connection[3], env.port.to_string(), "{out:?}");
    assert_eq!(lines[2], "unset", "{out:?}");
}

#[test]
fn hcp_uploads_file_with_zstd() {
    let mut env = TestEnv::new();
    env.start_server();
    let source = env.temp.path().join("local.txt");
    let destination = env.temp.path().join("remote.txt");
    fs::write(&source, "upload-ok\n").unwrap();

    let out = env
        .hcp()
        .arg(&source)
        .arg(format!("{}:{}", env.target(), destination.display()))
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read_to_string(destination).unwrap(), "upload-ok\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("upload local.txt"), "{out:?}");
    assert!(stderr.contains("done"), "{out:?}");
}

#[test]
fn hcp_downloads_file_without_compression() {
    let mut env = TestEnv::new();
    env.start_server();
    let source = env.temp.path().join("remote.txt");
    let destination = env.temp.path().join("local.txt");
    fs::write(&source, "download-ok\n").unwrap();

    let out = env
        .hcp()
        .arg("-C")
        .arg(format!("{}:{}", env.target(), source.display()))
        .arg(&destination)
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read_to_string(destination).unwrap(), "download-ok\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("download remote.txt"), "{out:?}");
    assert!(stderr.contains("done"), "{out:?}");
}

#[cfg(unix)]
#[test]
fn hcp_dispatches_from_argv0() {
    let mut env = TestEnv::new();
    env.start_server();
    let source = env.temp.path().join("argv0-remote.txt");
    let destination = env.temp.path().join("argv0-local.txt");
    fs::write(&source, "argv0-ok\n").unwrap();

    let out = env
        .hcp_argv0()
        .arg(format!("{}:{}", env.target(), source.display()))
        .arg(&destination)
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read_to_string(destination).unwrap(), "argv0-ok\n");
}

#[test]
fn openssh_tty_environment_is_set_for_pty() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-t")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-lc")
        .arg("printf '%s' \"$SSH_TTY\"")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("/dev/"),
        "{out:?}"
    );
}

#[test]
fn remote_signal_exit_is_reemitted_by_client() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("kill -TERM $$")
        .output()
        .unwrap();
    assert_eq!(out.status.signal(), Some(libc::SIGTERM), "{out:?}");
}

#[test]
fn non_pty_signal_forwarding_propagates_interrupt() {
    let mut env = TestEnv::new();
    env.start_server();
    let child = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("trap 'echo interrupted; exit 42' INT; while true; do sleep 1; done")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(1));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(42), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("interrupted"));
}

#[test]
fn non_pty_signal_forwarding_propagates_terminate() {
    let mut env = TestEnv::new();
    env.start_server();
    let child = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("trap 'echo terminated; exit 43' TERM; while true; do sleep 1; done")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(1));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(43), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("terminated"));
}

#[test]
fn non_pty_sigterm_times_out_if_remote_does_not_exit() {
    let mut env = TestEnv::new();
    env.start_server();
    let child = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("trap '' TERM; sleep 5")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(1));
    let start = Instant::now();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.signal(), Some(libc::SIGTERM), "{out:?}");
    assert!(start.elapsed() < Duration::from_secs(3), "{out:?}");
}

#[test]
fn local_forwarding_carries_tcp() {
    let mut env = TestEnv::new();
    env.start_server();
    let web = TcpListener::bind("127.0.0.1:0").unwrap();
    let web_port = web.local_addr().unwrap().port();
    let web_thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = web.accept().unwrap();
            use std::io::{Read, Write};
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nforward-ok")
                .unwrap();
        }
    });
    let local_port = free_tcp_port();
    let mut client = env
        .hush()
        .arg("-T")
        .arg("-L")
        .arg(format!("{local_port}:127.0.0.1:{web_port}"))
        .arg(env.target())
        .arg("--")
        .arg("/bin/sleep")
        .arg("3")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_tcp(local_port);
    let body = http_get(local_port);
    let _ = client.wait();
    let _ = web_thread.join();
    assert_eq!(body, "forward-ok");
}

#[test]
fn remote_forwarding_carries_tcp() {
    let mut env = TestEnv::new();
    env.start_server();
    let web = TcpListener::bind("127.0.0.1:0").unwrap();
    let web_port = web.local_addr().unwrap().port();
    let web_thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = web.accept().unwrap();
            use std::io::{Read, Write};
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nremote-forward-ok")
                .unwrap();
        }
    });
    let remote_port = free_tcp_port();
    let mut client = env
        .hush()
        .arg("-T")
        .arg("-R")
        .arg(format!("{remote_port}:127.0.0.1:{web_port}"))
        .arg(env.target())
        .arg("--")
        .arg("/bin/sleep")
        .arg("3")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_tcp(remote_port);
    let body = http_get(remote_port);
    let _ = client.wait();
    let _ = web_thread.join();
    assert_eq!(body, "remote-forward-ok");
}

#[test]
fn authorized_keys_options_are_rejected_without_detail() {
    let mut env = TestEnv::new();
    let key = fs::read_to_string(env.home.join(".ssh/id_ed25519.pub")).unwrap();
    fs::write(&env.authorized_keys, format!("command=\"nope\" {key}")).unwrap();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("true")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unauthorized"), "{out:?}");
    assert!(!stderr.contains("authorized_keys options"), "{out:?}");
}

#[test]
fn unauthorized_key_cannot_authenticate_or_forward() {
    let mut env = TestEnv::new();
    fs::write(&env.authorized_keys, "").unwrap();
    env.start_server();
    let remote_port = free_tcp_port();
    let out = env
        .hush()
        .arg("-T")
        .arg("-R")
        .arg(format!("{remote_port}:127.0.0.1:1"))
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("true")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unauthorized"),
        "{out:?}"
    );
    // The server must not have opened the requested remote listener.
    assert!(std::net::TcpStream::connect(("127.0.0.1", remote_port)).is_err());
}

/// A protocol-level client whose certificate claims a user its key is not
/// authorized for, racing a remote forward request against the rejection. The
/// server must close the connection without serving any stream, even though
/// the key would be authorized for the real user.
#[tokio::test]
async fn server_rejects_certificate_claiming_wrong_user() {
    use hush_core::protocol::{
        RemoteForwardRequest, StreamOpen, StreamResponse, TcpTarget, read_frame, write_frame,
    };

    let mut env = TestEnv::new();
    env.start_server();

    let identity =
        hush_core::auth::load_identity_from_file(&env.home.join(".ssh/id_ed25519")).unwrap();
    let client_config = hush_core::tls::make_client_config(
        &env.home.join(".hush"),
        hush_core::tls::host_key("127.0.0.1", env.port),
        identity,
        "hush-wrong-user",
        true,
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    let conn = endpoint
        .connect(
            format!("127.0.0.1:{}", env.port).parse().unwrap(),
            "127.0.0.1",
        )
        .unwrap()
        .await
        .unwrap();

    let forward_port = free_tcp_port();
    if let Ok((mut send, mut recv)) = conn.open_bi().await {
        let _ = write_frame(
            &mut send,
            &StreamOpen::OpenRemoteForward(RemoteForwardRequest {
                listen_host: "127.0.0.1".to_owned(),
                listen_port: forward_port,
                target: TcpTarget {
                    host: "127.0.0.1".to_owned(),
                    port: 1,
                },
            }),
        )
        .await;
        let _ = send.finish();
        if let Ok(StreamResponse::Ok) = read_frame::<StreamResponse>(&mut recv).await {
            panic!("server served a stream for an unauthorized user");
        }
    }

    match conn.closed().await {
        quinn::ConnectionError::ApplicationClosed(closed) => {
            assert_eq!(closed.reason.as_ref(), b"unauthorized");
        }
        other => panic!("expected application close, got {other:?}"),
    }
    assert!(std::net::TcpStream::connect(("127.0.0.1", forward_port)).is_err());
}

#[test]
fn tofu_mismatch_fails_without_insecure() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("true")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");

    let _ = env.server.take().map(|mut child| {
        let _ = child.kill();
        let _ = child.wait();
    });
    env.data = env.temp.path().join("data2");
    fs::create_dir_all(&env.data).unwrap();
    env.start_server();

    let mut cmd = Command::new(hush_bin());
    let out = cmd
        .env("HOME", &env.home)
        .env_remove("SSH_AUTH_SOCK")
        .arg("--data-dir")
        .arg(env.home.join(".hush"))
        .arg("-p")
        .arg(env.port.to_string())
        .arg("-T")
        .arg(format!("{}@127.0.0.1", hush_core::auth::current_username()))
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("true")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("host certificate mismatch"));
}

fn ensure_server_built() {
    BUILD_SERVER.get_or_init(|| {
        run(Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("hush-server"));
    });
}

fn run(cmd: &mut Command) {
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
}

fn hush_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hush"))
}

fn server_bin() -> PathBuf {
    let mut path = hush_bin();
    path.set_file_name("hush-server");
    path
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_tcp(port: u16) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("tcp port {port} did not open");
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn http_get(port: u16) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut data = String::new();
    stream.read_to_string(&mut data).unwrap();
    data.split("\r\n\r\n").nth(1).unwrap_or("").to_owned()
}

#[test]
fn ecdsa_p256_file_key_works() {
    ecdsa_file_key_works(256, "p256-file-ok");
}

#[test]
fn ecdsa_p384_file_key_works() {
    ecdsa_file_key_works(384, "p384-file-ok");
}

#[test]
fn ecdsa_p521_file_key_works() {
    ecdsa_file_key_works(521, "p521-file-ok");
}

fn ecdsa_file_key_works(bits: u32, marker: &str) {
    let mut env = TestEnv::new();
    let key = env.ecdsa_identity(bits);
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg("-i")
        .arg(&key)
        .arg(env.target())
        .arg("--")
        .arg("/bin/echo")
        .arg(marker)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), marker);
}

/// Message log of a stub ssh-agent: one entry per connection, containing the
/// raw agent protocol messages received on it.
type StubAgentLog = std::sync::Arc<std::sync::Mutex<Vec<Vec<Vec<u8>>>>>;

/// Speaks just enough of the agent protocol for these tests: answers
/// `SSH_AGENTC_REQUEST_IDENTITIES` with an empty list and accepts any
/// extension, recording everything it receives.
fn spawn_stub_agent(sock: &std::path::Path) -> StubAgentLog {
    use std::io::{Read, Write};

    fn read_agent_message(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len)?;
        let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut msg)?;
        Ok(msg)
    }

    let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
    let log = StubAgentLog::default();
    let thread_log = log.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut messages = Vec::new();
            loop {
                let Ok(msg) = read_agent_message(&mut stream) else {
                    break;
                };
                let reply: &[u8] = match msg.first() {
                    Some(27) => &[6],              // SSH_AGENTC_EXTENSION -> SSH_AGENT_SUCCESS
                    Some(11) => &[12, 0, 0, 0, 0], // REQUEST_IDENTITIES -> empty answer
                    _ => &[5],                     // SSH_AGENT_FAILURE
                };
                messages.push(msg);
                let framed = [&(reply.len() as u32).to_be_bytes()[..], reply].concat();
                if stream.write_all(&framed).is_err() {
                    break;
                }
            }
            thread_log.lock().unwrap().push(messages);
        }
    });
    log
}

fn take_ssh_string<'a>(buf: &mut &'a [u8]) -> &'a [u8] {
    let (len, rest) = buf.split_at(4);
    let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
    let (data, rest) = rest.split_at(len);
    *buf = rest;
    data
}

#[test]
fn agent_forwarding_relays_and_binds_session() {
    let mut env = TestEnv::new();
    env.start_server();
    let sock = env.temp.path().join("stub-agent.sock");
    let log = spawn_stub_agent(&sock);

    let out = env
        .hush()
        .env("SSH_AUTH_SOCK", &sock)
        .arg("-A")
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("ssh-add -l 2>&1; printf 'sock=%s' \"$SSH_AUTH_SOCK\"")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // ssh-add on the remote side reached the stub agent through the tunnel.
    assert!(stdout.contains("no identities"), "{out:?}");

    // The remote socket is hush's own, not the local one.
    let remote_sock = stdout.split("sock=").nth(1).unwrap_or("");
    assert!(remote_sock.contains("hush-"), "{out:?}");
    assert_ne!(remote_sock, sock.to_str().unwrap(), "{out:?}");

    // The forwarded connection was bound with session-bind@openssh.com before
    // any client data was relayed.
    let start = Instant::now();
    let bind = loop {
        let connections = log.lock().unwrap();
        if let Some(messages) = connections
            .iter()
            .find(|messages| messages.first().is_some_and(|msg| msg.first() == Some(&27)))
        {
            break messages[0].clone();
        }
        drop(connections);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "no session-bind seen; log: {:?}",
            log.lock().unwrap()
        );
        thread::sleep(Duration::from_millis(25));
    };

    let mut rest = &bind[1..];
    assert_eq!(take_ssh_string(&mut rest), b"session-bind@openssh.com");
    let host_key = take_ssh_string(&mut rest).to_vec();
    let session_id = take_ssh_string(&mut rest);
    let signature = take_ssh_string(&mut rest);
    assert_eq!(rest, [1], "is_forwarding flag should be set");
    assert_eq!(session_id.len(), 32);
    assert!(!signature.is_empty());

    // The bound host key is the server's TLS host key in SSH form.
    let cert = fs::read(env.data.join("server/host_cert.der")).unwrap();
    let expected = hush_core::auth::public_key_from_cert_der(&cert)
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(host_key, expected);
}

#[test]
fn agent_forwarding_works_with_real_ssh_agent() {
    let mut env = TestEnv::new();
    let sock = env.temp.path().join("agent.sock");

    let Ok(mut agent) = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        eprintln!("skipping agent_forwarding_works_with_real_ssh_agent: ssh-agent not available");
        return;
    };
    let started = Instant::now();
    while !sock.exists() && started.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(25));
    }
    let added = Command::new("ssh-add")
        .arg(env.home.join(".ssh/id_ed25519"))
        .env("SSH_AUTH_SOCK", &sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(added, Ok(status) if status.success()) {
        let _ = agent.kill();
        let _ = agent.wait();
        eprintln!("skipping agent_forwarding_works_with_real_ssh_agent: ssh-add failed");
        return;
    }

    env.start_server();
    let out = env
        .hush()
        .env("SSH_AUTH_SOCK", &sock)
        .arg("-v")
        .arg("-A")
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("ssh-add -l")
        .output()
        .unwrap();

    let _ = agent.kill();
    let _ = agent.wait();

    assert!(out.status.success(), "{out:?}");
    // The remote ssh-add sees the key held by the local agent.
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hush-test"),
        "{out:?}"
    );
    // The real ssh-agent verified our session-bind signature.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bound forwarded agent connection"),
        "{out:?}"
    );
    assert!(!stderr.contains("refused session-bind"), "{out:?}");
}

#[test]
fn agent_forwarding_requires_opt_in() {
    let mut env = TestEnv::new();
    env.start_server();
    let out = env
        .hush()
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("printf '%s' \"${SSH_AUTH_SOCK-unset}\"")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "unset");
}

#[test]
fn server_can_disable_agent_forwarding() {
    let mut env = TestEnv::new();
    env.start_server_with(&["--disable-agent-forwarding"]);
    let sock = env.temp.path().join("stub-agent.sock");
    let _log = spawn_stub_agent(&sock);
    let out = env
        .hush()
        .env("SSH_AUTH_SOCK", &sock)
        .arg("-A")
        .arg("-T")
        .arg(env.target())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("printf '%s' \"${SSH_AUTH_SOCK-unset}\"")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "unset");
}

#[test]
fn ecdsa_agent_key_works() {
    let mut env = TestEnv::new();
    let key = env.ecdsa_identity(384);
    let sock = env.temp.path().join("agent.sock");

    // Run ssh-agent bound to a known socket; skip the test if it is unavailable.
    let Ok(mut agent) = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        eprintln!("skipping ecdsa_agent_key_works: ssh-agent not available");
        return;
    };
    let started = Instant::now();
    while !sock.exists() && started.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(25));
    }
    let added = Command::new("ssh-add")
        .arg(&key)
        .env("SSH_AUTH_SOCK", &sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(added, Ok(status) if status.success()) {
        let _ = agent.kill();
        let _ = agent.wait();
        eprintln!("skipping ecdsa_agent_key_works: ssh-add failed");
        return;
    }

    env.start_server();
    let out = env
        .hush()
        .env("SSH_AUTH_SOCK", &sock)
        .arg("-T")
        .arg("-i")
        .arg(&key)
        .arg(env.target())
        .arg("--")
        .arg("/bin/echo")
        .arg("p384-agent-ok")
        .output()
        .unwrap();

    let _ = agent.kill();
    let _ = agent.wait();

    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "p384-agent-ok");
}
