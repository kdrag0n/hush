use std::{
    fs,
    net::{TcpListener, UdpSocket},
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
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
        let child = Command::new(server_bin())
            .arg("--data-dir")
            .arg(&self.data)
            .arg("--authorized-keys")
            .arg(&self.authorized_keys)
            .arg("-l")
            .arg(format!("127.0.0.1:{}", self.port))
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

    fn target(&self) -> String {
        self.target_for_host("127.0.0.1")
    }

    fn target_for_host(&self, host: &str) -> String {
        format!("{}@{host}", hush_core::auth::current_username())
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
fn authorized_keys_options_are_rejected() {
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
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("authorized_keys options"),
        "{out:?}"
    );
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
