use std::{
    fs,
    net::{TcpListener, UdpSocket},
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
        format!("{}@127.0.0.1", whoami::username())
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
    assert!(String::from_utf8_lossy(&out.stderr).contains("connection lost"));
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
        .arg(format!("{}@127.0.0.1", whoami::username()))
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
