use crate::auth::{self, LoadedIdentity};
use anyhow::{Context, Result, bail};
use kcp_tokio::{KcpConfig, KcpListener, KcpStream, UdpTransport};
use serde::{Deserialize, Serialize};
use snow::TransportState;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs,
    future::poll_fn,
    io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split},
    sync::{Mutex, mpsc},
};
use tokio_util::sync::PollSender;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const KCP_MTU: u32 = 1200;
const KCP_SEND_WINDOW: u32 = 256;
const KCP_RECV_WINDOW: u32 = 256;
const KCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const KCP_KEEPALIVE: Duration = Duration::from_secs(10);
const SECURE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const NOISE_MESSAGE_MAX_LEN: usize = 65_535;
const SECURE_RECORD_MAX_LEN: usize = 2 * 1024 * 1024;
const WRITE_RECORD_QUEUE_LEN: usize = 64;
const STREAM_EVENT_QUEUE_LEN: usize = 1024;

type RawStream = KcpStream;

#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

struct Inner {
    write_tx: mpsc::Sender<SecureRecord>,
    accept_bi_rx: Mutex<mpsc::Receiver<(SendStream, RecvStream)>>,
    accept_uni_rx: Mutex<mpsc::Receiver<RecvStream>>,
    streams: Mutex<HashMap<u64, mpsc::Sender<RecvEvent>>>,
    next_stream_id: AtomicU64,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    peer_public_key: ssh_key::PublicKey,
}

pub struct Listener {
    inner: KcpListener,
    data_dir: PathBuf,
}

pub struct SendStream {
    id: u64,
    tx: PollSender<SecureRecord>,
    finished: bool,
}

pub struct RecvStream {
    rx: mpsc::Receiver<RecvEvent>,
    buf: VecDeque<u8>,
    finished: bool,
}

#[derive(Debug, Serialize, Deserialize)]
enum SecureRecord {
    Auth(ClientAuth),
    Mux(MuxFrame),
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientAuth {
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
enum MuxFrame {
    OpenBi { id: u64 },
    OpenUni { id: u64 },
    Data { id: u64, bytes: Vec<u8> },
    Finish { id: u64 },
    Close,
}

enum RecvEvent {
    Data(Vec<u8>),
    Finish,
}

#[derive(Debug, Serialize, Deserialize)]
struct HostKeyFile {
    private: Vec<u8>,
    public: Vec<u8>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KnownHostsFile {
    hosts: BTreeMap<String, String>,
}

impl Connection {
    pub async fn connect(
        addr: SocketAddr,
        host_key: &str,
        data_dir: &Path,
        identity: LoadedIdentity,
        insecure: bool,
    ) -> Result<Self> {
        let mut raw = connect_kcp(addr)
            .await
            .with_context(|| format!("connect KCP to {addr}"))?;
        let local_addr = raw.local_addr().context("get local KCP address")?;
        let mut transport = tokio::time::timeout(
            SECURE_HANDSHAKE_TIMEOUT,
            client_handshake(&mut raw, host_key, data_dir, &identity, insecure),
        )
        .await
        .with_context(|| {
            format!(
                "secure handshake with {host_key} timed out after {}s",
                SECURE_HANDSHAKE_TIMEOUT.as_secs()
            )
        })?
        .with_context(|| format!("secure handshake with {host_key}"))?;
        let peer_public_key = identity.public_key.clone();
        let client_public = auth::ed25519_public_key_bytes(&peer_public_key)?.to_vec();
        let signature = auth::sign_identity(&identity, transport.handshake_hash.as_slice())?;
        write_secure_record(
            &mut raw,
            &mut transport.state,
            &SecureRecord::Auth(ClientAuth {
                public_key: client_public,
                signature,
            }),
        )
        .await?;
        Ok(Self::start(
            raw,
            transport.state,
            addr,
            local_addr,
            peer_public_key,
            StreamIdSide::Client,
        ))
    }

    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        let id = self.inner.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let (recv, incoming_tx) = RecvStream::new();
        self.inner.streams.lock().await.insert(id, incoming_tx);
        self.send_record(SecureRecord::Mux(MuxFrame::OpenBi { id }))
            .await?;
        Ok((self.send_stream(id), recv))
    }

    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.inner
            .accept_bi_rx
            .lock()
            .await
            .recv()
            .await
            .context("connection closed")
    }

    pub async fn open_uni(&self) -> Result<SendStream> {
        let id = self.inner.next_stream_id.fetch_add(2, Ordering::Relaxed);
        self.send_record(SecureRecord::Mux(MuxFrame::OpenUni { id }))
            .await?;
        Ok(self.send_stream(id))
    }

    pub async fn accept_uni(&self) -> Result<RecvStream> {
        self.inner
            .accept_uni_rx
            .lock()
            .await
            .recv()
            .await
            .context("connection closed")
    }

    pub fn close(&self) {
        let _ = self
            .inner
            .write_tx
            .try_send(SecureRecord::Mux(MuxFrame::Close));
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_addr
    }

    pub fn local_address(&self) -> SocketAddr {
        self.inner.local_addr
    }

    pub fn peer_public_key(&self) -> ssh_key::PublicKey {
        self.inner.peer_public_key.clone()
    }

    fn start(
        raw: RawStream,
        transport: TransportState,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        peer_public_key: ssh_key::PublicKey,
        side: StreamIdSide,
    ) -> Self {
        let (write_tx, write_rx) = mpsc::channel(WRITE_RECORD_QUEUE_LEN);
        let (accept_bi_tx, accept_bi_rx) = mpsc::channel(128);
        let (accept_uni_tx, accept_uni_rx) = mpsc::channel(128);
        let inner = Arc::new(Inner {
            write_tx,
            accept_bi_rx: Mutex::new(accept_bi_rx),
            accept_uni_rx: Mutex::new(accept_uni_rx),
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU64::new(side.first_local_id()),
            remote_addr,
            local_addr,
            peer_public_key,
        });
        let (read_half, write_half) = split(raw);
        let transport = Arc::new(Mutex::new(transport));
        tokio::spawn(write_loop(write_half, transport.clone(), write_rx));
        tokio::spawn(read_loop(
            read_half,
            transport,
            inner.clone(),
            accept_bi_tx,
            accept_uni_tx,
        ));
        Self { inner }
    }

    fn send_stream(&self, id: u64) -> SendStream {
        SendStream {
            id,
            tx: PollSender::new(self.inner.write_tx.clone()),
            finished: false,
        }
    }

    async fn send_record(&self, record: SecureRecord) -> Result<()> {
        self.inner
            .write_tx
            .send(record)
            .await
            .map_err(|_| anyhow::anyhow!("connection closed"))
    }
}

impl Listener {
    pub async fn bind(addr: SocketAddr, data_dir: PathBuf) -> Result<Self> {
        let inner = KcpListener::bind(addr, kcp_config())
            .await
            .with_context(|| format!("bind KCP listener {addr}"))?;
        Ok(Self { inner, data_dir })
    }

    pub async fn accept(&mut self) -> Result<Connection> {
        loop {
            let (mut raw, remote_addr) = self.inner.accept().await.context("accept KCP stream")?;
            let local_addr = raw.local_addr().context("get local KCP address")?;
            match tokio::time::timeout(
                SECURE_HANDSHAKE_TIMEOUT,
                server_handshake(&mut raw, &self.data_dir),
            )
            .await
            {
                Err(_) => {
                    tracing::warn!(
                        %remote_addr,
                        timeout_secs = SECURE_HANDSHAKE_TIMEOUT.as_secs(),
                        "secure handshake timed out"
                    );
                }
                Ok(Err(err)) => {
                    tracing::warn!(%remote_addr, %err, "secure handshake failed");
                }
                Ok(Ok((transport, auth))) => {
                    return Ok(Connection::start(
                        raw,
                        transport,
                        remote_addr,
                        local_addr,
                        auth,
                        StreamIdSide::Server,
                    ));
                }
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        *self.inner.local_addr()
    }
}

impl SendStream {
    pub async fn finish(&mut self) -> Result<()> {
        poll_fn(|cx| self.poll_finish(cx)).await
    }

    fn poll_finish(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                self.finished = true;
                match self
                    .tx
                    .send_item(SecureRecord::Mux(MuxFrame::Finish { id: self.id }))
                {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(_) => Poll::Ready(Err(anyhow::anyhow!("connection closed"))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(anyhow::anyhow!("connection closed"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is finished",
            )));
        }
        match this.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => match this.tx.send_item(SecureRecord::Mux(MuxFrame::Data {
                id: this.id,
                bytes: buf.to_vec(),
            })) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed",
                ))),
            },
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.poll_finish(cx) {
            Poll::Ready(result) => Poll::Ready(match result {
                Ok(()) => Ok(()),
                Err(err) => Err(io::Error::new(io::ErrorKind::BrokenPipe, err)),
            }),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(tx) = self.tx.get_ref() {
            let _ = tx.try_send(SecureRecord::Mux(MuxFrame::Finish { id: self.id }));
        }
    }
}

impl RecvStream {
    fn new() -> (Self, mpsc::Sender<RecvEvent>) {
        let (tx, rx) = mpsc::channel(STREAM_EVENT_QUEUE_LEN);
        (
            Self {
                rx,
                buf: VecDeque::new(),
                finished: false,
            },
            tx,
        )
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            while out.remaining() > 0 {
                let Some(byte) = self.buf.pop_front() else {
                    break;
                };
                out.put_slice(&[byte]);
            }
            if out.filled().len() > 0 || self.finished {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.rx).poll_recv(cx) {
                Poll::Ready(Some(RecvEvent::Data(bytes))) => self.buf.extend(bytes),
                Poll::Ready(Some(RecvEvent::Finish)) | Poll::Ready(None) => {
                    self.finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[derive(Clone, Copy)]
enum StreamIdSide {
    Client,
    Server,
}

impl StreamIdSide {
    fn first_local_id(self) -> u64 {
        match self {
            Self::Client => 1,
            Self::Server => 2,
        }
    }
}

struct ClientTransport {
    state: TransportState,
    handshake_hash: Vec<u8>,
}

async fn client_handshake(
    raw: &mut RawStream,
    host_key: &str,
    data_dir: &Path,
    identity: &LoadedIdentity,
    insecure: bool,
) -> Result<ClientTransport> {
    let builder = noise_builder()?;
    let keypair = builder
        .generate_keypair()
        .context("generate Noise client key")?;
    let mut noise = noise_builder()?
        .local_private_key(&keypair.private)?
        .build_initiator()
        .context("build Noise initiator")?;

    let mut msg = vec![0u8; NOISE_MESSAGE_MAX_LEN];
    let n = noise.write_message(&[], &mut msg)?;
    write_noise_message(raw, &msg[..n]).await?;

    let incoming = read_noise_message(raw).await?;
    let mut plain = vec![0u8; NOISE_MESSAGE_MAX_LEN];
    noise.read_message(&incoming, &mut plain)?;
    let server_static = noise
        .get_remote_static()
        .context("server did not send Noise static key")?
        .to_vec();
    check_known_host(data_dir, host_key, &server_static, insecure)?;

    let n = noise.write_message(&[], &mut msg)?;
    write_noise_message(raw, &msg[..n]).await?;
    let handshake_hash = noise.get_handshake_hash().to_vec();
    tracing::debug!(
        identity = %auth::public_key_fingerprint(&identity.public_key).unwrap_or_else(|_| "unknown".into()),
        server = %auth::bytes_fingerprint(&server_static),
        "secure KCP handshake complete"
    );
    Ok(ClientTransport {
        state: noise.into_transport_mode()?,
        handshake_hash,
    })
}

async fn server_handshake(
    raw: &mut RawStream,
    data_dir: &Path,
) -> Result<(TransportState, ssh_key::PublicKey)> {
    let host_key = load_or_create_host_key(data_dir)?;
    let mut noise = noise_builder()?
        .local_private_key(&host_key.private)?
        .build_responder()
        .context("build Noise responder")?;
    let mut plain = vec![0u8; NOISE_MESSAGE_MAX_LEN];

    let incoming = read_noise_message(raw).await?;
    noise.read_message(&incoming, &mut plain)?;

    let mut msg = vec![0u8; NOISE_MESSAGE_MAX_LEN];
    let n = noise.write_message(&[], &mut msg)?;
    write_noise_message(raw, &msg[..n]).await?;

    let incoming = read_noise_message(raw).await?;
    noise.read_message(&incoming, &mut plain)?;
    let handshake_hash = noise.get_handshake_hash().to_vec();
    let mut transport = noise.into_transport_mode()?;

    let record = read_secure_record(raw, &mut transport).await?;
    let SecureRecord::Auth(auth_msg) = record else {
        bail!("client did not authenticate");
    };
    let key = auth::ed25519_public_key_from_bytes(&auth_msg.public_key)?;
    auth::verify_public_key_signature(&key, &handshake_hash, &auth_msg.signature)?;
    Ok((transport, key))
}

fn noise_builder() -> Result<snow::Builder<'static>> {
    let params = NOISE_PATTERN.parse().context("parse Noise pattern")?;
    Ok(snow::Builder::new(params))
}

fn kcp_config() -> KcpConfig {
    KcpConfig::new()
        .turbo_mode()
        .stream_mode(true)
        .mtu(KCP_MTU)
        .window_size(KCP_SEND_WINDOW, KCP_RECV_WINDOW)
        .connect_timeout(KCP_CONNECT_TIMEOUT)
        .keep_alive(Some(KCP_KEEPALIVE))
}

async fn connect_kcp(addr: SocketAddr) -> Result<RawStream> {
    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let transport = UdpTransport::bind(bind_addr)
        .await
        .with_context(|| format!("bind client UDP socket {bind_addr}"))?;
    KcpStream::connect_with_transport(Arc::new(transport), addr, kcp_config())
        .await
        .context("connect KCP stream")
}

async fn write_loop<W>(
    mut writer: W,
    transport: Arc<Mutex<TransportState>>,
    mut rx: mpsc::Receiver<SecureRecord>,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(record) = rx.recv().await {
        if let Err(err) = write_secure_record_shared(&mut writer, &transport, &record).await {
            tracing::debug!(%err, "secure record write loop stopped");
            break;
        }
        if matches!(record, SecureRecord::Mux(MuxFrame::Close)) {
            let _ = writer.shutdown().await;
            break;
        }
    }
}

async fn read_loop<R>(
    mut reader: R,
    transport: Arc<Mutex<TransportState>>,
    inner: Arc<Inner>,
    accept_bi_tx: mpsc::Sender<(SendStream, RecvStream)>,
    accept_uni_tx: mpsc::Sender<RecvStream>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let record = read_secure_record_shared(&mut reader, &transport).await;
        let Ok(SecureRecord::Mux(frame)) = record else {
            break;
        };
        match frame {
            MuxFrame::OpenBi { id } => {
                let (recv, incoming_tx) = RecvStream::new();
                inner.streams.lock().await.insert(id, incoming_tx);
                let send = SendStream {
                    id,
                    tx: PollSender::new(inner.write_tx.clone()),
                    finished: false,
                };
                if accept_bi_tx.send((send, recv)).await.is_err() {
                    break;
                }
            }
            MuxFrame::OpenUni { id } => {
                let (recv, incoming_tx) = RecvStream::new();
                inner.streams.lock().await.insert(id, incoming_tx);
                if accept_uni_tx.send(recv).await.is_err() {
                    break;
                }
            }
            MuxFrame::Data { id, bytes } => {
                let tx = inner.streams.lock().await.get(&id).cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(RecvEvent::Data(bytes)).await;
                }
            }
            MuxFrame::Finish { id } => {
                let tx = inner.streams.lock().await.remove(&id);
                if let Some(tx) = tx {
                    let _ = tx.send(RecvEvent::Finish).await;
                }
            }
            MuxFrame::Close => break,
        }
    }
}

async fn write_noise_message<W>(writer: &mut W, msg: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if msg.len() > NOISE_MESSAGE_MAX_LEN {
        bail!("Noise message too large");
    }
    writer.write_u32(msg.len() as u32).await?;
    writer.write_all(msg).await?;
    Ok(())
}

async fn read_noise_message<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > NOISE_MESSAGE_MAX_LEN {
        bail!("Noise message too large: {len}");
    }
    let mut msg = vec![0u8; len];
    reader.read_exact(&mut msg).await?;
    Ok(msg)
}

async fn write_secure_record<W>(
    writer: &mut W,
    transport: &mut TransportState,
    record: &SecureRecord,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let ciphertext = encrypt_record(transport, record)?;
    writer.write_u32(ciphertext.len() as u32).await?;
    writer.write_all(&ciphertext).await?;
    Ok(())
}

async fn write_secure_record_shared<W>(
    writer: &mut W,
    transport: &Arc<Mutex<TransportState>>,
    record: &SecureRecord,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let ciphertext = {
        let mut transport = transport.lock().await;
        encrypt_record(&mut transport, record)?
    };
    writer.write_u32(ciphertext.len() as u32).await?;
    writer.write_all(&ciphertext).await?;
    Ok(())
}

async fn read_secure_record<R>(
    reader: &mut R,
    transport: &mut TransportState,
) -> Result<SecureRecord>
where
    R: AsyncRead + Unpin,
{
    let ciphertext = read_record_ciphertext(reader).await?;
    decrypt_record(transport, &ciphertext)
}

async fn read_secure_record_shared<R>(
    reader: &mut R,
    transport: &Arc<Mutex<TransportState>>,
) -> Result<SecureRecord>
where
    R: AsyncRead + Unpin,
{
    let ciphertext = read_record_ciphertext(reader).await?;
    let mut transport = transport.lock().await;
    decrypt_record(&mut transport, &ciphertext)
}

async fn read_record_ciphertext<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > SECURE_RECORD_MAX_LEN + 16 {
        bail!("secure record too large: {len}");
    }
    let mut ciphertext = vec![0u8; len];
    reader.read_exact(&mut ciphertext).await?;
    Ok(ciphertext)
}

fn encrypt_record(transport: &mut TransportState, record: &SecureRecord) -> Result<Vec<u8>> {
    let plain = postcard::to_allocvec(record).context("serialize secure record")?;
    if plain.len() > SECURE_RECORD_MAX_LEN {
        bail!("secure record too large: {}", plain.len());
    }
    let mut ciphertext = vec![0u8; plain.len() + 16];
    let n = transport
        .write_message(&plain, &mut ciphertext)
        .context("encrypt secure record")?;
    ciphertext.truncate(n);
    Ok(ciphertext)
}

fn decrypt_record(transport: &mut TransportState, ciphertext: &[u8]) -> Result<SecureRecord> {
    let mut plain = vec![0u8; ciphertext.len()];
    let n = transport
        .read_message(ciphertext, &mut plain)
        .context("decrypt secure record")?;
    postcard::from_bytes(&plain[..n]).context("deserialize secure record")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::AsyncWrite;

    #[tokio::test]
    async fn send_stream_waits_when_write_queue_is_full() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut send = SendStream {
            id: 1,
            tx: PollSender::new(tx),
            finished: false,
        };

        let n = poll_fn(|cx| Pin::new(&mut send).poll_write(cx, b"first"))
            .await
            .unwrap();
        assert_eq!(n, 5);

        let blocked = tokio::time::timeout(
            Duration::from_millis(25),
            poll_fn(|cx| Pin::new(&mut send).poll_write(cx, b"second")),
        )
        .await;
        assert!(blocked.is_err());

        let _ = rx.recv().await;
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| Pin::new(&mut send).poll_write(cx, b"second")),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n, 6);
    }
}

fn load_or_create_host_key(data_dir: &Path) -> Result<HostKeyFile> {
    let path = crate::paths::server_dir(data_dir).join("host_key.noise");
    if path.exists() {
        let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let key: HostKeyFile =
            postcard::from_bytes(&data).with_context(|| format!("parse {}", path.display()))?;
        if key.private.len() != 32 || key.public.len() != 32 {
            bail!("invalid Noise host key {}", path.display());
        }
        return Ok(key);
    }

    let builder = noise_builder()?;
    let keypair = builder
        .generate_keypair()
        .context("generate Noise host key")?;
    let key = HostKeyFile {
        private: keypair.private,
        public: keypair.public,
    };
    write_private_file_atomic(&path, &postcard::to_allocvec(&key)?)?;
    Ok(key)
}

fn check_known_host(
    data_dir: &Path,
    host_key: &str,
    server_public: &[u8],
    insecure: bool,
) -> Result<()> {
    let path = data_dir.join("known_hosts");
    let mut known = read_known_hosts(&path)?;
    let fingerprint = auth::bytes_fingerprint(server_public);
    match known.hosts.get(host_key) {
        Some(stored) if stored == &fingerprint => Ok(()),
        Some(stored) if insecure => {
            tracing::warn!(
                host = %host_key,
                stored = %stored,
                presented = %fingerprint,
                "known host mismatch ignored because --insecure is set"
            );
            Ok(())
        }
        Some(stored) => bail!(
            "host key mismatch for {host_key}: known {stored}, presented {fingerprint}; use -k to bypass"
        ),
        None => {
            known.hosts.insert(host_key.to_owned(), fingerprint);
            write_known_hosts(&path, &known)
        }
    }
}

fn read_known_hosts(path: &Path) -> Result<KnownHostsFile> {
    let Ok(data) = fs::read_to_string(path) else {
        return Ok(KnownHostsFile::default());
    };
    match toml::from_str(&data) {
        Ok(known) => Ok(known),
        Err(err) if is_obsolete_certificate_known_hosts(&data) => {
            tracing::warn!(
                path = %path.display(),
                %err,
                "discarding obsolete certificate known_hosts format"
            );
            Ok(KnownHostsFile::default())
        }
        Err(err) => Err(err).with_context(|| format!("parse {}", path.display())),
    }
}

fn is_obsolete_certificate_known_hosts(data: &str) -> bool {
    data.contains("[[hosts]]") && data.contains("x509-certificate")
}

fn write_known_hosts(path: &Path, known: &KnownHostsFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, toml::to_string_pretty(known)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))
}

fn write_private_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("host key has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod {}", parent.display()))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))
}
