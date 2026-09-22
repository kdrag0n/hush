use anyhow::{Context, Result, anyhow, bail};
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, TokioRuntime};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    task::JoinSet,
    time::{Duration, Instant},
};

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Resolve `host` and connect to the first address that answers, Happy
/// Eyeballs style. Each attempt gets its own endpoint whose UDP socket is
/// `connect()`ed to that address: on macOS an unconnected datagram send costs
/// several times more kernel time per packet than a connected one, which is
/// the difference between a few hundred Mbps and line rate for file copies.
pub(crate) async fn connect_any(
    client_config: ClientConfig,
    host: &str,
    port: u16,
) -> Result<(Endpoint, Connection)> {
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_any_inner(client_config, host, port),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => bail!("connect to {host}:{port}: timed out after 60s"),
    }
}

/// A UDP socket of `addr`'s family, bound to an ephemeral port and connected
/// to `addr`.
fn connected_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let (domain, local): (Domain, SocketAddr) = match addr {
        SocketAddr::V4(_) => (Domain::IPV4, (Ipv4Addr::UNSPECIFIED, 0).into()),
        SocketAddr::V6(_) => (Domain::IPV6, (Ipv6Addr::UNSPECIFIED, 0).into()),
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    hush_core::os::set_recv_buffer(&socket);
    socket.bind(&local.into())?;
    socket.connect(&addr.into())?;
    Ok(socket.into())
}

fn connected_endpoint(addr: SocketAddr, client_config: ClientConfig) -> Result<Endpoint> {
    #[cfg(target_os = "macos")]
    if std::env::var_os("HUSH_NW").is_some() {
        let socket = hush_core::nwsock::NwSocket::connect(addr)
            .with_context(|| format!("open Network.framework flow to {addr}"))?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            Arc::new(socket),
            Arc::new(TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);
        return Ok(endpoint);
    }
    let socket = connected_socket(addr).with_context(|| format!("open UDP socket to {addr}"))?;
    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn connect_any_inner(
    client_config: ClientConfig,
    host: &str,
    port: u16,
) -> Result<(Endpoint, Connection)> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("resolve {host}:{port}: no addresses");
    }

    let mut pending = VecDeque::from(happy_eyeballs_order(addrs));
    let mut attempts = JoinSet::<Result<(Endpoint, Connection)>>::new();
    let label = format!("{host}:{port}");

    if let Some(addr) = pending.pop_front() {
        spawn_connect_attempt(&mut attempts, &client_config, addr, host, &label);
    }

    let mut last_err = None;
    let mut next_attempt_at = (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
    loop {
        if attempts.is_empty() && pending.is_empty() {
            break;
        }
        if attempts.is_empty() {
            if let Some(addr) = pending.pop_front() {
                spawn_connect_attempt(&mut attempts, &client_config, addr, host, &label);
                next_attempt_at =
                    (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
                continue;
            }
        }

        match next_attempt_at {
            Some(deadline) => {
                tokio::select! {
                    result = attempts.join_next(), if !attempts.is_empty() => {
                        match result {
                            Some(Ok(Ok(conn))) => {
                                attempts.abort_all();
                                return Ok(conn);
                            }
                            Some(Ok(Err(err))) => last_err = Some(err),
                            Some(Err(err)) => last_err = Some(err.into()),
                            None => {}
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        if let Some(addr) = pending.pop_front() {
                            spawn_connect_attempt(&mut attempts, &client_config, addr, host, &label);
                        }
                        next_attempt_at =
                            (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
                    }
                }
            }
            None => match attempts.join_next().await {
                Some(Ok(Ok(conn))) => return Ok(conn),
                Some(Ok(Err(err))) => last_err = Some(err),
                Some(Err(err)) => last_err = Some(err.into()),
                None => {}
            },
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("connect to {host}:{port}: no attempts completed")))
}

fn spawn_connect_attempt(
    attempts: &mut JoinSet<Result<(Endpoint, Connection)>>,
    client_config: &ClientConfig,
    addr: SocketAddr,
    server_name: &str,
    label: &str,
) {
    let client_config = client_config.clone();
    let server_name = server_name.to_owned();
    let label = label.to_owned();
    attempts.spawn(async move {
        let endpoint = connected_endpoint(addr, client_config)?;
        let conn = endpoint
            .connect(addr, &server_name)
            .with_context(|| format!("start QUIC connect to {addr} for {label}"))?
            .await
            .with_context(|| format!("connect to {addr} for {label}"))?;
        Ok((endpoint, conn))
    });
}

fn happy_eyeballs_order(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if addrs.is_empty() {
        return addrs;
    }
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    let mut preferred = VecDeque::from(v6);
    let mut fallback = VecDeque::from(v4);
    let mut ordered = Vec::with_capacity(preferred.len() + fallback.len());

    while !preferred.is_empty() || !fallback.is_empty() {
        if let Some(addr) = preferred.pop_front() {
            ordered.push(addr);
        }
        if let Some(addr) = fallback.pop_front() {
            ordered.push(addr);
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_eyeballs_prefers_ipv6_and_interleaves_ipv4() {
        let ordered = happy_eyeballs_order(vec![
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        ]);
        assert_eq!(
            ordered,
            vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            ]
        );
    }
}
