use anyhow::{Context, Result, anyhow, bail};
use quinn::{Connection, Endpoint};
use std::{collections::VecDeque, net::SocketAddr};
use tokio::{
    task::JoinSet,
    time::{Duration, Instant},
};

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

pub(crate) async fn connect_any(endpoint: &Endpoint, host: &str, port: u16) -> Result<Connection> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("resolve {host}:{port}: no addresses");
    }

    let mut pending = VecDeque::from(happy_eyeballs_order(addrs));
    let mut attempts = JoinSet::<Result<Connection>>::new();
    let label = format!("{host}:{port}");

    if let Some(addr) = pending.pop_front() {
        spawn_connect_attempt(&mut attempts, endpoint, addr, host, &label);
    }

    let mut last_err = None;
    let mut next_attempt_at = (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
    loop {
        if attempts.is_empty() && pending.is_empty() {
            break;
        }
        if attempts.is_empty() {
            if let Some(addr) = pending.pop_front() {
                spawn_connect_attempt(&mut attempts, endpoint, addr, host, &label);
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
                            spawn_connect_attempt(&mut attempts, endpoint, addr, host, &label);
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
    attempts: &mut JoinSet<Result<Connection>>,
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    label: &str,
) {
    let endpoint = endpoint.clone();
    let server_name = server_name.to_owned();
    let label = label.to_owned();
    attempts.spawn(async move {
        endpoint
            .connect(addr, &server_name)
            .with_context(|| format!("start QUIC connect to {addr} for {label}"))?
            .await
            .with_context(|| format!("connect to {addr} for {label}"))
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
