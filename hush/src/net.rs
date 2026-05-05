use anyhow::{Context, Result, anyhow, bail};
use hush_core::{auth::LoadedIdentity, transport::Connection};
use std::{collections::VecDeque, net::SocketAddr};
use tokio::{
    task::JoinSet,
    time::{Duration, Instant},
};

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) async fn connect_any(
    host: &str,
    port: u16,
    data_dir: &std::path::Path,
    identity: LoadedIdentity,
    insecure: bool,
) -> Result<Connection> {
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_any_inner(host, port, data_dir, identity, insecure),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => bail!("connect to {host}:{port}: timed out after 60s"),
    }
}

async fn connect_any_inner(
    host: &str,
    port: u16,
    data_dir: &std::path::Path,
    identity: LoadedIdentity,
    insecure: bool,
) -> Result<Connection> {
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
        spawn_connect_attempt(&mut attempts, addr, &label, data_dir, &identity, insecure);
    }

    let mut last_err = None;
    let mut next_attempt_at = (!pending.is_empty()).then(|| Instant::now() + HAPPY_EYEBALLS_DELAY);
    loop {
        if attempts.is_empty() && pending.is_empty() {
            break;
        }
        if attempts.is_empty() {
            if let Some(addr) = pending.pop_front() {
                spawn_connect_attempt(&mut attempts, addr, &label, data_dir, &identity, insecure);
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
                            spawn_connect_attempt(&mut attempts, addr, &label, data_dir, &identity, insecure);
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
    addr: SocketAddr,
    label: &str,
    data_dir: &std::path::Path,
    identity: &LoadedIdentity,
    insecure: bool,
) {
    let label = label.to_owned();
    let host_key = label.clone();
    let data_dir = data_dir.to_owned();
    let identity = identity.clone();
    attempts.spawn(async move {
        Connection::connect(addr, &host_key, &data_dir, identity, insecure)
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
