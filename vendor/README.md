# Vendored crates

Patched copies of the quinn QUIC stack, applied through `[patch.crates-io]`
in the workspace `Cargo.toml`. Each directory is the crates.io release named
below plus the changes listed; the first commit adding each directory is the
pristine upstream source, so `git log -- vendor/<crate>` shows the patches.

## quinn-udp 0.5.14

- Connected sockets: sends omit the destination when the socket is connected
  (`UdpSocketState::connected`, `set_connected`). On macOS a connected
  datagram socket costs a fraction of the kernel time per packet of an
  unconnected one, which is what limits QUIC throughput there.
- ENOBUFS is returned to the caller instead of being logged and dropped, and
  is exported as `quinn_udp::ENOBUFS` so quinn can retry.
- Receive ignores ICMP-derived errors (`ECONNREFUSED`, `EHOSTUNREACH`, ...)
  that connected sockets report, instead of failing the endpoint.

## quinn 0.11.9

- `Connection::set_congestion_controller`, `set_ack_frequency_config` and
  `set_remote_address` wrappers.
- A send refused with ENOBUFS is held and retried after a short timer rather
  than dropped or treated as a fatal error.
- `UdpPollHelper` is public so custom `AsyncUdpSocket`s can reuse it.

## quinn-proto 0.11.14

- `Connection::set_congestion_controller` replaces the path's controller at
  runtime.
- `Connection::set_ack_frequency_config` changes the requested peer ACK
  behavior at runtime and forces a new ACK_FREQUENCY frame.
- `Connection::set_remote_address` lets a client follow a server that moves a
  connection to another port by agreement.
