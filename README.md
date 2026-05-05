# hush

Modern fuss-free SSH.

## Install server

```sh
curl -fsSL https://raw.githubusercontent.com/kdrag0n/hush/refs/heads/main/scripts/install-server.sh | sh
```

## Features

- Built on QUIC protocol
- High performance on flaky networks
    - Aggressive retransmits and congestion control, similar to KCP
- Roaming + long connection lifetime
- Compatible with Ed25519 SSH keys
    - Plaintext key files
    - Passphrase-encrypted key files
    - ssh-agent
- Compatible with `~/.ssh/config` and `~/.ssh/authorized_keys`
- Post-quantum security (hybrid X25519 + ML-KEM-768)
- Happy Eyeballs [(RFC6555)](https://datatracker.ietf.org/doc/html/rfc6555)
- (soon) Local prediction
- Server can run as root (multi-user mode) or as an unprivileged user (single-user mode)
- Classic SSH features:
    - Local and remote TCP port forwarding
    - `~.` escape to disconnect
    - PTY and piped modes with separate stdin/stdout/stderr
    - Login shells
    - Partial compatibility with `ssh` CLI
