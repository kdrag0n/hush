# hush

Modern fuss-free SSH over QUIC

## Install

Client:

```sh
brew install kdrag0n/tap/hush
```

Server:

```sh
curl -fsSL https://kdrag0n.dev/install-hush | sh
```

## Usage

Same syntax as `ssh`, just replace `ssh` with `hush` and `scp` with `hcp`.

Connect to server:

```sh
hush root@192.168.1.1
```

Copy files:

```sh
hush cp ./build.tar root@192.168.1.1:/tmp/build.tar
# or
hcp root@192.168.1.1:/var/log/app.log ./app.log
```

Shell completions (zsh and bash) cover flags, hosts from `~/.ssh/config` and known hosts, the remote command, and local and remote `hush cp` paths:

```sh
# zsh: write to a directory on $fpath, before compinit runs
hush --completions zsh > ~/.zfunc/_hush
# bash
hush --completions bash > ~/.local/share/bash-completion/completions/hush
```

Remote path completion only connects to hosts already in hush's known_hosts, and never prompts for a key passphrase.

## Features

- High performance on flaky networks
    - Aggressive retransmits and congestion control, similar to KCP
- Roaming + long connection lifetime
- Compatible with Ed25519 and ECDSA (P-256/384/521) SSH keys
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
    - ssh-agent forwarding (`-A`), with `session-bind@openssh.com` agent restrictions
    - File copy with `hush cp` / `hcp`
    - `~.` escape to disconnect
    - PTY and piped modes with separate stdin/stdout/stderr
    - Login shells
    - Partial compatibility with `ssh` CLI
