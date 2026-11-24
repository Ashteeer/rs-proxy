# rs-proxy

rs-proxy forwards traffic sent to a Linux host by a client-side DNS override.
It reads the hostname from the start of the connection, looks up the real
address using its own DNS resolvers, and forwards the original traffic.
The upstream port is always the port the client connected to on the proxy.

For example, if a client resolves `example.com` to the proxy's LAN address,
the proxy can read `example.com` from the TLS ClientHello and connect to the
real server on port 443. The TLS session and certificate remain between the
client and that server. No per-domain routing table is needed on the proxy.

## Install

On x86-64 or ARM64 Linux with systemd and curl, run:

```sh
curl -fsSL https://github.com/Ashteeer/rs-proxy/releases/latest/download/install.sh -o install-rs-proxy.sh &&
  sudo sh install-rs-proxy.sh
```

The installer verifies the downloaded archive against its release checksum,
installs the systemd unit and creates `/etc/rs-proxy/config.toml` with a
local-only HTTPS listener. It leaves startup to you so you can review the
configuration first. Running the installer again preserves your config.

## Configure and test

1. Open the config with `sudoedit /etc/rs-proxy/config.toml`. The installed
   [example](config.example.toml) starts with TCP on `127.0.0.1:443`. Set
   `dns.servers` to DNS servers reachable from the proxy that return the real
   destination addresses. Use IP addresses with ports, such as
   `1.1.1.1:53` or `[2606:4700:4700::1111]:53`.

2. Validate the file and start the service:

   ```sh
   sudo -u rs-proxy /usr/local/sbin/rs-proxy config validate --config /etc/rs-proxy/config.toml
   sudo systemctl enable --now rs-proxy
   ```

3. With the default listener, run this on the proxy host. It directs the
   connection to the proxy while keeping `example.com` as the TLS hostname:

   ```sh
   curl --noproxy '*' --resolve example.com:443:127.0.0.1 https://example.com/
   ```

4. To serve other machines, change `listen` to the proxy's LAN address, for
   example `192.168.1.10:443`. Restrict that port to trusted source IPs in
   your firewall before restarting. In the DNS service your clients use,
   override the desired domains to the proxy's address. On dual-stack
   clients, check both A and AAAA answers so the client uses the intended path.

Use `sudo systemctl restart rs-proxy` after config changes and
`sudo journalctl -u rs-proxy -f` to see startup errors or DNS failures.
For a new binary, run the install command again and restart the service.

## Listeners and routing

| Traffic | Listener | How the proxy finds the hostname |
| --- | --- | --- |
| HTTPS, including HTTP/2 over TLS | TCP, usually `443` | TLS ClientHello SNI |
| Plain HTTP/1.x | TCP, usually `80` | HTTP `Host` header |
| QUIC v1/v2 | UDP, usually `443` | TLS ClientHello in QUIC Initial packets |

Add one `[[listeners]]` block per address, port, and transport. To add QUIC
alongside HTTPS, add a UDP listener on the same IP and port. Start with TCP
when setting up a new host. QUIC stays on one client address and port, and
upstream responses are limited to three times the bytes received from the
client throughout the session.

Traffic with ECH, a missing hostname, or an unsupported handshake is
discarded. Configure clients to connect to the target hostname through their
normal DNS path. The HTTP inspector expects origin-form requests and does
not handle HTTP CONNECT or SOCKS.

Private and reserved upstream addresses are blocked by default. For an
intentional private upstream, add a narrow CIDR under
`routing.allow_upstream_cidrs`. Optional source filtering uses
[Linux IPset and a systemd drop-in](packaging/README.md#ipset-source-filtering).

## Build from source

On Linux with Rust 1.88 or later and a C toolchain:

```sh
cargo build --locked --release
target/release/rs-proxy config validate --config config.example.toml
```

See [manual installation](packaging/README.md) for setting up the systemd
unit from a local build.
