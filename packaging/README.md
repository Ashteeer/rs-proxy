# Linux installation

These commands install a locally built binary and the supplied systemd unit.
They do not configure transparent interception or create/populate operator
IPset contents. Strict IPset policies do install lifecycle-owned filter rules
scoped to configured listeners; that optional boundary is described below.
The copied example listens on TCP at `127.0.0.1:443`. Edit it before startup
if the host must expose a different address, port, or protocol. The
[main README](../README.md) covers first-time client and DNS setup.

```bash
cargo build --locked --release

if ! getent passwd rs-proxy >/dev/null; then
  sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin rs-proxy
fi
getent group rs-proxy >/dev/null
sudo install -D -o root -g root -m 0755 target/release/rs-proxy /usr/local/sbin/rs-proxy
sudo install -d -o root -g rs-proxy -m 0750 /etc/rs-proxy
if ! sudo test -e /etc/rs-proxy/config.toml; then
  sudo install -o root -g rs-proxy -m 0640 config.example.toml /etc/rs-proxy/config.toml
else
  echo "preserving existing /etc/rs-proxy/config.toml"
fi
sudo install -D -o root -g root -m 0644 packaging/rs-proxy.service /etc/systemd/system/rs-proxy.service
```

Edit `/etc/rs-proxy/config.toml`, then validate and start it:

```bash
sudo -u rs-proxy /usr/local/sbin/rs-proxy config validate --config /etc/rs-proxy/config.toml
sudo systemctl daemon-reload
sudo systemctl enable --now rs-proxy.service
systemctl status rs-proxy.service
journalctl -u rs-proxy.service -f
```

The unit grants only `CAP_NET_BIND_SERVICE`, which permits low TCP and UDP
listener ports. Remove both capability lines when every listener uses port
1024 or higher. The service owns no writable application directory and reads
a root-owned configuration through the `rs-proxy` group.

## IPset source filtering

To filter clients, set `enabled = true` and name an existing `hash:ip` set
for each family you want to filter. `ipv4_set` uses `family inet` and
`ipv6_set` uses `family inet6`. An omitted set leaves that family open to
normal routing. A named set must be available at startup.

When at least one set is configured and enabled, install the supplied
capability drop-in and restart the unit. It grants broad `CAP_NET_ADMIN`
so the child `ipset save` process can read the configured sets. For
`not_found = "silent"`, `"reject"`,
or `"first_response"`, the same capability lets RS-Proxy install its owned
`iptables`/`ip6tables` rules before binding listeners and remove them during a
normal shutdown. `not_found = "allow"` performs snapshot admission only and
installs no firewall rules.

Install the distribution `ipset` package first; strict modes also require the
distribution `iptables` package (including `ip6tables` for IPv6 listeners).
The service accepts only OS-managed absolute tool paths under `/usr/sbin` or
`/sbin` and never searches `PATH` while holding `CAP_NET_ADMIN`. Native nft
sets are not operator-set substitutes; an `iptables-nft` frontend is acceptable
only when its legacy-IPset match is available. Missing tools, unreadable sets,
or failed rule setup fail startup closed.

From a checkout with the `--with-ipset` option, run
`sudo sh install.sh --with-ipset` to check kernel access from a temporary
systemd service and install the drop-in. Configure the set names under
`[ipset]` and restart the service.

To install the drop-in by hand:

```bash
sudo install -D -o root -g root -m 0644 packaging/rs-proxy-ipset.conf \
  /etc/systemd/system/rs-proxy.service.d/ipset.conf
sudo systemctl daemon-reload
sudo systemctl restart rs-proxy.service
```

If `ipset save` returns `Operation not permitted`, run
`sudo ipset save <set-name> >/dev/null` on the proxy host. If that succeeds,
check that the running service uses the drop-in and receives `CAP_NET_ADMIN`:

```bash
systemctl show rs-proxy -p DropInPaths -p AmbientCapabilities -p CapabilityBoundingSet
```

If the command also fails as root, check whether the host or container
grants `CAP_NET_ADMIN` in the network namespace containing the sets.

RS-Proxy never changes the configured operator `hash:ip` sets. Strict modes own
only marker-tagged `RSPX_*` chains and, for `first_response`, bounded `rspx_f*`
flow sets. They refuse an unmarked name collision, serialize one firewall owner
with `/run/rs-proxy/firewall.lock`, recover stale owned artifacts on startup,
and leave unrelated rules untouched. A hard crash can leave owned artifacts
until the next successful startup; do not manually remove them while the
service is active. The drop-in keeps the xtables lock file inside the unit's
writable runtime directory rather than making the rest of `/run` writable.

Keep the capability drop-in installed for the first successful startup after a
strict-mode crash, even when the intended next policy is `allow`. That
privileged startup with at least one enabled set can recover marker-owned IPv4
and IPv6 artifacts. Stop the service cleanly before setting
`enabled = false` and removing the
drop-in. Starting directly with IPset disabled has no `CAP_NET_ADMIN` and cannot
prove or remove rules left by a previous crashed process. A crash in the small
window before a new chain/set receives its ownership marker is deliberately
treated as a foreign reserved-name collision; inspect that artifact manually
instead of letting RS-Proxy guess ownership.

## Updating

Use a binary built with a pinned GitHub repository and Ed25519 public key.
An administrator can check, install, and activate a newer release with:

```bash
rs-proxy update --check
sudo rs-proxy --update
sudo systemctl restart rs-proxy
```

`-u` and `update` are aliases for installation. The updater verifies the
release signature, the binary's checksum and ELF architecture, then replaces
the executable atomically. The running service switches to it on restart.
Builds without pinned trust, including the initial v0.1.0 binaries, use the
release installer for upgrades.

### Signing release assets

Use the same release key for each update to a deployed build. Keep the
Ed25519 private key in the release operator's secret storage and pass its file
path through `RS_PROXY_UPDATE_SIGNING_KEY_FILE`. The public key and repository
are set at build time:

```bash
export RS_PROXY_UPDATE_REPOSITORY=Ashteeer/rs-proxy
export RS_PROXY_UPDATE_SIGNING_KEY_FILE=/path/to/release-key.pem
export RS_PROXY_UPDATE_PUBLIC_KEY="$(bash packaging/sign-release.sh --public-key)"
cargo build --locked --release --target x86_64-unknown-linux-musl
cargo build --locked --release --target aarch64-unknown-linux-musl
```

For both targets, copy the same executables used in the release archives to
the release asset directory as `rs-proxy-linux-x86_64` and
`rs-proxy-linux-aarch64`. Run
`bash packaging/sign-release.sh "$version" "$asset_dir"` with the version
from `Cargo.toml`. Include the raw executables, `rs-proxy-manifest.toml` and
`rs-proxy-manifest.toml.sig` alongside the usual installer assets in the
public GitHub release. The signer requires OpenSSL with Ed25519 support.

The updater also supports custom GNU/Linux builds whose signed manifest
contains a matching GNU target and binary. The public installer ships musl
builds for x86-64 and ARM64.
