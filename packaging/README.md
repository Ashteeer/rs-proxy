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

When `[ipset] enabled = true`, install the supplied capability drop-in and
restart the unit. It grants broad `CAP_NET_ADMIN` so the child `ipset save`
process can read both existing sets. For `not_found = "silent"`, `"reject"`,
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

```bash
sudo install -D -o root -g root -m 0644 packaging/rs-proxy-ipset.conf \
  /etc/systemd/system/rs-proxy.service.d/ipset.conf
sudo systemctl daemon-reload
sudo systemctl restart rs-proxy.service
```

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
privileged startup can recover marker-owned IPv4 and IPv6 artifacts and should
then be stopped cleanly before setting `enabled = false` and removing the
drop-in. Starting directly with IPset disabled has no `CAP_NET_ADMIN` and cannot
prove or remove rules left by a previous crashed process. A crash in the small
window before a new chain/set receives its ownership marker is deliberately
treated as a foreign reserved-name collision; inspect that artifact manually
instead of letting RS-Proxy guess ownership.

## Updating

An ordinary source build intentionally has no update repository or signing
key. Both `update` forms then fail before network or filesystem I/O. A release
authority enables authenticated updates only by pinning both values at build
time; runtime environment variables cannot redirect the installed binary:

```bash
RS_PROXY_UPDATE_REPOSITORY='<owner>/<repository>' \
RS_PROXY_UPDATE_PUBLIC_KEY='<64 hexadecimal characters: raw Ed25519 public key>' \
cargo build --locked --release
```

For such a trust-configured build, `update --check` authenticates release
metadata without replacing the executable:

```bash
sudo -u rs-proxy /usr/local/sbin/rs-proxy update --check
```

The built-in transport has no GitHub token or other credential support, so this
live path is limited to public release repositories.

The installed executable is root-owned, so an actual update is an explicit
administrator operation. Stop the service, run the updater as root, and start
the service explicitly; the updater never executes the new binary or restarts
the service itself. If the update fails, its atomic replacement/rollback path
keeps the old executable available, so start the service again after reviewing
the reported error.

```bash
sudo systemctl stop rs-proxy.service
sudo /usr/local/sbin/rs-proxy update
sudo systemctl start rs-proxy.service
```

For an ordinary build without pinned trust, stop the service, install a locally
verified replacement with the installation command above, and start it again.
Re-running the installation block preserves an existing
`/etc/rs-proxy/config.toml`.
