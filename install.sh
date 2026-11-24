#!/bin/sh
set -eu
umask 077

version=v0.1.1
release_url="https://github.com/Ashteeer/rs-proxy/releases/download/$version"
config=/etc/rs-proxy/config.toml
binary=/usr/local/sbin/rs-proxy
unit=/etc/systemd/system/rs-proxy.service
ipset_unit=/etc/systemd/system/rs-proxy.service.d/ipset.conf

die() {
    printf 'rs-proxy: %s\n' "$*" >&2
    exit 1
}

with_ipset=false
case "${1-}" in
    --with-ipset) with_ipset=true; shift ;;
    -h|--help) printf 'Usage: sh install.sh [--with-ipset]\n'; exit 0 ;;
esac
[ "$#" -eq 0 ] || die "usage: sh install.sh [--with-ipset]"

[ "$(uname -s)" = Linux ] || die "Linux is required"
case "$(uname -m)" in
    x86_64) arch=x86_64 ;;
    aarch64) arch=aarch64 ;;
    *) die "supported architectures: x86_64 and aarch64" ;;
esac
[ "$(id -u)" -eq 0 ] || die "run this installer with sudo"
[ -d /run/systemd/system ] || die "systemd must be running"
for command in curl sha256sum tar getent install systemctl; do
    command -v "$command" >/dev/null || die "missing command: $command"
done

if "$with_ipset"; then
    command -v systemd-run >/dev/null || die "missing command: systemd-run"
    ipset_command=/usr/sbin/ipset
    if [ ! -f "$ipset_command" ] || [ ! -x "$ipset_command" ]; then
        ipset_command=/sbin/ipset
    fi
    if [ ! -f "$ipset_command" ] || [ ! -x "$ipset_command" ]; then
        die "install the ipset package first"
    fi
fi

archive="rs-proxy-linux-$arch.tar.gz"
work_dir=$(mktemp -d)
new_binary=
cleanup() {
    if [ -n "$new_binary" ]; then
        rm -f -- "$new_binary"
    fi
    rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
cd "$work_dir"

curl -fsSL --retry 3 --proto '=https' --proto-redir '=https' -O \
    "$release_url/$archive"
curl -fsSL --retry 3 --proto '=https' --proto-redir '=https' -O \
    "$release_url/$archive.sha256"
sha256sum --check --status "$archive.sha256" || die "archive checksum failed"
tar -xzf "$archive" rs-proxy config.example.toml rs-proxy.service

if "$with_ipset"; then
    curl -fsSL --retry 3 --proto '=https' --proto-redir '=https' -O \
        "https://raw.githubusercontent.com/Ashteeer/rs-proxy/$version/packaging/rs-proxy-ipset.conf"
fi

if [ -e "$config" ] || [ -L "$config" ]; then
    check_config=$config
else
    check_config=config.example.toml
fi
./rs-proxy config validate --config "$check_config"

if ! getent passwd rs-proxy >/dev/null; then
    command -v useradd >/dev/null || die "missing command: useradd"
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin rs-proxy
fi
getent group rs-proxy >/dev/null || die "missing rs-proxy group"

if "$with_ipset"; then
    # Check the kernel from a service running with the same IPset capability.
    systemd-run --quiet --wait --collect --pipe --service-type=exec \
        --property=User=rs-proxy --property=Group=rs-proxy \
        --property=AmbientCapabilities=CAP_NET_ADMIN \
        --property=CapabilityBoundingSet=CAP_NET_ADMIN \
        --property=NoNewPrivileges=yes --property=RuntimeMaxSec=10s \
        -- "$ipset_command" list -name >/dev/null ||
        die "systemd could not read IPset with CAP_NET_ADMIN; check host or container permissions"
fi

if [ "$check_config" != "$config" ]; then
    install -d -o root -g rs-proxy -m 0750 /etc/rs-proxy
    install -o root -g rs-proxy -m 0640 config.example.toml "$config"
fi

install -d /usr/local/sbin
new_binary=$(mktemp /usr/local/sbin/.rs-proxy.XXXXXXXX)
install -o root -g root -m 0755 rs-proxy "$new_binary"
mv -fT -- "$new_binary" "$binary"
new_binary=
install -o root -g root -m 0644 rs-proxy.service "$unit"
if "$with_ipset"; then
    if [ -e "$ipset_unit" ] && ! cmp -s rs-proxy-ipset.conf "$ipset_unit"; then
        cp -a -- "$ipset_unit" "$ipset_unit.bak"
    fi
    install -D -o root -g root -m 0644 rs-proxy-ipset.conf "$ipset_unit"
fi
systemctl daemon-reload

printf '\nInstalled rs-proxy %s.\n' "$version"
printf 'Configuration: %s\n' "$config"
if "$with_ipset"; then
    printf 'IPset access:  %s\n' "$ipset_unit"
fi
printf 'First start:   sudo systemctl enable --now rs-proxy\n'
printf 'After upgrade: sudo systemctl restart rs-proxy\n'
