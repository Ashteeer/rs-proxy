#!/usr/bin/env bash
set -euo pipefail

die() {
    printf 'sign-release: %s\n' "$*" >&2
    exit 1
}

if [[ $# -ne 2 && ( $# -ne 1 || "$1" != --public-key ) ]]; then
    die "usage: sign-release.sh --public-key | sign-release.sh <version> <asset-dir>"
fi

key_file=${RS_PROXY_UPDATE_SIGNING_KEY_FILE:?set the path to the release Ed25519 private key}
public_der=$(openssl pkey -in "$key_file" -pubout -outform DER | od -An -v -tx1 | tr -d '[:space:]')
# Ed25519 SubjectPublicKeyInfo wraps the raw 32-byte key in this fixed header.
if [[ ! "$public_der" =~ ^302a300506032b6570032100([0-9a-f]{64})$ ]]; then
    die "the release signing key must be Ed25519"
fi
public_key=${BASH_REMATCH[1]}
if [[ "$1" == --public-key ]]; then
    [[ $# -eq 1 ]] || die "--public-key takes no arguments"
    printf '%s\n' "$public_key"
    exit 0
fi

repository=${RS_PROXY_UPDATE_REPOSITORY:?set the same owner/repository used for the build}
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "expected owner/repository"
version=${1#v}
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "expected a stable version such as 1.2.3"

asset_dir=$2
stage=$(mktemp -d "$asset_dir/.rs-proxy-sign.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
manifest="$stage/rs-proxy-manifest.toml"
signature="$stage/rs-proxy-manifest.toml.sig"
{
    printf 'schema = 1\nrepository = "%s"\nversion = "%s"\n' "$repository" "$version"
    for arch in x86_64 aarch64; do
        asset="rs-proxy-linux-$arch"
        checksum=$(sha256sum -- "$asset_dir/$asset")
        printf '\n[[assets]]\ntarget = "%s-unknown-linux-musl"\nname = "%s"\nsha256 = "%s"\n' \
            "$arch" "$asset" "${checksum%% *}"
    done
} > "$manifest"

openssl pkeyutl -sign -rawin -inkey "$key_file" -in "$manifest" |
    od -An -v -tx1 | tr -d '[:space:]' > "$signature"
[[ $(wc -c < "$signature") -eq 128 ]] || die "invalid Ed25519 signature length"
chmod 0644 "$manifest" "$signature"
mv -f -- "$manifest" "$signature" "$asset_dir/"
