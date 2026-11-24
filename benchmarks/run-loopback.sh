#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="${RS_PROXY_BENCH_OUT:-${repo_root}/bench-results/${run_id}}"
mkdir -p "${output_dir}"

if (( $# == 0 )); then
  set -- \
    --duration-secs "${RS_PROXY_BENCH_DURATION_SECS:-5}" \
    --concurrency "${RS_PROXY_BENCH_CONCURRENCY:-4}" \
    --payload-bytes "${RS_PROXY_BENCH_PAYLOAD_BYTES:-65536}" \
    --udp-payload-bytes "${RS_PROXY_BENCH_UDP_PAYLOAD_BYTES:-1200}" \
    --latency-samples "${RS_PROXY_BENCH_LATENCY_SAMPLES:-100}"
fi

cargo +1.88.0 build \
  --locked \
  --release \
  --manifest-path "${script_dir}/Cargo.toml"

binary="${script_dir}/target/release/rs-proxy-benchmarks"
source_manifest="${output_dir}/sources.sha256"
(
  cd "${repo_root}"
  {
    printf '%s\0' Cargo.toml Cargo.lock build.rs
    find src -type f -name '*.rs' -print0
    printf '%s\0' \
      benchmarks/Cargo.toml \
      benchmarks/Cargo.lock \
      benchmarks/build.rs \
      benchmarks/run-loopback.sh
    find benchmarks/src -type f -name '*.rs' -print0
  } | LC_ALL=C sort -z | xargs -0 sha256sum
) >"${source_manifest}"

{
  printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'command='
  printf '%q ' "${binary}" "$@"
  printf '\n'
  uname -a
  cat /etc/os-release
  lscpu
  rustc +1.88.0 --version --verbose
  cargo +1.88.0 --version
  printf 'ulimit_n=%s\n' "$(ulimit -n)"
  printf 'update_repository_build_env=%s\n' "${RS_PROXY_UPDATE_REPOSITORY:-<unset>}"
  if [[ -n "${RS_PROXY_UPDATE_PUBLIC_KEY:-}" ]]; then
    printf 'update_public_key_build_env_sha256=%s\n' \
      "$(printf '%s' "${RS_PROXY_UPDATE_PUBLIC_KEY}" | sha256sum | cut -d ' ' -f 1)"
  else
    printf 'update_public_key_build_env_sha256=<unset>\n'
  fi
  printf 'source_manifest_sha256=%s\n' "$(sha256sum "${source_manifest}" | cut -d ' ' -f 1)"
  printf '%s\n' 'source_hashes_begin'
  cat "${source_manifest}"
  printf '%s\n' 'source_hashes_end'
  sha256sum "${repo_root}/Cargo.lock" "${script_dir}/Cargo.lock" "${binary}"
} >"${output_dir}/environment.txt"

if [[ -x /usr/bin/time ]]; then
  /usr/bin/time -v -o "${output_dir}/time.txt" \
    "${binary}" "$@" | tee "${output_dir}/results.jsonl"
else
  printf '%s\n' '/usr/bin/time is unavailable; process resource metadata was not captured' \
    >"${output_dir}/time.txt"
  "${binary}" "$@" | tee "${output_dir}/results.jsonl"
fi

printf 'results=%s\n' "${output_dir}"
