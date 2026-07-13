#!/usr/bin/env bash
set -euo pipefail

script_dir=$(
  CDPATH= cd -- "$(dirname -- "$0")" && pwd
)

include_dirs=(
  "$script_dir/bpf/include"
)

for candidate in \
  "/usr/include/$(uname -m)-linux-gnu" \
  "/usr/include/$(clang -dumpmachine 2>/dev/null || true)" \
  "/usr/include/x86_64-linux-gnu" \
  "/usr/include/aarch64-linux-gnu"
do
  if [[ -n "$candidate" && -d "$candidate" ]]; then
    include_dirs+=("$candidate")
  fi
done

cflags=("-std=gnu2x" "-O2" "-g" "-Wall" "-Werror")
for dir in "${include_dirs[@]}"; do
  cflags+=("-I${dir}")
done

generate_variant() {
  local ident=$1
  shift

  go run github.com/cilium/ebpf/cmd/bpf2go \
    -no-strip \
    -target bpfel,bpfeb \
    -cc clang \
    -cflags "${cflags[*]}" \
    "$ident" \
    "$script_dir/bpf/traceguard.c" \
    -- \
    "$@"
}

generate_variant traceguardLinux71 \
  -DTRACEGUARD_LINUX71_TELEMETRY=1
generate_variant traceguardLinux71DNSCompat \
  -DTRACEGUARD_LINUX71_TELEMETRY=1 \
  -DTRACEGUARD_DNS_NO_CURRENT_COMM=1
generate_variant traceguardLinux71RecvmsgCompat \
  -DTRACEGUARD_LINUX71_TELEMETRY=1 \
  -DTRACEGUARD_CONNECTION_NO_RECVMSG=1
generate_variant traceguardLinux71DNSRecvmsgCompat \
  -DTRACEGUARD_LINUX71_TELEMETRY=1 \
  -DTRACEGUARD_DNS_NO_CURRENT_COMM=1 \
  -DTRACEGUARD_CONNECTION_NO_RECVMSG=1
generate_variant traceguard
generate_variant traceguardDNSCompat \
  -DTRACEGUARD_DNS_NO_CURRENT_COMM=1
generate_variant traceguardRecvmsgCompat \
  -DTRACEGUARD_CONNECTION_NO_RECVMSG=1
generate_variant traceguardDNSRecvmsgCompat \
  -DTRACEGUARD_DNS_NO_CURRENT_COMM=1 \
  -DTRACEGUARD_CONNECTION_NO_RECVMSG=1
