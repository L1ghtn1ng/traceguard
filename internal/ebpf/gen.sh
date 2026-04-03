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

go run github.com/cilium/ebpf/cmd/bpf2go \
  -no-strip \
  -cc clang \
  -cflags "${cflags[*]}" \
  traceguard \
  "$script_dir/bpf/traceguard.c" \
  -- \
  -target bpfel

go run github.com/cilium/ebpf/cmd/bpf2go \
  -no-strip \
  -cc clang \
  -cflags "${cflags[*]}" \
  traceguardDNSCompat \
  "$script_dir/bpf/traceguard.c" \
  -- \
  -DTRACEGUARD_DNS_NO_CURRENT_COMM=1 \
  -target bpfel

go run github.com/cilium/ebpf/cmd/bpf2go \
  -no-strip \
  -cc clang \
  -cflags "${cflags[*]}" \
  traceguardRecvmsgCompat \
  "$script_dir/bpf/traceguard.c" \
  -- \
  -DTRACEGUARD_CONNECTION_NO_RECVMSG=1 \
  -target bpfel

go run github.com/cilium/ebpf/cmd/bpf2go \
  -no-strip \
  -cc clang \
  -cflags "${cflags[*]}" \
  traceguardDNSRecvmsgCompat \
  "$script_dir/bpf/traceguard.c" \
  -- \
  -DTRACEGUARD_DNS_NO_CURRENT_COMM=1 \
  -DTRACEGUARD_CONNECTION_NO_RECVMSG=1 \
  -target bpfel
