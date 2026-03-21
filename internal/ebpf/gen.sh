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

cflags=("-O2" "-g" "-Wall" "-Werror")
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
