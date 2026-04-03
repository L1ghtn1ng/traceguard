# TraceGuard

TraceGuard is a Go 1.26 Linux security utility that uses the kernel eBPF subsystem to:

- observe outbound DNS queries on UDP and TCP port 53
- report the process that issued the DNS request
- enrich events with process path, argv, UID, PPID, and parent process metadata from `/proc`
- detect outbound DNS-over-TLS resolver connections
- detect configured DNS-over-HTTPS resolver connections
- trace `execve` and `execveat` activity so newly spawned programs are visible
- optionally block DNS lookups for domains loaded from a local or remote blocklist
- apply exact-match allow rules that take precedence over exact-match block rules
- support suffix policies such as `*.example.com` and `suffix:example.com`
- expose health and Prometheus-style metrics over HTTP
- optionally archive JSON events locally and export them to an HTTPS collector
- support batched authenticated HTTPS export with durable retry spooling
- support optional gzip and mTLS for HTTPS event export
- optionally enrich pod-scoped events with Kubernetes namespace, pod, node, workload, service account, container, and image metadata
- run a built-in environment doctor check before deployment

In block mode, TraceGuard caches the remote blocklist for six hours by default and refreshes it on the same cadence.

## Design

TraceGuard uses two eBPF programs:

- `cgroup_skb/egress` parses outbound UDP and TCP DNS packets on port 53, emits DNS telemetry, and drops matching queries when blocking is enabled
- `cgroup/connect4` and `cgroup/connect6` observe resolver endpoint connections for DoT and configured DoH endpoints and block matching endpoints when blocking is enabled
- `tracepoint/syscalls/sys_enter_execve*` emits process execution events

The user-space service:

- normalizes blocklist input before loading it into a BPF hash map
- supports `block:` and `allow:` policy entries in local and remote rule sources
- supports exact and suffix domain rules in the policy engine
- caches the remote blocklist on disk with atomic file replacement
- enriches event records from `/proc` using a bounded metadata cache
- can archive structured events to a local JSONL file with rotation
- can export structured events to an HTTPS endpoint in batches
- can persist failed export batches to disk for later replay
- can enrich pod-scoped events from the Kubernetes API using the existing `pod_uid` signal
- emits newline-delimited JSON records by default and can also emit text logs
- exports `/health` and `/metrics` when a metrics address is configured
- uses bounded parsing and fixed-size buffers throughout the BPF program
- avoids shelling out or executing fetched content

## Requirements

- Linux with cgroup v2 mounted at `/sys/fs/cgroup`
- eBPF support for cgroup egress and tracepoints
- privileges equivalent to `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_ADMIN` and `CAP_SYS_RESOURCE`
- tracepoint perf-event access for `execve` probes, which may require lowering `kernel.perf_event_paranoid` when `CAP_PERFMON` is unavailable
- Go 1.26
- `clang` for `go generate`

Notes:

- blocking is exact-match on normalized DNS QNAMEs for classic UDP/TCP DNS on port 53
- allow rules are exact-match and take precedence over exact-match block rules
- suffix rules match a domain and any subdomain, for example `*.example.com` or `suffix:example.com`
- `*` enables a deny-all policy for DNS names and identifiable resolver traffic, with explicit allow rules punching holes back in
- DNS QNAME matching is ASCII case-insensitive
- DoT support is endpoint-based: TraceGuard can detect outbound connections to port 853 and block configured DoT resolver endpoints
- DoH support is endpoint-based: TraceGuard can detect and block configured HTTPS resolver endpoints, but it cannot recover the encrypted inner DNS query name
- wildcard resolver mode does not treat every HTTPS connection as DoH; port 443 is only classified when it matches an explicit DoH endpoint rule or CIDR
- DoT and DoH endpoint rules are configured with `dot://resolver.example` or `https://resolver.example/dns-query`; exact IPv4 and bracketed IPv6 endpoint literals are also supported
- bare IP literals such as `1.1.1.1` or `[2606:4700:4700::1111]` are treated as resolver exceptions for both DoH on 443 and DoT on 853
- bare CIDR literals such as `1.1.1.0/24` or `2606:4700:4700::/48` are treated the same way for resolver ranges on DoH 443 and DoT 853
- logs are written to `/var/log/traceguard/traceguard.log` by default, rotate at 1 GiB, and retain the last 5 rotated files
- process metadata is cached from `/proc` for 10 minutes by default to reduce lookup overhead
- Kubernetes enrichment is optional, API-driven, and keyed by the observed pod UID
- common IPv6 extension headers are parsed before DNS inspection
- in block mode, segmented TCP DNS queries and fragmented IPv6 DNS packets that cannot be safely inspected are denied instead of allowed
- exact domain policies are enforceable in kernel block mode; suffix and wildcard domain policies are available for observe and dry-run workflows but are rejected in enforced block mode on this kernel path
- in enforced block mode with `*`, exact domain rules, DoH/DoT endpoint rules, and resolver IP/CIDR rules are supported as exceptions; suffix allow rules still require observe or dry-run mode
- event archive and export use the same structured event records as the logger
- event export can use custom trust roots, client certificates, and gzip-compressed batches

## Build

```bash
go generate ./internal/ebpf
go test ./...
go build ./cmd/traceguard
```

Common targets:

```bash
make generate
make test
make build
make snapshot
```

## Usage

Observe only:

```bash
sudo ./traceguard
```

Block exact domains:

```bash
sudo ./traceguard -block \
  -block-domain example.com \
  -block-domain bad.example.org
```

Allow a resolver hostname even if it appears in a remote blocklist:

```bash
sudo ./traceguard -block \
  -blocklist-url https://security.example/blocklist.txt \
  -allow-domain resolver.corp.example
```

Deny all DNS names and resolver endpoints, then allow only explicit exceptions:

```bash
sudo ./traceguard -block \
  -block-all \
  -allow-domain corp.example \
  -allow-domain 1.1.1.1 \
  -allow-domain 1.1.1.0/24 \
  -allow-domain https://1.1.1.1/dns-query \
  -allow-domain dot://[2606:4700:4700::1111]
```

If you prefer the wildcard form directly, quote it so your shell does not expand it:

```bash
sudo ./traceguard -block -block-domain '*'
```

Dry-run the policy without enforcing drops:

```bash
sudo ./traceguard -dry-run \
  -block-domain '*.example.com'
```

Manually reload policy sources:

```bash
sudo kill -HUP $(pidof traceguard)
```

Block a DoH resolver endpoint and a DoT resolver endpoint:

```bash
sudo ./traceguard -block \
  -block-domain https://dns.google/dns-query \
  -block-domain dot://one.one.one.one
```

Block from a remote list with six-hour refresh:

```bash
sudo ./traceguard -block \
  -blocklist-url https://security.example/blocklist.txt \
  -cache-path /var/lib/traceguard/blocklist.txt \
  -refresh-interval 6h
```

Print the program version:

```bash
./traceguard -v
```

Run diagnostics:

```bash
./traceguard -doctor
```

Enable Kubernetes enrichment on a node:

```bash
sudo ./traceguard \
  -kubernetes-enrich \
  -kubernetes-api-url https://kubernetes.default.svc:443 \
  -kubernetes-node-name "$(hostname)"
```

Enable JSON output and metrics:

```bash
sudo ./traceguard \
  -log-format json \
  -metrics-addr :9090
```

Archive events locally and export them to a collector:

```bash
sudo ./traceguard \
  -log-format json \
  -event-archive-path /var/lib/traceguard/events.jsonl \
  -event-export-url https://siem.example/api/traceguard \
  -event-export-auth-token 'Bearer secret-token' \
  -event-export-gzip \
  -event-export-spool-path /var/lib/traceguard/export-spool
```

Use mTLS for the HTTPS event collector:

```bash
sudo ./traceguard \
  -event-export-url https://siem.example/api/traceguard \
  -event-export-ca-path /etc/traceguard/siem-ca.crt \
  -event-export-client-cert /etc/traceguard/siem-client.crt \
  -event-export-client-key /etc/traceguard/siem-client.key
```

Environment variables can be used instead of flags:

- `TRACEGUARD_BLOCK`
- `TRACEGUARD_BLOCK_ALL`
- `TRACEGUARD_DRY_RUN`
- `TRACEGUARD_BLOCKLIST_URL`
- `TRACEGUARD_BLOCK_DOMAINS`
- `TRACEGUARD_ALLOW_DOMAINS`
- `TRACEGUARD_CACHE_PATH`
- `TRACEGUARD_REFRESH_INTERVAL`
- `TRACEGUARD_CGROUP_PATH`
- `TRACEGUARD_LOG_PATH`
- `TRACEGUARD_LOG_FORMAT`
- `TRACEGUARD_METRICS_ADDR`
- `TRACEGUARD_EVENT_ARCHIVE_PATH`
- `TRACEGUARD_EVENT_EXPORT_URL`
- `TRACEGUARD_EVENT_EXPORT_AUTH_HEADER`
- `TRACEGUARD_EVENT_EXPORT_AUTH_TOKEN`
- `TRACEGUARD_EVENT_EXPORT_BATCH_SIZE`
- `TRACEGUARD_EVENT_EXPORT_FLUSH_INTERVAL`
- `TRACEGUARD_EVENT_EXPORT_SPOOL_PATH`
- `TRACEGUARD_EVENT_EXPORT_CA_PATH`
- `TRACEGUARD_EVENT_EXPORT_CLIENT_CERT`
- `TRACEGUARD_EVENT_EXPORT_CLIENT_KEY`
- `TRACEGUARD_EVENT_EXPORT_GZIP`
- `TRACEGUARD_PROCESS_CACHE_TTL`
- `TRACEGUARD_KUBERNETES_ENRICH`
- `TRACEGUARD_KUBERNETES_API_URL`
- `TRACEGUARD_KUBERNETES_TOKEN_PATH`
- `TRACEGUARD_KUBERNETES_CA_PATH`
- `TRACEGUARD_KUBERNETES_NODE_NAME`
- `TRACEGUARD_KUBERNETES_POLL_INTERVAL`

By default, TraceGuard logs in JSON. Use `-log-format text` or `TRACEGUARD_LOG_FORMAT=text` to switch back to text output.

Example output:

```text
2026/03/16 08:17:20 dns level="info" cgroup="/kubepods.slice/kubepods-burstable.slice/pod12345678_1234_1234_1234_123456789abc.slice/cri-containerd-0123.scope" cmdline=["/usr/bin/dig","example.com"] domain="example.com" event="dns" exe="/usr/bin/dig" k8s_app="dns-client" k8s_containers=["app","sidecar"] k8s_images=["ghcr.io/example/app:v1","ghcr.io/example/sidecar:v2"] k8s_namespace="default" k8s_node="worker-1" k8s_owner="dns-client-7f4b6d" k8s_owner_kind="ReplicaSet" k8s_pod="dns-client" k8s_pod_ip="10.0.0.12" k8s_service_account="dns-client" parent_program="bash" pid=31742 pod_uid="12345678-1234-1234-1234-123456789abc" ppid=31680 program="dig" runtime="containerd" service="cri-containerd-0123.scope" transport="udp" uid=1000
2026/03/16 08:17:21 blocked-doh level="info" address="8.8.8.8" container_id="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" endpoint="dns.google" event="resolver_blocked" exe="/usr/bin/curl" parent_program="python3" pid=31811 policy="block" port=443 program="curl" transport="doh" uid=1000
2026/03/16 08:17:22 would-block level="info" cmdline=["/usr/bin/dig","api.example.com"] domain="api.example.com" event="dns" exe="/usr/bin/dig" mode="dry-run" pid=31742 pod_uid="12345678-1234-1234-1234-123456789abc" policy="block" program="dig" runtime="containerd" transport="udp" uid=1000
```

Example JSON output:

```json
{"timestamp":"2026-03-16T08:17:20.123456Z","level":"info","message":"dns","event":"dns","program":"dig","pid":31742,"exe":"/usr/bin/dig","cmdline":["/usr/bin/dig","example.com"],"uid":1000,"ppid":31680,"parent_program":"bash","cgroup":"/kubepods.slice/kubepods-burstable.slice/pod12345678_1234_1234_1234_123456789abc.slice/cri-containerd-0123.scope","service":"cri-containerd-0123.scope","pod_uid":"12345678-1234-1234-1234-123456789abc","runtime":"containerd","k8s_namespace":"default","k8s_pod":"dns-client","k8s_node":"worker-1","k8s_pod_ip":"10.0.0.12","k8s_service_account":"dns-client","k8s_owner_kind":"ReplicaSet","k8s_owner":"dns-client-7f4b6d","k8s_app":"dns-client","k8s_containers":["app","sidecar"],"k8s_images":["ghcr.io/example/app:v1","ghcr.io/example/sidecar:v2"],"domain":"example.com","transport":"udp"}
```

## Packaging

GoReleaser is configured to build Linux archives plus:

- `.deb`
- `.rpm`
- `archlinux`

Run a local snapshot release with:

```bash
goreleaser release --snapshot --clean
```

The generated packages install:

- `/usr/bin/traceguard`
- `/etc/traceguard/traceguard.env`
- `/var/log/traceguard/traceguard.log` at runtime via the packaged service defaults
- a systemd unit at the distro-appropriate system path
- optional metrics on the configured listen address

## Secure Development Notes

- Dependencies are managed through Go modules and suitable for GoReleaser verifiable builds.
- Remote blocklist fetches use HTTPS only, bounded response sizes, and network timeouts.
- Oversized remote blocklists are rejected instead of being silently truncated.
- Remote blocklist redirects are limited and must remain on HTTPS.
- Log file creation rejects symlink targets and non-regular files to reduce log-path attacks.
- Cache reads reject symlinks, cache writes are atomic, and cached blocklists are written with restricted permissions.
- The BPF parser uses explicit bounds checks and fixed maximum sizes to satisfy the verifier and reduce parser risk.
- Block mode fails closed if blocked-event telemetry cannot be emitted or if TCP/IPv6 DNS traffic cannot be safely inspected.
- Process enrichment is performed from `/proc` in userspace; if a process exits before enrichment, TraceGuard falls back to kernel-provided task metadata.
- Process enrichment also extracts cgroup path, likely service unit, and container ID heuristics from `/proc/<pid>/cgroup`.
- Process enrichment now also extracts pod UID and runtime hints from common Kubernetes/container cgroup layouts when present.
- Optional Kubernetes API enrichment can add namespace, pod name, pod IP, node name, service account, controller workload, app label, container names, and image names keyed by the observed pod UID.
- `dry-run` uses the same policy engine as enforcement mode but logs `would-block` decisions instead of enabling kernel drops.
- `SIGHUP` triggers an immediate policy reload from local and remote sources.
- Metrics and health endpoints are served only when explicitly enabled with `-metrics-addr`.
- Event export requires an HTTPS endpoint and uses bounded in-memory queuing to avoid blocking the main event loop.
- Event export batches records as JSON arrays, supports a configurable auth header, optional gzip compression, optional mTLS, and can spool failed batches to disk for replay.
- Kubernetes enrichment uses HTTPS, a bearer token, bounded response sizes, and a periodic cache refresh instead of live per-event API calls.
- Encrypted DoH and DoT traffic is handled at the resolver-endpoint level; the implementation does not attempt TLS interception or decryption.
