# TraceGuard
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/L1ghtn1ng/traceguard) [![Go Report](https://goreportcard.com/badge/github.com/L1ghtn1ng/traceguard)](https://goreportcard.com/report/github.com/L1ghtn1ng/traceguard)

TraceGuard is a Go 1.26 Linux security utility that uses the kernel eBPF subsystem to:

- observe outbound DNS queries on UDP and TCP port 53
- report the process that issued the DNS request
- enrich events with process path, argv, UID, PPID, and parent process metadata from `/proc`
- enrich events with SELinux context or AppArmor profile data when exposed by `/proc/<pid>/attr`
- detect outbound DNS-over-TLS resolver connections
- detect configured DNS-over-HTTPS resolver connections
- trace `execve` and `execveat` activity so newly spawned programs are visible
- audit file access through open-style syscall tracepoints when enabled
- optionally block DNS lookups for domains loaded from a local or remote blocklist
- apply exact-match allow rules that take precedence over exact-match block rules
- support suffix policies such as `*.example.com` and `suffix:example.com`
- expose health and Prometheus-style metrics over HTTP
- optionally archive JSON events locally and export them to an HTTPS collector
- support batched authenticated HTTPS export with durable retry spooling
- export structured events to remote syslog over UDP, TCP, or TLS
- support optional `Authorization` headers and mTLS for HTTPS event export
- optionally enrich pod-scoped events with Kubernetes namespace, pod, node, workload, service account, container, and image metadata
- run a built-in environment doctor check before deployment

In block mode, TraceGuard caches the remote blocklist for six hours by default and refreshes it on the same cadence.

## Design

TraceGuard uses two eBPF programs:

- `cgroup_skb/egress` parses outbound UDP and TCP DNS packets on port 53, emits DNS telemetry, and drops matching queries when blocking is enabled
- `cgroup/connect4` and `cgroup/connect6` observe resolver endpoint connections for DoT and configured DoH endpoints and block matching endpoints when blocking is enabled
- `tracepoint/syscalls/sys_enter_execve*` emits process execution events
- `tracepoint/syscalls/sys_enter_open*` and `sys_enter_creat` emit file access audit events when file auditing is enabled

The user-space service:

- normalizes blocklist input before loading it into a BPF hash map
- supports `block:` and `allow:` policy entries in local and remote rule sources
- supports exact and suffix domain rules in the policy engine
- caches the remote blocklist on disk with atomic file replacement
- enriches event records from `/proc` using a bounded metadata cache
- adds SELinux/AppArmor process labels to enriched records where the host LSM exposes them
- can archive structured events to a local JSONL file with rotation
- can export structured events to an HTTPS endpoint in batches
- can persist failed export batches to disk for later replay
- can send structured events to remote syslog collectors in RFC5424-style messages
- can enrich pod-scoped events from the Kubernetes API using the existing `pod_uid` signal
- emits newline-delimited JSON records by default and can also emit text logs
- exports `/health` and `/metrics` when a metrics address is configured
- uses bounded parsing and fixed-size buffers throughout the BPF program
- avoids shelling out or executing fetched content

## Requirements

- Linux 6.12 or newer with cgroup v2 mounted at `/sys/fs/cgroup`
- eBPF support for cgroup egress and tracepoints
- privileges equivalent to `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_ADMIN` and `CAP_SYS_RESOURCE`
- tracepoint perf-event access for syscall probes, which may require lowering `kernel.perf_event_paranoid` when `CAP_PERFMON` is unavailable
- Go 1.26
- `clang` for `go generate`

Notes:

- blocking is exact-match on normalized DNS QNAMEs for classic UDP/TCP DNS on port 53
- allow rules take precedence over block rules; plain domain allow rules are exact matches, while `*.example.com` and `suffix:example.com` allow suffix matches
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
- enforced blocked events are also written as JSON to `blocked.log` in the same log directory, with the same rotation policy
- first-seen DNS query domains are written once to `domains.log` in the same log directory as timestamped domain lines, with the same rotation policy
- process metadata is cached from `/proc` with pidfd identity tracking and a bounded 4,096-entry LRU cache
- SELinux/AppArmor labels are read from `/proc/<pid>/attr/current` and `/proc/<pid>/attr/apparmor/current` when available
- file access auditing is enabled by default in packaged deployments; disable it with `TRACEGUARD_FILE_AUDIT=false` if open-style syscall volume is too high for the host
- Kubernetes enrichment is optional, API-driven, and keyed by the observed pod UID
- common IPv6 extension headers are parsed before DNS inspection
- in block mode, segmented TCP DNS queries, fragmented IPv6 DNS packets, and unparseable IPv4 or IPv6 UDP DNS payloads are denied instead of allowed
- kernel policy refreshes are published atomically, so packet and connection hooks see either the previous complete policy or the next complete policy
- event timestamps represent kernel event occurrence time and are converted from `CLOCK_BOOTTIME` to UTC wall time in userspace
- `/health` returns HTTP 503 after a critical local event sink write failure and recovers after that sink writes successfully; enforcement continues while unhealthy
- exact domain policies and suffix allow policies are enforceable in kernel block mode; suffix block policies are available for observe and dry-run workflows but are rejected in enforced block mode on this kernel path
- in enforced block mode with `*`, exact domain rules, suffix allow domain rules, DoH/DoT endpoint rules, and resolver IP/CIDR rules are supported as exceptions
- enforced suffix allow matching checks up to 16 DNS label boundaries and 64 wire-format bytes per suffix candidate to stay within kernel verifier limits; exact allow rules are unaffected
- event archive and export use the same structured event records as the logger
- event export can use custom trust roots, client certificates, and durable retry spooling
- on Linux 7.1 or newer, TraceGuard automatically tries an enhanced telemetry eBPF object that adds event source and kernel feature-set fields; if the kernel or verifier rejects that object, TraceGuard falls back to the standard object without user configuration

## Build

```bash
go generate ./internal/ebpf
go test ./...
make build
```

Common targets:

```bash
make generate
make test
make build
make snapshot
```

`make build` produces a hardened Linux binary with PIE enabled and the C
toolchain configured for link-time optimization, stack protection on all C
functions, `_FORTIFY_SOURCE=2`, RELRO, BIND_NOW, and a non-executable stack.

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
  -block-domain '*' \
  -allow-domain corp.example \
  -allow-domain '*.trusted.example' \
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

Load manual block and allow entries from files:

```bash
sudo ./traceguard -block \
  -block-domain @/etc/traceguard/block-domains.txt \
  -allow-domain @/etc/traceguard/allow-domains.txt
```

Print the program version:

```bash
./traceguard -v
```

Run diagnostics:

```bash
./traceguard -doctor
```

Enable file access auditing when running the binary without the packaged env file:

```bash
sudo ./traceguard \
  -file-audit
```

Enable Kubernetes enrichment on a node:

```bash
sudo ./traceguard \
  -kubernetes-enrich \
  -kubernetes-node-name "$(hostname)"
```

When running in Kubernetes, `-kubernetes-enrich` can infer the API URL from
`KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT_HTTPS`, and it uses the
standard service-account token and CA paths by default. Set
`TRACEGUARD_KUBERNETES_NODE_NAME`, or expose `NODE_NAME` through the downward API,
to scope pod metadata listing to one node.

Use the packaged JSON output and metrics defaults:

```bash
sudo ./traceguard \
  -log-format json \
  -metrics-addr :9091
```

Archive events locally:

```bash
sudo ./traceguard \
  -event-archive-path /var/lib/traceguard/events.jsonl
```

Use HTTPS batch export when a SIEM, data lake, webhook collector, or other
remote service should receive structured events reliably. TraceGuard sends each
request as a JSON array of event records, batches events to reduce request
volume, and can spool failed batches to disk for later replay. Use local archive
for host-local retention only, and use remote syslog for simpler best-effort
forwarding.

Minimal HTTPS batch export:

```bash
sudo ./traceguard \
  -event-export-url https://collector.example/api/traceguard
```

Production HTTPS batch export with auth and durable retry:

```bash
sudo ./traceguard \
  -event-export-url https://siem.example/api/traceguard \
  -event-export-authorization 'Bearer secret-token' \
  -event-export-spool
```

Use a private CA and mTLS for the HTTPS event collector:

```bash
sudo ./traceguard \
  -event-export-url https://siem.example/api/traceguard \
  -event-export-ca-path /etc/traceguard/siem-ca.crt \
  -event-export-client-cert /etc/traceguard/siem-client.crt \
  -event-export-client-key /etc/traceguard/siem-client.key
```

Export events to a remote syslog collector:

```bash
sudo ./traceguard \
  -event-syslog-url syslog+tls://syslog.example:6514 \
  -event-syslog-facility local0 \
  -event-syslog-ca-path /etc/traceguard/syslog-ca.crt
```

Remote syslog supports `syslog+udp://`, `syslog+tcp://`, and `syslog+tls://`
URLs. It is best-effort and does not spool failed sends; use HTTPS export when
durable retry is required.

Environment variables can be used instead of flags:

- `TRACEGUARD_BLOCK`
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
- `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION`
- `TRACEGUARD_EVENT_EXPORT_SPOOL`
- `TRACEGUARD_EVENT_EXPORT_CA_PATH`
- `TRACEGUARD_EVENT_EXPORT_CLIENT_CERT`
- `TRACEGUARD_EVENT_EXPORT_CLIENT_KEY`
- `TRACEGUARD_EVENT_SYSLOG_URL`
- `TRACEGUARD_EVENT_SYSLOG_FACILITY`
- `TRACEGUARD_EVENT_SYSLOG_TAG`
- `TRACEGUARD_EVENT_SYSLOG_TIMEOUT`
- `TRACEGUARD_EVENT_SYSLOG_CA_PATH`
- `TRACEGUARD_PROCESS_CACHE_TTL`
- `TRACEGUARD_FILE_AUDIT`
- `TRACEGUARD_KUBERNETES_ENRICH`
- `TRACEGUARD_KUBERNETES_API_URL`
- `TRACEGUARD_KUBERNETES_TOKEN_PATH`
- `TRACEGUARD_KUBERNETES_CA_PATH`
- `TRACEGUARD_KUBERNETES_NODE_NAME`
- `TRACEGUARD_KUBERNETES_POLL_INTERVAL`

By default, TraceGuard logs in JSON. Use `-log-format text` or `TRACEGUARD_LOG_FORMAT=text` to switch back to text output.

Packaged defaults in `/etc/traceguard/traceguard.env`:

- observe-only mode: `TRACEGUARD_BLOCK=false` and `TRACEGUARD_DRY_RUN=false`
- remote blocklist disabled: `TRACEGUARD_BLOCKLIST_URL=`
- cache path: `TRACEGUARD_CACHE_PATH=/var/lib/traceguard/blocklist.txt`
- refresh interval: `TRACEGUARD_REFRESH_INTERVAL=6h`
- cgroup path: `TRACEGUARD_CGROUP_PATH=/sys/fs/cgroup`
- log path and format: `TRACEGUARD_LOG_PATH=/var/log/traceguard/traceguard.log`, `TRACEGUARD_LOG_FORMAT=json`
- first-seen DNS query domains are also retained in `/var/log/traceguard/domains.log`; this is a deduplicated DNS-domain inventory, not full HTTP URL/path capture
- metrics enabled on `TRACEGUARD_METRICS_ADDR=:9091`
- local event archive disabled unless `TRACEGUARD_EVENT_ARCHIVE_PATH` is set
- durable HTTPS batch export disabled unless `TRACEGUARD_EVENT_EXPORT_URL` is set
- HTTPS export sends batches of 50 events or every 5 seconds
- HTTPS export spooling enabled by default with `TRACEGUARD_EVENT_EXPORT_SPOOL=true`; failed batches are stored in `/var/lib/traceguard/export-spool` with a 1 MiB per-batch limit and 256 MiB total spool limit
- remote syslog export disabled unless `TRACEGUARD_EVENT_SYSLOG_URL` is set; defaults: `TRACEGUARD_EVENT_SYSLOG_FACILITY=local0`, `TRACEGUARD_EVENT_SYSLOG_TAG=traceguard`, `TRACEGUARD_EVENT_SYSLOG_TIMEOUT=5s`
- process cache TTL: `TRACEGUARD_PROCESS_CACHE_TTL=5m`
- file audit enabled: `TRACEGUARD_FILE_AUDIT=true`
- Kubernetes enrichment disabled: `TRACEGUARD_KUBERNETES_ENRICH=false`; when enabled without an explicit API URL, TraceGuard auto-detects the in-cluster API endpoint

Manual policy inputs:

- Use `-block-domain` and `-allow-domain` repeatedly for inline entries.
- Use `-block-domain @/abs/path` and `-allow-domain @/abs/path` to load entries from files.
- Use `TRACEGUARD_BLOCK_DOMAINS` and `TRACEGUARD_ALLOW_DOMAINS` for env-based configuration.
- Set `TRACEGUARD_BLOCK_DOMAINS=@/abs/path` or `TRACEGUARD_ALLOW_DOMAINS=@/abs/path` to load entries from files.
- Use `*` as the deny-all marker with `-block-domain '*'` or `TRACEGUARD_BLOCK_DOMAINS=*`.
- Use `example.com` with `-allow-domain` for an exact exception only; it does not allow `foo.example.com`.
- Use `*.example.com` or `suffix:example.com` with `-allow-domain` for enforced block-mode exceptions that cover a domain and its subdomains.

Example output:

```text
2026/03/16 08:17:20 dns level="info" cgroup="/kubepods.slice/kubepods-burstable.slice/pod12345678_1234_1234_1234_123456789abc.slice/cri-containerd-0123.scope" cmdline=["/usr/bin/dig","example.com"] domain="example.com" event="dns" exe="/usr/bin/dig" k8s_app="dns-client" k8s_containers=["app","sidecar"] k8s_images=["ghcr.io/example/app:v1","ghcr.io/example/sidecar:v2"] k8s_namespace="default" k8s_node="worker-1" k8s_owner="dns-client-7f4b6d" k8s_owner_kind="ReplicaSet" k8s_pod="dns-client" k8s_pod_ip="10.0.0.12" k8s_service_account="dns-client" parent_program="bash" pid=31742 pod_uid="12345678-1234-1234-1234-123456789abc" ppid=31680 program="dig" runtime="containerd" service="cri-containerd-0123.scope" transport="udp" uid=1000
2026/03/16 08:17:21 blocked-doh level="info" address="8.8.8.8" container_id="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" endpoint="dns.google" event="resolver_blocked" exe="/usr/bin/curl" parent_program="python3" pid=31811 policy="block" port=443 program="curl" transport="doh" uid=1000
2026/03/16 08:17:22 would-block level="info" cmdline=["/usr/bin/dig","api.example.com"] domain="api.example.com" event="dns" exe="/usr/bin/dig" mode="dry-run" pid=31742 pod_uid="12345678-1234-1234-1234-123456789abc" policy="block" program="dig" runtime="containerd" transport="udp" uid=1000
2026/03/16 08:17:23 file_access level="info" apparmor_mode="enforce" apparmor_profile="traceguard-default" event="file_access" exe="/usr/bin/cat" file_access="read" file_flags=0 file_mode=0 lsm_label="traceguard-default (enforce)" lsm_source="apparmor" path="/etc/passwd" pid=31900 program="cat" uid=1000
2026/03/16 08:17:24 file_created level="info" apparmor_mode="enforce" apparmor_profile="traceguard-default" event="file_created" exe="/usr/bin/touch" file_access="write" file_flags=64 file_mode=420 lsm_label="traceguard-default (enforce)" lsm_source="apparmor" path="/tmp/example" pid=31901 program="touch" uid=1000
```

Example JSON output:

```json
{"timestamp":"2026-03-16T08:17:20.123456Z","level":"info","message":"dns","event":"dns","program":"dig","pid":31742,"exe":"/usr/bin/dig","cmdline":["/usr/bin/dig","example.com"],"uid":1000,"ppid":31680,"parent_program":"bash","cgroup":"/kubepods.slice/kubepods-burstable.slice/pod12345678_1234_1234_1234_123456789abc.slice/cri-containerd-0123.scope","service":"cri-containerd-0123.scope","pod_uid":"12345678-1234-1234-1234-123456789abc","runtime":"containerd","k8s_namespace":"default","k8s_pod":"dns-client","k8s_node":"worker-1","k8s_pod_ip":"10.0.0.12","k8s_service_account":"dns-client","k8s_owner_kind":"ReplicaSet","k8s_owner":"dns-client-7f4b6d","k8s_app":"dns-client","k8s_containers":["app","sidecar"],"k8s_images":["ghcr.io/example/app:v1","ghcr.io/example/sidecar:v2"],"domain":"example.com","transport":"udp"}
{"timestamp":"2026-03-16T08:17:23.123456Z","level":"info","message":"file_access","event":"file_access","program":"cat","pid":31900,"exe":"/usr/bin/cat","uid":1000,"lsm_label":"system_u:system_r:user_t:s0","lsm_source":"selinux","selinux_context":"system_u:system_r:user_t:s0","path":"/etc/passwd","file_flags":0,"file_mode":0,"file_access":"read"}
{"timestamp":"2026-03-16T08:17:24.123456Z","level":"info","message":"file_created","event":"file_created","program":"touch","pid":31901,"exe":"/usr/bin/touch","uid":1000,"lsm_label":"system_u:system_r:user_t:s0","lsm_source":"selinux","selinux_context":"system_u:system_r:user_t:s0","path":"/tmp/example","file_flags":64,"file_mode":420,"file_access":"write"}
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
- metrics on the configured listen address, `:9091` by default in the packaged env file

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
- Process enrichment includes SELinux contexts and AppArmor profile/mode where the host exposes those labels through `/proc`.
- File access auditing records open-style syscall path, flags, mode, and read/write intent. Opens with create intent are emitted as `file_created`; other opens are emitted as `file_access`. It is enabled by the packaged env file with `TRACEGUARD_FILE_AUDIT=true`; disable it when retained path data or event volume is not acceptable.
- Repeated file access audit records are deduplicated for 5 minutes using stable file, process, container/pod, and SELinux/AppArmor label fields so short-lived PID churn does not spam logs with unchanged LSM-attributed entries.
- Process enrichment now also extracts pod UID and runtime hints from common Kubernetes/container cgroup layouts when present.
- Optional Kubernetes API enrichment can add namespace, pod name, pod IP, node name, service account, controller workload, app label, container names, and image names keyed by the observed pod UID.
- `dry-run` uses the same policy engine as enforcement mode but logs `would-block` decisions instead of enabling kernel drops.
- `SIGHUP` triggers an immediate policy reload from local and remote sources.
- Metrics and health endpoints are served when `-metrics-addr` is set. The packaged env file enables them on `:9091`.
- Metrics include event volume, policy decisions, blocklist refresh/load status, policy size and mode, eBPF attachment/read health, export queue and spool backlog, process attribution quality, Kubernetes refreshes, and enrichment hit/miss counts.
- HTTPS batch export requires an HTTPS endpoint and uses bounded in-memory queuing to avoid blocking the main event loop.
- HTTPS batch export sends records as JSON arrays, supports an optional `Authorization` header, optional mTLS, and can spool failed batches to disk for replay.
- Remote syslog export sends RFC5424-style structured events over UDP, TCP, or TLS without durable spooling.
- Kubernetes enrichment uses HTTPS, a bearer token, bounded response sizes, and a periodic cache refresh instead of live per-event API calls.
- Encrypted DoH and DoT traffic is handled at the resolver-endpoint level; the implementation does not attempt TLS interception or decryption.
