# TraceGuard
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/L1ghtn1ng/traceguard)

TraceGuard is a Go 1.27 Linux security utility that uses the kernel eBPF subsystem to:

- observe outbound DNS queries on UDP and TCP port 53
- report the process that issued the DNS request
- enrich events with process path, argv, UID, PPID, and parent process metadata from `/proc`
- enrich events with SELinux context or AppArmor profile data when exposed by `/proc/<pid>/attr`
- detect outbound DNS-over-TLS resolver connections
- detect configured DNS-over-HTTPS resolver connections
- trace `execve` and `execveat` activity so newly spawned programs are visible
- observe memfd creation, ptrace and cross-process memory access, kernel module and BPF program loads, io_uring setup, mounts, namespace changes, and privilege changes
- audit file access through open-style syscall tracepoints when enabled, and path-based unlink, rename, chmod, chown, and truncate requests
- monitor file integrity for policy-selected paths: SHA-256 and attribute baselines, change attribution to the acting process, and periodic rescans
- optionally block DNS lookups defined by local or remote YAML policy
- enforce exact and suffix DNS policies, with allow rules taking precedence
- enforce UID- and cgroup-aware outbound TCP/UDP CIDR and port policy
- deny selected executable paths and file opens through BPF LSM hooks
- mediate inet binds, AF_UNIX operations, and selected socket options
- observe TCP established, listen, retransmit, and close sockops signals
- load a strict YAML v1 policy from a local file, HTTPS endpoint, or both
- emit bounded alert-only detections over fully enriched events, with a default baseline and an opt-in runtime threat profile, mapped to MITRE ATT&CK
- expose health and Prometheus-style metrics over HTTP
- optionally archive JSON events locally and export them to an HTTPS collector
- support batched authenticated HTTPS export with durable retry spooling
- export structured events to remote syslog over UDP, TCP, or TLS
- support optional `Authorization` headers and mTLS for HTTPS event export
- optionally send HTTPS export and syslog records as OCSF 1.3.0 events
- optionally enrich pod-scoped events with Kubernetes namespace, pod, node, workload, service account, container, and image metadata
- run a built-in environment doctor check before deployment
- optionally pin eBPF maps, programs, and cgroup/tracepoint links across daemon restarts
- optionally export per-program eBPF runtime statistics
- count events lost to a full ring buffer per event kind and record each loss
- report the effective policy's SHA-256 and a periodic heartbeat with self-health for fleet drift and stuck-agent detection
- optionally require a detached Ed25519 signature on remote policy
- suppress named detections with scoped, expiring exceptions that record a reason
- replay detection rules over an archived event stream to measure noise before rollout

Remote YAML policy is cached for validated startup fallback and refreshed every
five minutes by default. After a remote policy has been activated, refresh
failures retain that in-memory policy instead of rolling back to an older cache.

## Design

TraceGuard uses a set of eBPF programs:

- `cgroup_skb/egress` parses outbound UDP and TCP DNS packets on port 53, emits DNS telemetry, and drops matching queries when blocking is enabled
- `cgroup/connect4` and `cgroup/connect6` observe resolver endpoint connections for DoT and configured DoH endpoints and block matching endpoints when blocking is enabled
- `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, and `cgroup/sendmsg6` enforce outbound TCP/UDP egress policy by UID, cgroup ID, destination CIDR, port, and protocol
- MAC LSM `bprm_check_security` and `file_open` programs enforce explicit executable and file-open path rules
- `cgroup/bind4` and `cgroup/bind6` enforce local TCP/UDP bind tuples
- AF_UNIX sock-addr programs enforce pathname or abstract connect/sendmsg rules and audit matching recvmsg addresses
- `cgroup/setsockopt` enforces selected level/name pairs without mutating option values
- an observe-only `sockops` program reports selected TCP lifecycle callbacks
- `tracepoint/syscalls/sys_enter_execve*` emits process execution events
- `tracepoint/syscalls/sys_enter_open*` and `sys_enter_creat` emit file access audit events when file auditing is enabled
- observe-only syscall-entry tracepoints for `memfd_create`, `ptrace`, `process_vm_readv`/`writev`, `init_module`/`finit_module`, `bpf`, `io_uring_setup`, `mount`, `setns`, `unshare`, the `set*id` family, and `capset` emit security events when enabled

The user-space service:

- normalizes DNS policy before loading it into BPF maps
- supports block and allow DNS entries in local and remote YAML policy
- supports exact and suffix domain rules in the policy engine
- strictly validates and overlays versioned local and remote YAML policy
- reconciles cgroup path selectors to kernel cgroup IDs as workloads change
- publishes every enforcement domain with immutable dual-slot settings and one RCU-replaced selector
- independently loads optional hooks so one unsupported verifier path does not suppress unrelated controls
- can adopt compatible bpffs pins and update persistent cgroup/tracepoint links without stacking attachments
- evaluates bounded match, exclusion, threshold, grouping, and cooldown detection rules
- caches remote YAML policy on disk with atomic file replacement
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

See [kernel support](docs/kernel-support.md) for what each feature needs from the kernel.

- Linux 6.12 or newer with cgroup v2 mounted at `/sys/fs/cgroup`
- eBPF support for cgroup egress and tracepoints
- privileges equivalent to `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_ADMIN` and `CAP_SYS_RESOURCE`
- tracepoint perf-event access for syscall probes, which may require lowering `kernel.perf_event_paranoid` when `CAP_PERFMON` is unavailable
- `CAP_SYS_PTRACE` is intentionally not granted by the packaged systemd unit; without it TraceGuard cannot read `/proc/<pid>/exe` for processes owned by other users, so the `current_exe` and `current_parent_exe` enrichment fields are empty for those processes. Operators who accept the additional privilege may add `CAP_SYS_PTRACE` to the unit's `AmbientCapabilities` and `CapabilityBoundingSet` to restore full executable-path enrichment
- Go 1.27.x
- `clang` for `go generate`

Notes:

- exec and file enforcement require BPF LSM enabled in the host LSM list; their MAC hooks are host-wide and require `TRACEGUARD_CGROUP_PATH=/sys/fs/cgroup`
- new optional enforcement hooks are checked with their real load and attach path; a policy requiring an unavailable hook is rejected while unrelated observation remains available
- exec and file defaults are always allow; only explicit block rules can deny them
- enforced path rules support exact paths and `/**` descendant prefixes, not general shell globs
- file enforcement covers the LSM file-open hook, not `O_PATH`, chmod, unlink, standalone truncate, or mmap-after-read-only-open
- AF_UNIX unnamed, relative, too-short, or unreadable addresses fail open; there is no Unix bind policy
- bind policy evaluates the requested local tuple and never rewrites it; sockopt policy never mutates option values

- DNS blocking supports exact and suffix matches on normalized QNAMEs for classic UDP/TCP DNS on port 53
- allow rules take precedence over block rules; plain domain allow rules are exact matches, while `*.example.com` and `suffix:example.com` allow suffix matches
- suffix rules match a domain and any subdomain, for example `*.example.com` or `suffix:example.com`
- `*` enables a deny-all policy for DNS names and identifiable resolver traffic, with explicit allow rules punching holes back in
- DNS QNAME matching is ASCII case-insensitive
- DoT support is endpoint-based: TraceGuard can detect outbound connections to port 853 and block configured DoT resolver endpoints
- DoH support is endpoint-based: TraceGuard can detect and block configured HTTPS resolver endpoints, but it cannot recover the encrypted inner DNS query name
- wildcard resolver mode does not treat every HTTPS connection as DoH; port 443 is only classified when it matches an explicit DoH endpoint rule or CIDR
- DoT and DoH endpoint rules may use hostnames in observe-only mode, but `-block` and `-dry-run` require literal IP or CIDR endpoints so unauthenticated DNS cannot redefine enforcement
- bare IP literals such as `1.1.1.1` or `[2606:4700:4700::1111]` are treated as resolver exceptions for both DoH on 443 and DoT on 853
- bare CIDR literals such as `1.1.1.0/24` or `2606:4700:4700::/48` are treated the same way for resolver ranges on DoH 443 and DoT 853
- logs are written to `/var/log/traceguard/traceguard.log` by default, rotate at 1 GiB, and retain the last 5 rotated files as gzip-compressed `.gz` archives
- structured text and JSON records include the startup hostname in a protected `hostname` field so aggregated logs retain their source host
- enforced blocked events are also written as JSON to `blocked.log` in the same log directory, with the same rotation policy
- first-seen DNS query domains are written once to `domains.log` in the same log directory as tab-separated timestamp, hostname, and domain lines, with the same rotation policy
- process metadata is cached from `/proc` with pidfd identity tracking and a bounded 4,096-entry LRU cache
- SELinux/AppArmor labels are read from `/proc/<pid>/attr/current` and `/proc/<pid>/attr/apparmor/current` when available
- file access auditing is enabled by default in packaged deployments; disable it with `TRACEGUARD_FILE_AUDIT=false` if open-style syscall volume is too high for the host
- Kubernetes enrichment is optional, API-driven, and keyed by the observed pod UID
- common IPv6 extension headers are parsed before DNS inspection
- in block mode, TCP DNS payloads that are not exactly one complete length-prefixed message, fragmented IPv6 DNS packets, IPv6 packets with more than six extension headers, and unparseable IPv4 or IPv6 UDP DNS payloads are denied instead of allowed
- kernel policy refreshes are published atomically from immutable per-slot settings, so every enforcement hook sees either the previous complete policy or the next complete policy
- failed scheduled or SIGHUP-triggered policy refreshes leave the last successfully committed policy active and are retried without stopping TraceGuard
- event timestamps represent kernel event occurrence time and are converted from `CLOCK_BOOTTIME` to UTC wall time in userspace
- `/health` returns HTTP 503 after a critical local event sink write failure and recovers after that sink writes successfully; enforcement continues while unhealthy
- exact and suffix domain block/allow policies are enforceable in kernel block mode
- in enforced block mode with `*`, exact domain rules, suffix allow domain rules, DoH/DoT endpoint rules, and resolver IP/CIDR rules are supported as exceptions
- enforced suffix matching checks every possible DNS label boundary and hashes at most 64 wire-format bytes per suffix candidate; configured block or allow suffixes over that limit are rejected in enforced block mode, and exact rules are unaffected
- event archive and export use the same structured event records as the logger
- event export can use custom trust roots, client certificates, and durable retry spooling
- on Linux 7.1 or newer, TraceGuard automatically tries an enhanced telemetry eBPF object that adds event source and kernel feature-set fields; if the kernel or verifier rejects that object, TraceGuard falls back to the standard object without user configuration
- outbound egress policy defaults to allow; explicit allow rules win over block rules, and DNS plus egress are independent enforcement gates
- cgroup selectors use cgroup v2 paths relative to the configured root; prefixes are matched against kernel cgroup ancestry through level 63, and block or dry-run mode reserves both exact and prefix selectors for fail-closed allow rules
- the detection engine is alert-only, caps state at 16,384 threshold groups and 65,536 retained timestamps, and enables three baseline rules by default
- bpffs pinning is disabled by default and requires real `bpf_link` attachments; unpinned startup rejects an existing TraceGuard pin root until `traceguard -unpin` removes it, and host-wide LSM links remain lifecycle-bound
- eBPF runtime statistics are disabled by default because kernel runtime accounting has a system-wide performance cost
- events that cannot be queued because the 16 MiB event ring buffer is full are counted in the kernel per event kind and exported as `traceguard_ringbuf_dropped_total{kind}`, with `traceguard_ringbuf_size_bytes` and `traceguard_ringbuf_unread_bytes` for occupancy; any new drops are also recorded as an `eBPF ring buffer full; events dropped` error event with `dropped_events` and `dropped_<kind>` counts, checked every five seconds. Enforcement decisions are unaffected by drops; only their telemetry is lost
- the ring buffer reader starts before the initial YAML policy is loaded, so a slow remote policy fetch at startup does not leave attached programs filling an unread buffer

## Build

```bash
go generate ./internal/ebpf
make fmt-check
make lint
go test ./...
make build
```

Common targets:

```bash
make generate
make fmt-check
make lint
make test
make build
make snapshot
```

`make build` produces a hardened Linux binary with PIE enabled and the C
toolchain configured for link-time optimization, stack protection on all C
functions, `_FORTIFY_SOURCE=2`, RELRO, BIND_NOW, and a non-executable stack.
`make fmt-check` and `make lint` use the repository's golangci-lint v2
configuration; CI pins golangci-lint 2.15.0, builds it with the Go 1.27 toolchain, and runs it as a separate gate.

## Usage

Observe only:

```bash
sudo ./traceguard
```

Enforce a local policy:

```bash
sudo ./traceguard -block \
  -policy-path /etc/traceguard/policy.yaml
```

Dry-run the policy without enforcing drops:

```bash
sudo ./traceguard -dry-run \
  -policy-path /etc/traceguard/policy.yaml
```

The strict YAML v1 policy is the single source for DNS, egress, exec, file,
bind, Unix, sockopt, and detection rules. Copy
[`examples/policy.yaml`](examples/policy.yaml) as a starting point, then see the
[policy guide](docs/policy.md) and [JSON Schema](docs/policy.schema.json).

Recover from a problematic deny policy while leaving monitoring active:

```bash
sudo ./traceguard -emergency-allow
```

For a pinned service, stop the running daemon first. Emergency mode removes
persistent policy state before opening listeners or remote sinks, then starts
the monitor with an empty policy. Host-wide LSM links are intentionally not
pinned and detach when the previous daemon exits.

Keep compatible eBPF state across daemon restarts:

```bash
sudo ./traceguard -block -pin-ebpf \
  -policy-path /etc/traceguard/policy.yaml
```

Stop the service and remove persistent pins before disabling pinning,
uninstalling, or starting without `-pin-ebpf`:

```bash
sudo systemctl stop traceguard
sudo traceguard -unpin
```

Enable per-program kernel runtime accounting temporarily:

```bash
sudo ./traceguard -ebpf-stats
```

Pinning and runtime statistics are disabled by default. See
[Operational controls](docs/policy.md#operational-controls) for lifecycle,
readiness, and performance details.

Manually reload the configured policy sources:

```bash
sudo kill -HUP $(pidof traceguard)
```

Use a remote base policy with a local overlay, private CA, and mTLS:

```bash
sudo ./traceguard -block \
  -policy-url https://policy.example/traceguard/v1 \
  -policy-path /etc/traceguard/policy.yaml \
  -policy-ca-path /etc/traceguard/policy-ca.crt \
  -policy-client-cert /etc/traceguard/policy-client.crt \
  -policy-client-key /etc/traceguard/policy-client.key
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
  -metrics-addr 127.0.0.1:9091
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

Production HTTPS batch export with auth and durable retry. Keep the
Authorization value in the root-only `/etc/traceguard/traceguard.env` rather
than on the command line, where local users can read it from process listings:

```bash
# /etc/traceguard/traceguard.env
TRACEGUARD_EVENT_EXPORT_URL=https://siem.example/api/traceguard
TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer secret-token
TRACEGUARD_EVENT_EXPORT_SPOOL=true
```

To keep the value out of the environment too, put it in a root-owned `0600` or
`0400` file and point `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE` (or
`-event-export-authorization-file`) at it instead. The file holds a single line
of at most 8 KiB, a trailing newline is removed, and symlinks are rejected. With
systemd `LoadCredential=`, TraceGuard expands a leading
`${CREDENTIALS_DIRECTORY}`, which systemd does not expand in the environment
file:

```ini
# /etc/systemd/system/traceguard.service.d/credentials.conf
[Service]
LoadCredential=event-export-authorization:/etc/traceguard/credentials/event-export-authorization
```

```bash
# /etc/traceguard/traceguard.env
TRACEGUARD_EVENT_EXPORT_URL=https://siem.example/api/traceguard
TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE=${CREDENTIALS_DIRECTORY}/event-export-authorization
```

`-policy-authorization-file` and `TRACEGUARD_POLICY_AUTHORIZATION_FILE` work
the same way for the remote policy source. Setting both a value and a file for
the same header is rejected.

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

Send HTTPS export and syslog records as [OCSF](https://schema.ocsf.io/) 1.3.0
events instead of the TraceGuard format:

```bash
sudo ./traceguard \
  -event-export-url https://siem.example/ingest \
  -event-schema ocsf
```

| TraceGuard events | OCSF class |
| --- | --- |
| `dns`, `blocked` | DNS Activity (4003) |
| `connection`, `resolver*`, `egress_*`, `bind_*`, `unix_*`, `sockopt_*`, `tcp_sockops` | Network Activity (4001) |
| `exec*`, `ptrace`, `process_vm`, `privilege_change`, `memfd_create`, `io_uring_setup`, `namespace_change` | Process Activity (1007) |
| `module_load`, `bpf_prog_load` | Kernel Extension Activity (1002) |
| `file_access`, `file_created`, `file_*block*`, `file_change`, `file_integrity`, `mount` | File System Activity (1001) |
| `detection_alert` | Detection Finding (2004), with ATT&CK techniques and tactics in `attacks` |
| Heartbeats and daemon status | Base Event (0) |

Fields that map to an OCSF attribute move there: the acting process's
event-time PID, program, and user to `actor` (from the socket cache's
`cached_*` identity when that attributed the event, and for `file_integrity`
the triggering `actor_*` process), endpoints to `src_endpoint` and
`dst_endpoint`, paths and digests to `file` (a deletion's previous ones), and
the alert's `alert_id` to `finding_info.uid`. `current_exe` is read from
`/proc` later and may name another binary, so it stays unmapped. A required
`actor` or `dst_endpoint` that the record cannot fill, such as a rescan's actor
or a socket option's peer, is present but empty. Events use the `security_control`
profile: `action_id` is `2` (Denied) for blocked events and `1` (Allowed)
otherwise, with `disposition_id` `2` (Blocked) or, for dry-run, `15`
(Detected). Activities without an OCSF name, such as `memfd_create`, carry the
TraceGuard operation or event name as `activity_name`. A pathless module load
and a BPF program load have a driver file named `unknown`. Every other field,
including the TraceGuard `event` name, is kept under `unmapped`, so nothing is
lost. An event over the 32 KiB record limit drops `unmapped`, then shortens
mapped strings and lists, and records `unmapped.telemetry_truncated=true`. The
local event archive and logs keep the TraceGuard format, which `-replay` reads.

Amazon Security Lake accepts OCSF 1.3 or earlier, but as Apache Parquet objects
per event class; send OCSF JSON through a collector that writes Parquet.

Environment variables can be used instead of flags:

- `TRACEGUARD_BLOCK`
- `TRACEGUARD_DRY_RUN`
- `TRACEGUARD_EMERGENCY_ALLOW`
- `TRACEGUARD_PIN_EBPF`
- `TRACEGUARD_EBPF_STATS`
- `TRACEGUARD_POLICY_PATH`
- `TRACEGUARD_POLICY_URL`
- `TRACEGUARD_POLICY_CACHE_PATH`
- `TRACEGUARD_POLICY_REFRESH_INTERVAL`
- `TRACEGUARD_POLICY_AUTHORIZATION`
- `TRACEGUARD_POLICY_AUTHORIZATION_FILE`
- `TRACEGUARD_POLICY_CA_PATH`
- `TRACEGUARD_POLICY_CLIENT_CERT`
- `TRACEGUARD_POLICY_CLIENT_KEY`
- `TRACEGUARD_CGROUP_PATH`
- `TRACEGUARD_LOG_PATH`
- `TRACEGUARD_LOG_FORMAT`
- `TRACEGUARD_METRICS_ADDR`
- `TRACEGUARD_EVENT_ARCHIVE_PATH`
- `TRACEGUARD_EVENT_EXPORT_URL`
- `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION`
- `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE`
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
- `TRACEGUARD_STRICT_HOOKS`
- `TRACEGUARD_HEARTBEAT_INTERVAL`
- `TRACEGUARD_POLICY_SIGNING_KEY`
- `TRACEGUARD_CONNECTION_DEDUPE_WINDOW`
- `TRACEGUARD_SECURITY_EVENTS`
- `TRACEGUARD_EVENT_SCHEMA`

By default, TraceGuard logs in JSON. Use `-log-format text` or `TRACEGUARD_LOG_FORMAT=text` to switch back to text output. Both formats include the OS hostname captured at startup. The same protected `hostname` field is retained in the local event archive, blocked-event log, HTTPS export records, and JSON syslog payloads; RFC5424 syslog headers use that value too.

Packaged defaults in `/etc/traceguard/traceguard.env`:

- observe-only mode: `TRACEGUARD_BLOCK=false` and `TRACEGUARD_DRY_RUN=false`
- emergency allow, bpffs pinning, and runtime statistics disabled: `TRACEGUARD_EMERGENCY_ALLOW=false`, `TRACEGUARD_PIN_EBPF=false`, and `TRACEGUARD_EBPF_STATS=false`
- YAML policy sources disabled unless `TRACEGUARD_POLICY_PATH` or `TRACEGUARD_POLICY_URL` is set
- YAML policy cache and refresh: `TRACEGUARD_POLICY_CACHE_PATH=/var/lib/traceguard/policy.yaml`, `TRACEGUARD_POLICY_REFRESH_INTERVAL=5m`
- cgroup path: `TRACEGUARD_CGROUP_PATH=/sys/fs/cgroup`
- log path and format: `TRACEGUARD_LOG_PATH=/var/log/traceguard/traceguard.log`, `TRACEGUARD_LOG_FORMAT=json`
- first-seen DNS query domains are also retained in `/var/log/traceguard/domains.log`; this is a hostname-attributed, deduplicated DNS-domain inventory, not full HTTP URL/path capture
- metrics enabled on loopback with `TRACEGUARD_METRICS_ADDR=127.0.0.1:9091`
- local event archive disabled unless `TRACEGUARD_EVENT_ARCHIVE_PATH` is set
- durable HTTPS batch export disabled unless `TRACEGUARD_EVENT_EXPORT_URL` is set
- HTTPS export sends batches of 50 events or every 5 seconds
- HTTPS export spooling enabled by default with `TRACEGUARD_EVENT_EXPORT_SPOOL=true`; failed batches are stored in `/var/lib/traceguard/export-spool` with a 1 MiB per-batch limit and 256 MiB total spool limit per event schema. Batches are stored as encoded, so each `-event-schema` has its own spool files and a batch is resent only while its schema is configured
- remote syslog export disabled unless `TRACEGUARD_EVENT_SYSLOG_URL` is set; defaults: `TRACEGUARD_EVENT_SYSLOG_FACILITY=local0`, `TRACEGUARD_EVENT_SYSLOG_TAG=traceguard`, `TRACEGUARD_EVENT_SYSLOG_TIMEOUT=5s`
- process cache TTL: `TRACEGUARD_PROCESS_CACHE_TTL=5m`
- file audit enabled: `TRACEGUARD_FILE_AUDIT=true`
- security events enabled: `TRACEGUARD_SECURITY_EVENTS=true`
- HTTPS export and syslog records in the TraceGuard format: `TRACEGUARD_EVENT_SCHEMA=traceguard`
- connection event deduplication: `TRACEGUARD_CONNECTION_DEDUPE_WINDOW=1m`
- strict hook mode disabled and heartbeats every five minutes: `TRACEGUARD_STRICT_HOOKS=false`, `TRACEGUARD_HEARTBEAT_INTERVAL=5m`
- remote policy signatures not required unless `TRACEGUARD_POLICY_SIGNING_KEY` is set
- Kubernetes enrichment disabled: `TRACEGUARD_KUBERNETES_ENRICH=false`; when enabled without an explicit API URL, TraceGuard auto-detects the in-cluster API endpoint

Example output:

```text
2026/03/16 08:17:20 dns level="info" hostname="worker-1" cgroup_id=7451 current_cmdline=["/usr/bin/dig","example.com"] current_exe="/usr/bin/dig" current_k8s_namespace="default" current_k8s_pod="dns-client" domain="example.com" event="dns" pid=31742 process_start_ticks=819400 program="dig" transport="udp" uid=1000
2026/03/16 08:17:21 blocked-doh level="info" hostname="worker-1" address="8.8.8.8" current_exe="/usr/bin/curl" endpoint="8.8.8.8" event="resolver_blocked" pid=31811 policy="block" port=443 program="curl" transport="doh" uid=1000
2026/03/16 08:17:23 file_access level="info" hostname="worker-1" current_apparmor_profile="traceguard-default" current_exe="/usr/bin/cat" event="file_access" file_access="read" file_flags=0 file_mode=0 path_source="syscall-requested" pid=31900 program="cat" requested_path="/etc/passwd" uid=1000
```

Example JSON output:

```json
{"timestamp":"2026-03-16T08:17:20.123456Z","level":"info","message":"dns","hostname":"worker-1","event":"dns","program":"dig","pid":31742,"process_start_ticks":819400,"uid":1000,"cgroup_id":7451,"current_exe":"/usr/bin/dig","current_cmdline":["/usr/bin/dig","example.com"],"domain":"example.com","transport":"udp"}
{"timestamp":"2026-03-16T08:17:23.123456Z","level":"info","message":"file_access","hostname":"worker-1","event":"file_access","program":"cat","pid":31900,"uid":1000,"current_exe":"/usr/bin/cat","requested_path":"/etc/passwd","path_source":"syscall-requested","file_flags":0,"file_mode":0,"file_access":"read"}
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
- `/usr/share/doc/traceguard/policy.example.yaml` and `policy.schema.json`
- `/var/log/traceguard/traceguard.log` at runtime via the packaged service defaults
- a systemd unit at the distro-appropriate system path
- an optional systemd sandbox allowance for bpffs; TraceGuard creates `/sys/fs/bpf/traceguard` with mode `0700` only when pinning is enabled
- metrics on the configured listen address, `127.0.0.1:9091` by default in the packaged env file

## Secure Development Notes

- Dependencies are managed through Go modules and suitable for GoReleaser verifiable builds.
- CI runs the extended golangci-lint v2 policy, eBPF C checks, generated bindings, unit/race tests, kernel integration tests, and a Go build.
- Remote YAML policy fetches use HTTPS only, bounded response sizes, same-origin redirects, and network timeouts.
- Log file creation rejects symlink targets and non-regular files to reduce log-path attacks.
- Policy cache reads reject symlinks and cache writes are atomic with restricted permissions.
- The BPF parser uses explicit bounds checks and fixed maximum sizes to satisfy the verifier and reduce parser risk.
- Block-mode kernel decisions do not depend on blocked-event ring-buffer availability; DNS parsing and true LSM `ENAMETOOLONG` failures follow their documented fail-closed paths.
- Optional eBPF programs load and attach independently, while policy application fails when a requested enforcement hook is unavailable or incorrectly scoped.
- Pinned cgroup/tracepoint link adoption uses `link.Update` to avoid stacking duplicate TraceGuard attachments, and incompatible ABI metadata is discarded before a fresh load. Unpinned startup refuses an existing TraceGuard pin root instead of attaching a second policy collection. Host-wide LSM links are lifecycle-bound to keep recovery startup reachable.
- Current-task event identity comes from one kernel snapshot (`program`, UID, cgroup ID, and process start ticks). Potentially stale DNS/listener socket identity is labeled `socket-cache`, exposed only as `cached_*` telemetry, and excluded from detection matching and grouping. `/proc` enrichment is labeled with `current_*` fields.
- Detection matching and grouping never use `current_*` enrichment or syscall-requested path aliases; canonical path events report truncation explicitly and accept only bounded exact or `/**` detection patterns.
- Process enrichment also extracts cgroup path, likely service unit, and container ID heuristics from `/proc/<pid>/cgroup`.
- Process enrichment includes SELinux contexts and AppArmor profile/mode where the host exposes those labels through `/proc`.
- File access auditing records open-style syscall path, flags, mode, read/write intent, and, for `openat` and `openat2` relative to a directory descriptor, `requested_dirfd`. Opens with create intent are emitted as `file_created`; other opens are emitted as `file_access`. It is enabled by the packaged env file with `TRACEGUARD_FILE_AUDIT=true`; disable it when retained path data or event volume is not acceptable.
- Repeated file access audit records are deduplicated for 5 minutes using stable file, process, container/pod, and SELinux/AppArmor label fields so short-lived PID churn does not spam logs with unchanged LSM-attributed entries.
- Process enrichment now also extracts pod UID and runtime hints from common Kubernetes/container cgroup layouts when present.
- Optional Kubernetes API enrichment can add namespace, pod name, pod IP, node name, service account, controller workload, app label, container names, and image names keyed by the observed pod UID.
- `dry-run` uses the same policy engine as enforcement mode but logs `would-block` decisions instead of enabling kernel drops.
- `SIGHUP` triggers an immediate policy reload from local and remote sources.
- Metrics and health endpoints are served when `-metrics-addr` is set. The packaged env file enables them on loopback at `127.0.0.1:9091`; non-loopback listeners are unauthenticated and should be restricted to a trusted management network.
- Metrics include event volume, per-domain enforcement decisions, hook readiness, YAML policy source health, rule counts, detection alerts and state, eBPF attachment/read health, optional program statistics, export backlog, process attribution quality, and enrichment hit/miss counts.
- HTTPS batch export requires an HTTPS endpoint and uses bounded in-memory queuing to avoid blocking the main event loop.
- HTTPS batch export sends records as JSON arrays, supports an optional `Authorization` header, optional mTLS, and can spool failed batches to disk for replay.
- Telemetry messages, strings, field counts, serialized records, export batches, and UDP syslog datagrams are bounded. Truncated records carry `telemetry_truncated=true` instead of silently growing queues or datagrams.
- Remote syslog export sends RFC5424-style structured events over UDP, TCP, or TLS without durable spooling.
- Kubernetes enrichment uses HTTPS, a bearer token, bounded response sizes, and a periodic cache refresh instead of live per-event API calls.
- Encrypted DoH and DoT traffic is handled at the resolver-endpoint level; the implementation does not attempt TLS interception or decryption.
