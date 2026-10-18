# Changelog

All notable changes to TraceGuard are documented in this file.

## [Unreleased]

### Added

- Added `-policy-authorization-file` / `TRACEGUARD_POLICY_AUTHORIZATION_FILE` and `-event-export-authorization-file` / `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE`, which read the `Authorization` header value from a root-only file so it stays out of the daemon's command line and environment. A leading `${CREDENTIALS_DIRECTORY}` is expanded for systemd `LoadCredential=`; group- or world-accessible files, symlinks, and setting both a value and a file are rejected.
- Added the `local_ports` detection selector for the local port of connection, egress, bind, and sockops events, so rules can match connections to a listening port and bind decisions by port.
- Added the `unix_path_globs` detection selector for `unix_blocked` and `unix_would_block` socket paths, including `@` abstract names.
- Added the `peer` threshold group field as a clearer name for the peer address of inbound connections.
- Added the `baseline.inbound-ssh-bruteforce` detection: 20 inbound TCP connection attempts to port 22 from one address within a minute.
- Added per-kind kernel counters for events lost because the event ring buffer was full, exported as `traceguard_ringbuf_dropped_total{kind}`, plus `traceguard_ringbuf_size_bytes` and `traceguard_ringbuf_unread_bytes` occupancy gauges. New drops are also recorded as an `eBPF ring buffer full; events dropped` error event. Previously a full ring buffer discarded events without any signal.
- Added a SHA-256 digest of the effective merged policy, exported as `traceguard_policy_info{sha256}` and included in the `policy loaded` record, so hosts running different policy are easy to find.
- Added a `heartbeat` event, recorded at startup and every `-heartbeat-interval` / `TRACEGUARD_HEARTBEAT_INTERVAL` (default `5m`, `0` disables), carrying the policy digest and mode, health, unavailable hooks, ring buffer loss, and detection and exception counts.
- Added `-strict-hooks` / `TRACEGUARD_STRICT_HOOKS`, which refuses to start when any optional eBPF hook cannot be loaded or attached.
- Added `detection_exceptions`: scoped suppressions for named detection rules with a required `reason` and an optional RFC 3339 `expires`. Suppressed events do not count toward thresholds. They are reported through `traceguard_detection_suppressed_total{exception}`, `traceguard_detection_exceptions{state}`, a one-time `detection exception expired` record, and the heartbeat.
- Added `-replay`, which evaluates detection rules and exceptions from `-policy-path` over a JSONL or gzip event archive offline, writes alerts as JSON lines, and summarizes alert counts per rule, noisiest first.
- Added `-connection-dedupe-window` / `TRACEGUARD_CONNECTION_DEDUPE_WINDOW` (default `1m`, at most `1h`, `0` disables) for the previously fixed 60-second suppression of repeated connection and TCP retransmit events.
- Added observe-only security events from syscall-entry tracepoints, enabled by `-security-events` / `TRACEGUARD_SECURITY_EVENTS` (default `true`): `memfd_create`, `ptrace` (attach, seize, traceme, and poke requests), `process_vm` reads and writes, `module_load`, `bpf_prog_load`, `io_uring_setup`, `mount`, `namespace_change`, and `privilege_change`. They are detection events with event-time kernel identity, and the new `operations` selector matches their operation.
- Added kernel-captured exec command lines: `exec` events now carry `exec_syscall`, a redacted `command_line` of up to 32 arguments and 255 bytes read at syscall entry, `command_line_truncated`, and `exec_source` (`path`, or `fd` with `exec_fd` for `execveat(AT_EMPTY_PATH)` and `/proc/<pid>/fd` or `/dev/fd` paths). The `command_globs` detection selector is accepted again for `exec` events and matches this command line, and the new `exec_sources` selector matches the source.
- Added `mitre` (`tactics`, `techniques`) and `compliance` fields to detection rules, carried on alerts as `mitre_tactics`, `mitre_techniques`, and `compliance`. Baseline rules now carry ATT&CK mappings.
- Added the opt-in `runtime` detection profile, enabled with `builtin_profiles: [runtime]`, with eight rules over security and exec events: kernel module load, BPF program load, ptrace attach or write, process memory write, fileless exec, namespace join, sensitive filesystem mount, and sensitive capability request. It is off by default so upgrades do not change existing alerting.
- Added the `mount_fstypes` and `capabilities` detection selectors for `mount` and `privilege_change` events.
- Added file integrity monitoring configured by a `file_integrity` policy section: watched paths and exclusions, SHA-256 hashing of regular files up to `max_hash_bytes` (default 16 MiB), and a periodic `rescan_interval` (default `1h`). Changes are reported as `file_integrity` events with the previous and current state and, when a kernel event triggered the check, the acting process as `actor_*` fields, with `actor_ambiguous` when another process also touched the path before the check. Writes by processes in another mount namespace, such as a container, wait for the rescan, and an error is recorded when file auditing is off, because writes are then found only by rescan. The runtime profile adds `runtime.persistence-file-change` for watched cron, systemd, sudoers, PAM, account, and SSH files, and the `changes` selector matches the change kind.
- Added `file_change` events for path-based unlink, rmdir, rename, chmod, chown, and truncate requests, recorded with file auditing. The hooks attach regardless, so file integrity monitoring sees these requests with file auditing off.
- Added `-event-schema` / `TRACEGUARD_EVENT_SCHEMA`. With `ocsf`, HTTPS export and syslog send OCSF 1.3.0 events: DNS, Network, Process, Kernel Extension, and File System Activity, Detection Finding with ATT&CK attacks, and Base Event, with unmapped fields kept under `unmapped`. Events carry the `security_control` profile's `action_id`, an `activity_name`, and their class's required objects; an oversized event is shortened rather than dropped, and a UDP syslog datagram cut to its minimum keeps its class. The local archive and logs keep the TraceGuard format.
- Added advisory host posture lines to `-doctor`: BPF LSM with LSM program and task storage support, `kernel.unprivileged_bpf_disabled`, kernel lockdown, module signature enforcement (including lockdown's rejection of unsigned modules), and Yama `ptrace_scope`. They are `INFO` or `WARN` and never fail the doctor.
- Added `alert_id`, a random identifier unique to each detection alert, which OCSF findings use as `finding_info.uid`.
- Added `docs/kernel-support.md`, which explains the Linux 6.12 minimum and what each feature needs from the kernel.

### Changed

- Clarified that the `ports` and `destination_cidrs` detection selectors match the peer, which is the remote source on inbound connections.
- File audit no longer reports TraceGuard's own file opens, which file integrity hashing would otherwise flood it with.
- `file_access` and `file_created` records carry `requested_dirfd` when `openat` or `openat2` names a path relative to a directory descriptor.
- The ring buffer reader now starts before the initial YAML policy is loaded and applied, so events from the already-attached programs are consumed while a remote policy fetch is in progress instead of accumulating until the buffer fills. Detection holds up to 8,192 of those events until the policy is installed and then evaluates them in order, so they are judged by the configured rules.
- Bumped the eBPF pin layout to version 6 for the new drop-counter map. With `-pin-ebpf`, the first start after upgrading discards the previous pins and attaches fresh programs.
- Updated `docs/policy.md` to document pin layout version 6.
- Bumped the eBPF pin layout to version 7, because the drop-counter map grew with the new event kinds.

### Security

- Added `-policy-signing-key` / `TRACEGUARD_POLICY_SIGNING_KEY`. With a PEM Ed25519 public key configured, a remote policy is accepted only with a valid detached base64 signature at `<policy-url>.sig`, and a stale cache only if its cached signature still verifies, so a compromised policy server cannot push unsigned policy.
- Installed the packaged `/etc/traceguard/traceguard.env` as `0600 root:root`, and tightened an existing file to that mode on package install and upgrade, so authorization values stored there are not readable by other local users.
- Closed a DNS policy bypass through IPv6 extension-header chains: a packet with six extension headers now reaches DNS policy, and in block mode a packet whose chain is too long to parse is dropped because it could hide DNS.
- Broadened `current_cmdline` redaction of monitored processes to password-, token-, and key-style flags, `NAME=value` and `Header: value` arguments, query parameters, URL credentials, and the same forms inside `sh -c` strings, including quoted values and space-separated flags. Redaction is best effort, and `current_cmdline` should still be treated as sensitive.
- Documented the environment file and the new authorization file inputs instead of command-line flags for `Authorization` values, which are visible in process listings.
- Pinned GoReleaser in the release workflow to v2.18.3 instead of `latest`.

## [1.7.0] - 2026-10-17

### Upgrade notes

- Process enrichment fields read from `/proc` or Kubernetes are now prefixed with `current_` (`current_cgroup`, `current_service`, `current_container_id`, `current_pod_uid`, `current_runtime`, `current_lsm_*`, `current_selinux_context`, `current_apparmor_*`, `current_cmdline`, `current_exe`), and `filename` is now `requested_path`. `exe` is only set on exec decision events, where it is the target executable. Update SIEM queries and dashboards that use the old names.
- `domains.log` lines now contain `timestamp<TAB>hostname<TAB>domain`. TraceGuard still reads older two-column backups, but external parsers that take the second column must move to the third.
- Detection rules can no longer match on mutable enrichment (`command_globs`, `services`, `cgroup_prefixes`, `container_ids`, `pod_uids`, `k8s_*`, `lsm_*`), and executable or file-path globs are limited to LSM events. Policies that use these keys fail validation and must be updated before upgrading.
- Egress and bind rules reject an explicit `ports: [0]`, which matched every port. Omit `ports` to match any port, including ephemeral binds.
- Stop the service and run `traceguard -unpin` before downgrading from a release that used `-pin-ebpf`.

### Added

- Added atomic exec, file-open, inet bind, AF_UNIX, and socket-option enforcement with allow-first policy semantics, dry-run decisions, hook readiness, rule attribution, schema coverage, and detection events.
- Added observe-only TCP sockops lifecycle telemetry and opt-in eBPF runtime statistics.
- Added optional bpffs persistence for maps, programs, and cgroup/tracepoint `bpf_link` objects, explicit unpinning, and an emergency-allow recovery mode; host-wide LSM links remain lifecycle-bound.
- Added an extended golangci-lint v2 configuration with local Make targets and a dedicated pinned CI gate.
- Added a protected startup hostname to text and JSON logs, event archives, blocked-event and domain logs, HTTPS exports, and syslog output.
- Extended the cloud-metadata baseline to AWS IPv6 IMDS, ECS and EKS credential endpoints, and Alibaba Cloud, with per-cgroup/executable grouping and a one-hour cooldown so guest-agent polling cannot hide other processes.
- Made `traceguard -doctor` evaluate the cached remote policy merged with the local overlay for exec/file readiness checks, and warn when no cache is available.
- Added audit-only AF_UNIX `recvmsg` decisions; the kernel does not allow `cgroup/recvmsg_unix` to deny, so matching rules emit `unix_would_block` events and the receive proceeds.

### Changed

- Expanded the YAML v1 merge, cgroup reconciliation, doctor, metrics, example, and policy documentation for the new enforcement sections.
- Split settings into two immutable 32-byte slots, an RCU-replaced selector, and a separate exact daemon identity; advanced the pin layout to version 5 while preserving the 632-byte event ABI.

### Security

- Made policy-slot reuse wait for in-kernel readers, bound telemetry and detection state, rejected enforcement-time resolver hostnames and stale-cache rollback, and tied daemon exemptions and `/proc` enrichment to process generations.
- Matched bounded cgroup prefixes against kernel ancestry, rejected exact-cgroup deny rules and unsupported deep prefix roots, canonicalized IPv4-mapped resolver, enforcement, and detection prefixes before masking, rejected batched or multi-question DNS requests in block mode, and preserved DNS decisions at event time.
- Bound daemon identity to the thread-group leader generation and made bpffs directory creation conditional on pinning so default systemd startup does not require writable bpffs.
- Reject cgroup-scoped block rules in block and dry-run modes so cgroup deletion and recreation cannot create a fail-open policy window; cgroup-scoped allow exceptions remain fail-closed.
- Restricted detection matching and grouping to event-time kernel identity and canonical LSM paths; mutable `/proc`/Kubernetes enrichment and syscall-requested path aliases remain telemetry-only.
- Separated staleable DNS/listener socket-cache attribution from contemporaneous process identity, rejected incompatible UID and process-grouping detection scopes, and excluded plaintext DNS packet decisions from the identity-grouped denial baseline.
- Replaced requested-path-dependent built-in detections with default-active cloud-metadata and direct-email egress baselines that use event-time socket data.
- Embedded stable rule names in kernel enforcement events, made emergency mode clear persistent policy before startup sinks, and kept LSM links unpinned so delayed events and recovery restarts cannot inherit unsafe state.
- Refused unpinned startup and readiness while a TraceGuard pin root exists, preventing persistent policies from remaining active beside a second unpinned collection and providing explicit `-unpin` recovery guidance.
- Matched each socket-option name only at its own level instead of crossing every listed level with every listed name, which also matched unrelated options with the same number (for example `SOL_IP` option 36, `IP_DROP_MEMBERSHIP`). Rules must now list each name's level and may not list unused levels; the `tcp` level is no longer accepted because no supported option uses it.
- Evaluated `O_RDWR` file opens against both read and write rules, so a `read` block rule can no longer be bypassed by opening the file read-write.
- Required the bind6 hook for IPv4 bind rules and evaluated wildcard `::` binds against IPv4 wildcard policy, closing IPv4-mapped and dual-stack bypasses of IPv4-only bind rules.
- Refused exec and file enforcement when the daemon runs outside the host PID or time namespace, where its LSM self-exemption cannot identify it.
- Removed a newly created pin set when startup fails, including failures after the monitor starts such as an invalid policy, so pinned links cannot keep policy attached without a daemon or block later unpinned starts.
- Committed fetched remote policy to the cache and conditional-request state only after the full effective policy validates, and kept the last accepted remote base during refresh outages so local overlay changes still apply on `SIGHUP`.
- Compiled detection rules before the kernel policy commit and reported hook health only after the commit succeeds.
- Sent syslog UDP records unshortened when they fit in one datagram, and marked shortened messages as truncated.
- Validated syslog APP-NAME and HOSTNAME as RFC 5424 printable US-ASCII with length limits, and stopped event export URL parse errors from echoing secrets in the URL.
- Joined policy refresh, reload, cgroup reconciliation, and statistics workers before closing eBPF objects at shutdown, so a late reload cannot write to closed or reused map descriptors.
- Grouped exec denials by the calling program instead of the denied target, so the denial-burst baseline fires for one process trying several blocked binaries.
- Preserved other sockops programs' callback flags when enabling TraceGuard's retransmit and state callbacks.
- Bounded telemetry by admitting the smallest fields first and shortening oversized strings, so process-controlled command lines and paths cannot evict identity fields from logs and exports.
- Added aggregate policy limits, escaped DNS labels in telemetry, redacted credentials and URL secrets from diagnostics, and changed the packaged metrics listener to loopback.

## [1.6.0] - 2026-07-31

### Added

- Added strict YAML v1 policy from local and HTTPS sources, with remote-base/local-overlay semantics, ETag and Last-Modified refreshes, authenticated TLS/mTLS transport, atomic restricted cache writes, and validated stale-cache fallback.
- Added atomic UID- and cgroup-aware outbound TCP/UDP egress enforcement for IPv4 and IPv6 CIDRs and ports, including default allow/block posture, explicit allow precedence, dry-run events, rule attribution, and cgroup reconciliation.
- Added kernel-enforced DNS suffix blocks while preserving exact, suffix-allow, resolver endpoint, and deny-all behavior.
- Added a bounded alert-only detection engine with match/exclude filters, thresholds, grouping, cooldowns, Kubernetes and LSM enrichment fields, three enabled baseline rules, metrics, schema, example policy, and operational documentation.

### Removed

- Removed the superseded newline blocklist, manual domain flags and environment variables, and their separate cache, refresh, reload, doctor, and telemetry paths. Strict YAML v1 policy is now the single source for DNS, egress, and detection policy.

## [1.5.2] - 2026-07-16

### Changed

- Automatically gzip-compress rotated local log files while retaining the five-backup rotation policy, and preserve domain inventory deduplication across compressed and legacy uncompressed backups.

## [1.5.1] - 2026-07-13

### Fixed

- Restored block and allow domain-file loading on systems where `openat2` is unavailable by falling back to descriptor-relative `openat` path traversal while continuing to reject symlinked path components.

## [1.5.0] - 2026-07-13

### Fixed

- Restored logging when `/var/log/traceguard` is a symlink by allowing only that directory's final path component to be followed, while continuing to reject symlinked parent directories, custom log directories, and log files.
- Removed the rotating logger's dependency on `openat2` for descriptor-relative log-file creation, preventing startup failures on systems where the syscall is unavailable while retaining `O_NOFOLLOW` protection.
- Big refactor

## [1.4.0] - 2026-07-10

### Added

- Added transparent Linux 7.1 eBPF object probing with DNS and `recvmsg` compatibility variants, automatic legacy fallback, and startup, metrics, and doctor diagnostics for the selected object and enhanced-load failures.
- Added a Linux 6.12 minimum-kernel check at startup and in doctor output, while reporting kernel-release detection failures separately from unsupported versions.
- Added event-sink health gauges and `/health` degradation when a critical local audit sink cannot be written, while keeping eBPF enforcement active.

### Fixed

- Made policy reloads atomic for kernel readers by preparing a complete inactive rule slot and publishing all domain, resolver, CIDR, and mode changes with one settings-map update, while skipping map writes that would not change existing slot state.
- Raised userspace domain, suffix, resolver endpoint, and CIDR policy limits from 8,192 to 16,384 entries to match the kernel map capacities.
- Failed closed on malformed or unparseable IPv6 UDP DNS traffic in enforced block mode, matching the IPv4 path.
- Enforced IPv4 endpoint and CIDR policy for IPv4-mapped IPv6 connections in both userspace decisions and the `connect6` eBPF hook.
- Converted boot-clock eBPF timestamps to wall-clock event occurrence times instead of interpreting monotonic nanoseconds as Unix epoch values, with a cached clock offset to avoid per-event syscalls.
- Hardened blocklist cache and export-spool access with bounded reads and `openat2` no-symlink resolution, and kept freshly fetched rules active when cache persistence fails.
- Added pidfd-backed process identity tracking, per-read start-time validation, concurrent replacement cleanup, and a 4,096-entry LRU cap to prevent PID-reuse misattribution and descriptor growth.
- Serialized recorder shutdown against in-flight writes, prevented rotating files from reopening after close, drained queued syslog records during bounded shutdown, and restored default signal handling so a second termination signal can force exit.
- Reported unexpected optional tracepoint attach failures, protected reserved structured-log fields, propagated doctor writer errors, validated cache paths and Kubernetes poll intervals, and bounded worker error reporting during shutdown.
- Bounded file-audit and error deduplication state with TTL-based pruning and hard entry limits, and capped change-detection state to prevent event cardinality from causing unbounded memory growth.
- Bounded the in-memory DNS domain inventory deduplication set so unique-domain traffic cannot grow daemon memory indefinitely.
- Restricted HTTPS export and Kubernetes API redirects to the original HTTPS origin, preventing credentials and client certificates from being forwarded across origins.
- Ensured deferred recorder and log cleanup runs before nonzero process exit so queued export events can be flushed or spooled.

## [1.3.0] - 2026-06-17

### Added

- Added SELinux and AppArmor process-label enrichment to structured events when labels are exposed under `/proc`.
- Added file access auditing through open-style syscall tracepoints, with packaged deployments enabling file audit by default.
- Added remote syslog export over UDP, TCP, and TLS for simpler collector forwarding.
- Added Kubernetes enrichment setup improvements, including in-cluster API defaulting and clearer doctor checks.
- Added operational metrics for policy decisions, blocklist refresh/load status, policy size and mode, eBPF health, export queue and spool backlog, process attribution quality, Kubernetes refreshes, and enrichment hit/miss counts.
- Added HTTPS export mTLS and durable retry spooling documentation and packaged configuration examples.
- Added a deduplicated `domains.log` inventory in the TraceGuard log directory for first-seen DNS query domains.

### Changed

- Simplified HTTPS batch export configuration to URL, `Authorization`, spool enablement, and TLS settings.
- Fixed HTTPS export batching at 50 events or 5 seconds and fixed the durable spool path at `/var/lib/traceguard/export-spool`.
- Updated packaged environment defaults and README guidance to make local archive, HTTPS batch export, remote syslog, and Kubernetes enrichment setup easier to understand.
- Increased the packaged and built-in process metadata cache TTL to 5 minutes.
- Enabled stronger release build hardening and optimization through LTO-related build flags.
- Reduced repeated process metadata reads and hot-path allocation overhead in process attribution, metric rendering, cgroup parsing, and info-event deduplication.

### Fixed

- Failed closed on unparseable IPv4 UDP DNS payloads in enforced block mode, preventing fragmented UDP DNS bypasses.
- Pruned expired process metadata cache entries under PID churn to avoid unbounded stale metadata growth.
- Capped HTTPS export spool writes at 1 MiB per batch and 256 MiB total spool usage to reduce disk exhaustion risk.
- Improved file audit deduplication so AppArmor/LSM-attributed events suppress PID churn without merging different command lines or fallback process metadata records.
- Rejected malformed domain names from the domain inventory log to prevent line-oriented log forging from crafted DNS queries.
- Counted failed periodic blocklist refreshes in blocklist load-status metrics.
- Ensured Kubernetes auto-detected defaults are applied consistently in doctor mode.
- Regenerated eBPF objects for the updated DNS enforcement behavior.
