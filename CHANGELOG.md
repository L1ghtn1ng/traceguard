# Changelog

All notable changes to TraceGuard are documented in this file.

## [1.4.0] - 2026-07-10

### Added

- Added transparent Linux 7.1 eBPF object probing with DNS and `recvmsg` compatibility variants, automatic legacy fallback, and startup, metrics, and doctor diagnostics for the selected object and enhanced-load failures.
- Added a Linux 6.12 minimum-kernel check at startup and in doctor output.
- Added event-sink health gauges and `/health` degradation when a critical local audit sink cannot be written, while keeping eBPF enforcement active.

### Fixed

- Made policy reloads atomic for kernel readers by preparing a complete inactive rule slot and publishing all domain, resolver, CIDR, and mode changes with one settings-map update.
- Failed closed on malformed or unparseable IPv6 UDP DNS traffic in enforced block mode, matching the IPv4 path.
- Enforced IPv4 endpoint and CIDR policy for IPv4-mapped IPv6 connections in both userspace decisions and the `connect6` eBPF hook.
- Converted boot-clock eBPF timestamps to wall-clock event occurrence times instead of interpreting monotonic nanoseconds as Unix epoch values.
- Hardened blocklist cache and export-spool access with bounded reads and `openat2` no-symlink resolution, and kept freshly fetched rules active when cache persistence fails.
- Added pidfd-backed process identity tracking, per-read start-time validation, and a 4,096-entry LRU cap to prevent PID-reuse misattribution and descriptor growth.
- Serialized recorder shutdown against in-flight writes, prevented rotating files from reopening after close, drained queued syslog records during bounded shutdown, and restored default signal handling so a second termination signal can force exit.
- Reported unexpected optional tracepoint attach failures, protected reserved structured-log fields, propagated doctor writer errors, validated cache paths and Kubernetes poll intervals, and bounded worker error reporting during shutdown.
- Bounded file-audit and error deduplication state with TTL-based pruning and hard entry limits, preventing event cardinality from causing unbounded memory growth.
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
