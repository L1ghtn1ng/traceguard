# Changelog

All notable changes to TraceGuard are documented in this file.

## [1.3.0] - 2026-06-07

### Added

- Added SELinux and AppArmor process-label enrichment to structured events when labels are exposed under `/proc`.
- Added file access auditing through open-style syscall tracepoints, with packaged deployments enabling file audit by default.
- Added remote syslog export over UDP, TCP, and TLS for simpler collector forwarding.
- Added Kubernetes enrichment setup improvements, including in-cluster API defaulting and clearer doctor checks.
- Added operational metrics for policy decisions, blocklist refresh/load status, policy size and mode, eBPF health, export queue and spool backlog, process attribution quality, Kubernetes refreshes, and enrichment hit/miss counts.
- Added HTTPS export mTLS and durable retry spooling documentation and packaged configuration examples.

### Changed

- Simplified HTTPS batch export configuration to URL, `Authorization`, spool enablement, and TLS settings.
- Fixed HTTPS export batching at 50 events or 5 seconds and fixed the durable spool path at `/var/lib/traceguard/export-spool`.
- Updated packaged environment defaults and README guidance to make local archive, HTTPS batch export, remote syslog, and Kubernetes enrichment setup easier to understand.
- Enabled stronger release build hardening and optimization through LTO-related build flags.
- Reduced repeated process metadata reads and hot-path allocation overhead in process attribution, metric rendering, cgroup parsing, and info-event deduplication.

### Fixed

- Failed closed on unparseable IPv4 UDP DNS payloads in enforced block mode, preventing fragmented UDP DNS bypasses.
- Pruned expired process metadata cache entries under PID churn to avoid unbounded stale metadata growth.
- Capped HTTPS export spool writes at 1 MiB per batch and 256 MiB total spool usage to reduce disk exhaustion risk.
- Counted failed periodic blocklist refreshes in blocklist load-status metrics.
- Ensured Kubernetes auto-detected defaults are applied consistently in doctor mode.
- Regenerated eBPF objects for the updated DNS enforcement behavior.
