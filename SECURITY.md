# Security Policy

TraceGuard is a privileged Linux security utility that attaches eBPF programs to cgroup and tracepoint hooks, reads process metadata from `/proc`, and can export telemetry to remote HTTPS endpoints. Security reports should focus on issues that materially affect privilege boundaries, policy enforcement, confidentiality, integrity, or availability.

## Supported Versions

Security fixes are applied to the latest patch release in the current stable series.

| Version | Supported |
| --- | --- |
| `1.0.x` | Yes |
| `< 1.0.0` | No |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately.

- Prefer GitHub private vulnerability reporting for this repository: <https://github.com/L1ghtn1ng/traceguard/security/advisories/new>
- Do not open a public GitHub issue for an unpatched security issue.
- If GitHub private reporting is unavailable in your environment, contact the repository maintainer privately before disclosing details publicly.

Include as much of the following as you can:

- TraceGuard version and commit, if known
- Linux distribution, kernel version, and whether cgroup v2 is mounted
- Whether the issue occurs in observe, dry-run, or enforced block mode
- Relevant configuration, with secrets and tokens redacted
- Reproduction steps, proof of impact, and any suggested mitigation
- Whether Kubernetes enrichment, remote blocklists, metrics, or event export are enabled

## Response Process

- Initial acknowledgement target: within 5 business days
- Status updates: provided when triage, fix planning, or release timing materially changes
- Coordinated disclosure: preferred after a fix or effective mitigation is available

## In Scope

The following are generally considered security issues:

- Privilege escalation or unintended code execution
- Bypass of enforced DNS or resolver endpoint blocking
- Exposure of sensitive telemetry, credentials, or local files
- TLS verification flaws in remote blocklist fetch or HTTPS event export
- Unauthorized access introduced by metrics, logging, cache, or spool handling
- Denial of service caused by untrusted network input or malformed policy input in privileged paths
- Kubernetes enrichment behavior that exposes data beyond the configured node or cluster permissions

## Out of Scope

The following are usually not treated as security vulnerabilities by themselves:

- Detection gaps that are already documented in `README.md`, including the inability to recover encrypted DoH query names
- Availability issues on unsupported kernels, unsupported privilege models, or non-Linux platforms
- False positives, false negatives, or bad entries in third-party blocklists without an underlying TraceGuard defect
- Feature requests for new protocols, broader inspection coverage, or alternative deployment models
- Publicly known vulnerabilities in unpatched downstream environments where TraceGuard is only one component

## Deployment Hardening

Because TraceGuard runs with elevated privileges, treat deployment choices as part of your security posture.

- Run the latest supported release and keep the host kernel and Go dependencies current.
- Prefer the packaged systemd unit or an equivalent hardened service definition with a tight capability set and restricted writable paths.
- Expose `-metrics-addr` only on localhost or a trusted management network. The built-in `/health` and `/metrics` server is plain HTTP and does not provide authentication.
- Keep `-blocklist-url` and `-event-export-url` on `https://` endpoints. Use custom CA roots and mTLS for event export where appropriate.
- Protect `TRACEGUARD_EVENT_EXPORT_AUTH_TOKEN`, client certificates, cache files, export spool data, and logs with least-privilege filesystem permissions.
- Review Kubernetes API credentials and RBAC carefully before enabling `-kubernetes-enrich`.
- Run `./traceguard -doctor` before production rollout and after significant environment changes.

## Safe Handling Notes

If you believe a report may expose user data, credentials, host details, or a working exploit path, keep the report private and avoid attaching sensitive logs or telemetry to public discussions.
