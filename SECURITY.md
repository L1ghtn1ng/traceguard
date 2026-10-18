# Security Policy

TraceGuard is a privileged Linux security utility that attaches eBPF programs to cgroup, BPF LSM, sockops, and tracepoint hooks, reads process metadata from `/proc`, and can export telemetry to remote HTTPS or syslog endpoints. Security reports should focus on issues that materially affect privilege boundaries, policy enforcement, confidentiality, integrity, or availability.

## Supported Versions

Security fixes are applied to the latest patch release in the current stable series.

| Version | Supported |
| --- | --- |
| `1.7.x` | Yes |
| `< 1.7.0` | No |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately.

- Prefer GitHub private vulnerability reporting for this repository: <https://github.com/L1ghtn1ng/traceguard/security/advisories/new>
- Do not open a public GitHub issue for an unpatched security issue.
- If GitHub private reporting is unavailable in your environment, contact the repository maintainer privately before disclosing details publicly.

Include as much of the following as you can:

- TraceGuard version and commit, if known
- Linux distribution, kernel version, and whether cgroup v2 is mounted
- Whether the issue occurs in observe, dry-run, or enforced block mode, and whether bpffs pinning is enabled
- Relevant configuration, with secrets and tokens redacted
- Reproduction steps, proof of impact, and any suggested mitigation
- Whether Kubernetes enrichment, file access auditing, remote policy, metrics, or event export are enabled

## Response Process

- Initial acknowledgement target: within 5 business days
- Status updates: provided when triage, fix planning, or release timing materially changes
- Coordinated disclosure: preferred after a fix or effective mitigation is available

## In Scope

The following are generally considered security issues:

- Privilege escalation or unintended code execution
- Bypass of enforced DNS, egress, exec, file-open, bind, AF_UNIX, or socket-option policy
- Exposure of sensitive telemetry, credentials, or local files
- TLS verification flaws in remote policy fetch, HTTPS event export, or TLS syslog export
- Unauthorized access introduced by metrics, logging, cache, or spool handling
- Incorrect SELinux/AppArmor label reporting or file access auditing behavior that materially affects security decisions
- Denial of service caused by untrusted network input or malformed policy input in privileged paths
- Kubernetes enrichment behavior that exposes data beyond the configured node or cluster permissions

## Out of Scope

The following are usually not treated as security vulnerabilities by themselves:

- Detection gaps that are already documented in `README.md`, including the inability to recover encrypted DoH query names
- Availability issues on unsupported kernels, unsupported privilege models, or non-Linux platforms
- False positives, false negatives, or bad entries in externally managed policies without an underlying TraceGuard defect
- Feature requests for new protocols, broader inspection coverage, or alternative deployment models
- Publicly known vulnerabilities in unpatched downstream environments where TraceGuard is only one component

## Deployment Hardening

Because TraceGuard runs with elevated privileges, treat deployment choices as part of your security posture.

- Run the latest supported release and keep the host kernel and Go dependencies current.
- Prefer the packaged systemd unit or an equivalent hardened service definition with a tight capability set and restricted writable paths.
- Test new deny rules in `-dry-run` before enabling `-block`. Exec and file policy uses host-wide MAC LSM hooks and must keep `-cgroup-path /sys/fs/cgroup`; after stopping an existing daemon, use `-emergency-allow` to clear persistent policy and start lifecycle-bound LSM hooks with an empty recovery policy.
- Keep `/sys/fs/bpf/traceguard` root-owned and mode `0700` when `-pin-ebpf` is enabled. Stop the service and run `traceguard -unpin` before uninstalling or downgrading.
- Expose `-metrics-addr` only on localhost or a trusted management network. The built-in `/health` and `/metrics` server is plain HTTP and does not provide authentication.
- Keep `-policy-url` and `-event-export-url` on `https://` endpoints. Use custom CA roots and mTLS where appropriate. Prefer `syslog+tls://` over UDP or plaintext TCP when sending syslog events outside a trusted management network.
- Set `TRACEGUARD_POLICY_AUTHORIZATION` and `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION` in the root-only `/etc/traceguard/traceguard.env` instead of passing `-policy-authorization` or `-event-export-authorization`; command-line values are visible to local users in process listings for the daemon's lifetime.
- To keep these values out of the daemon's environment as well, use `TRACEGUARD_POLICY_AUTHORIZATION_FILE` and `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE`, ideally with systemd `LoadCredential=` and `${CREDENTIALS_DIRECTORY}`. TraceGuard rejects credential files that are symlinks, not owned by root, or accessible by group or others.
- Treat `current_cmdline` as sensitive. TraceGuard redacts common credential forms from monitored process arguments, but secrets passed positionally or in unrecognized spellings are retained in every configured event sink, so keep credentials out of monitored workloads' command lines.
- Protect `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION`, event export client keys, cache files, export spool data, and logs with least-privilege filesystem permissions. The HTTPS export spool can contain structured telemetry from failed batches until replay succeeds.
- File audit and enforcement events can retain filesystem paths and Unix socket names. Set `TRACEGUARD_FILE_AUDIT=false` when the expected event volume or retained path data is not acceptable for the host, and protect every configured event sink accordingly.
- Review Kubernetes API credentials and RBAC carefully before enabling `-kubernetes-enrich`.
- Run `./traceguard -doctor` before production rollout and after significant environment changes.

## Safe Handling Notes

If you believe a report may expose user data, credentials, host details, or a working exploit path, keep the report private and avoid attaching sensitive logs or telemetry to public discussions.
