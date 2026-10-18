# YAML policy

TraceGuard policy files combine DNS, egress, exec, file, bind, Unix-socket,
socket-option, and alert-only detection controls in one strict, versioned YAML
document.

Start with the [complete example](../examples/policy.yaml). The
[JSON Schema](policy.schema.json) can provide validation and completion in an
editor.

## Contents

- [Quick start](#quick-start)
- [Document structure](#document-structure)
- [How policy sources combine](#how-policy-sources-combine)
- [DNS policy](#dns-policy)
- [Egress policy](#egress-policy)
- [Shared enforcement semantics](#shared-enforcement-semantics)
- [Exec policy](#exec-policy)
- [File policy](#file-policy)
- [Bind policy](#bind-policy)
- [Unix policy](#unix-policy)
- [Sockopt policy](#sockopt-policy)
- [Detection rules](#detection-rules)
- [File integrity monitoring](#file-integrity-monitoring)
- [Threat intelligence feeds](#threat-intelligence-feeds)
- [Responses](#responses)
- [Local and remote policy configuration](#local-and-remote-policy-configuration)
- [Operational controls](#operational-controls)
- [Validation rules and limits](#validation-rules-and-limits)
- [Troubleshooting](#troubleshooting)

## Quick start

Copy the example to an absolute path and adjust its example values:

```bash
sudo install -m 0600 examples/policy.yaml /etc/traceguard/policy.yaml
```

Check that TraceGuard can read and parse it:

```bash
sudo ./traceguard -doctor \
  -policy-path /etc/traceguard/policy.yaml
```

Look for `PASS policy-parse` in the doctor output. Other doctor checks can still
fail if the host is not ready to run TraceGuard.

Evaluate blocking decisions without denying traffic:

```bash
sudo ./traceguard -dry-run \
  -policy-path /etc/traceguard/policy.yaml
```

After reviewing the resulting events, enable enforcement:

```bash
sudo ./traceguard -block \
  -policy-path /etc/traceguard/policy.yaml
```

`-dry-run` and `-block` use the same policy. Dry-run permits the operation and
records the corresponding would-block event. Block mode denies it and records
a blocked event. Detection rules are always alert-only.

## Document structure

Every document requires `version: 1`. All other top-level fields are optional.

| Field | Purpose |
| --- | --- |
| `version` | Policy format version. The only supported value is `1`. |
| `builtin_profiles` | Built-in detection profiles: `baseline`, always enabled, and the opt-in `runtime` profile. |
| `disabled_rule_ids` | Removes enforcement, custom detection, or built-in detection rule IDs after policy sources are merged. |
| `dns` | Domain and encrypted-resolver block/allow entries. |
| `egress` | Outbound TCP/UDP policy, including the default action. |
| `exec` | Host-wide BPF LSM execution-path policy. |
| `file` | Host-wide BPF LSM file-open policy. |
| `bind` | Local IPv4/IPv6 TCP and UDP bind policy. |
| `unix` | AF_UNIX connect/sendmsg/recvmsg policy. |
| `sockopt` | Selected `setsockopt` level/name policy. |
| `detections` | Alert-only rules evaluated against enriched TraceGuard events. |
| `detection_exceptions` | Scoped, expiring suppressions for named detection rules. |
| `detection_sequences` | Correlation rules that alert when ordered steps match for one process or cgroup within a window. |
| `file_integrity` | Files whose content and attributes are baselined and compared after changes. |
| `threat_intel` | Local indicator files that DNS and connection events are matched against. |
| `responses` | Reversible actions run when named rules alert. |

A minimal document is:

```yaml
version: 1
```

Rule IDs are shared across every enforcement section and detection rules. They
must:

- begin with a lowercase letter or digit;
- contain only lowercase letters, digits, `.`, `_`, or `-`;
- be between 1 and 64 characters.

IDs must be unique within a document.

## How policy sources combine

TraceGuard can load a remote base policy, a local overlay, or both:

```bash
sudo ./traceguard -dry-run \
  -policy-url https://policy.example/traceguard/v1 \
  -policy-path /etc/traceguard/policy.yaml
```

The merge order is:

| Policy area | Merge behavior |
| --- | --- |
| DNS block/allow entries | Remote and local entries are combined and deduplicated. A local overlay cannot delete a remote DNS entry; add a more specific allow entry when an exception is needed. |
| Egress rules | A local rule replaces a remote rule with the same `id`. Other remote rules remain. |
| Exec, file, bind, unix, and sockopt rules | A local rule replaces a remote rule with the same `id`. Other remote rules remain. |
| Detection rules | A local rule replaces a remote rule with the same `id`. `enabled: false` is a convenient way to replace and disable one. |
| `egress.default` | The local value wins when it is present; otherwise the remote value is retained. The final default is `allow` when neither source sets it. |
| New enforcement defaults | The local section value wins when present; otherwise the remote value remains. All final defaults are `allow` when unset. Exec and file do not permit `default: block`. |
| `builtin_profiles` | Values from both sources are combined. |
| `disabled_rule_ids` | Values from both sources are combined, then applied to the merged rules and built-in detections. |

Policy commits are atomic across all kernel enforcement maps: hooks see either
the previous complete policy or the next complete policy. A failed refresh or
failed apply leaves the last successful policy active.

TraceGuard also tracks in-kernel readers of each policy slot. Before an inactive
slot is reused, the daemon waits for its readers to drain, preventing a rapid
sequence of reloads from rewriting maps still in use by an older hook invocation.
Settings are immutable while their slot is active. After the inactive maps,
settings, and rule-name table are complete, userspace replaces a one-entry hash
selector under RCU. Enforcement events copy the full rule ID in-kernel, so a
queued event remains attributable even after multiple later policy commits.

## DNS policy

DNS entries use the same syntax in `dns.block` and `dns.allow`:

```yaml
dns:
  block:
    - malware.example
    - "*.tracking.example"
    - https://192.0.2.53/dns-query
  allow:
    - updates.tracking.example
    - "*.corp.example"
    - dot://[2001:db8::10]
```

### Supported DNS entries

| Form | Example | Meaning |
| --- | --- | --- |
| Exact domain | `malware.example` | Matches only that domain. |
| Domain suffix | `"*.tracking.example"` | Matches `tracking.example` and every subdomain. Quote the wildcard in YAML. |
| Domain suffix | `suffix:tracking.example` | Equivalent explicit suffix form. |
| Deny-all marker | `"*"` | In `dns.block`, blocks all DNS names and encrypted resolver endpoints unless an allow rule wins. |
| DoH endpoint | `https://192.0.2.53/dns-query` | Matches HTTPS DNS resolver connections at the URL host and port. The URL path is not inspected. |
| DoT endpoint | `dot://192.0.2.53` | Matches DNS-over-TLS at the host and default port 853. `tls://` is also accepted. |
| Bare IP | `192.0.2.53` | Matches both DoH on port 443 and DoT on port 853 at that address. |
| IP CIDR | `192.0.2.0/24` | Matches both DoH and DoT endpoints within the range. IPv6 CIDRs are supported. |

Custom ports are accepted in DoH and DoT URLs:

```yaml
dns:
  block:
    - https://192.0.2.53:8443/dns-query
    - dot://[2001:db8::53]:8853
```

Endpoint hostnames are resolved only for observe-only operation. `-block` and
`-dry-run` reject hostname endpoints and require literal IP or CIDR entries;
otherwise unauthenticated DNS could redefine which resolver connection is
allowed or denied. If observe-only resolution fails, the new policy is rejected
and the previous policy remains active.

### DNS precedence and enforcement

DNS evaluation follows this order:

1. exact allow;
2. suffix allow;
3. block-all;
4. exact block;
5. suffix block;
6. no decision.

Resolver endpoints follow the same allow-first model. This makes specific
exceptions possible:

```yaml
dns:
  block:
    - "*.tracking.example"
  allow:
    - updates.tracking.example
```

Plain DNS names are inspected in outbound UDP and TCP port 53 traffic. DoH and
DoT rules operate on the resolver address and port; TraceGuard does not decrypt
TLS or inspect encrypted DNS contents.

Enforced suffix rules may contain at most 64 bytes in DNS wire format. Longer
suffixes are rejected when block mode needs to install them in the kernel.
Exact domain rules are unaffected by this suffix limit.

## Egress policy

Egress policy controls outbound:

- TCP through `connect4` and `connect6`;
- UDP through `sendmsg4` and `sendmsg6`.

The default is `allow`:

```yaml
egress:
  default: allow
  rules: []
```

Use `default: block` for an allow-list posture, but introduce it in dry-run
mode first.

### Rule anatomy

```yaml
egress:
  default: allow
  rules:
    - id: block-user-metadata
      action: block
      selectors:
        uids:
          - 1000
      destinations:
        cidrs:
          - 169.254.169.254/32
        ports:
          - 80
        protocols:
          - tcp
```

Each rule has:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Stable identifier used in policy events, overlays, and `disabled_rule_ids`. |
| `action` | Yes | `allow` or `block`. |
| `selectors.uids` | No | Numeric Linux UIDs. |
| `selectors.cgroup_paths` | No | Exact clean, absolute cgroup v2 paths. |
| `selectors.cgroup_prefixes` | No | A cgroup path and every descendant. |
| `destinations.cidrs` | No | IPv4 or IPv6 destination prefixes. |
| `destinations.ports` | No | Destination ports. |
| `destinations.protocols` | No | `tcp`, `udp`, or both. |

Matching behavior is deliberately composable:

- values inside one list are alternatives (OR);
- different selector and destination fields must all match (AND);
- if both UID and cgroup selectors are present, both must match;
- an omitted selector makes the rule global;
- omitted CIDRs match all IPv4 and IPv6 destinations;
- omitted ports match every destination port;
- omitted protocols match both TCP and UDP.

IPv4-mapped IPv6 CIDRs at `/96` or longer are canonicalized to their IPv4
equivalent before storage for DNS resolver, egress, bind, and detection policy.
Shorter mapped prefixes are ambiguous across address families and are rejected
before masking.

For example, this blocks TCP ports 22 and 3389 for either UID:

```yaml
- id: block-service-admin-network
  action: block
  selectors:
    uids: [1001, 1002]
  destinations:
    cidrs:
      - 10.20.0.0/16
    ports: [22, 3389]
    protocols: [tcp]
```

### Precedence

Rule order does not determine the result. TraceGuard evaluates:

1. any matching explicit allow rule;
2. any matching explicit block rule;
3. `egress.default`.

An allow rule can therefore carve an exception out of a broad block:

```yaml
egress:
  default: allow
  rules:
    - id: block-batch-internet
      action: block
      selectors:
        uids: [2000]
      destinations:
        cidrs: [0.0.0.0/0, "::/0"]

    - id: allow-batch-api
      action: allow
      selectors:
        uids: [2000]
      destinations:
        cidrs: [198.51.100.20/32]
        ports: [443]
        protocols: [tcp]
```

DNS and egress are independent gates. Allowing a DNS name does not
automatically allow a later connection to its address, and allowing an egress
address does not override a DNS block.

### Cgroup selectors

Cgroup selectors are paths relative to the configured cgroup v2 root, written
with a leading `/`. TraceGuard resolves them to kernel cgroup IDs.

- `cgroup_paths` matches only the named cgroup.
- `cgroup_prefixes` resolves the named root once and matches that cgroup and its
  descendants in-kernel by walking the task's cgroup ancestry.
- paths must be absolute and clean: `/system.slice/app.service` is valid;
  `system.slice/app.service` and `/system.slice/../app.service` are rejected.

Every selected path or prefix root must exist when the policy is applied.
Prefix roots must be between cgroup hierarchy levels 0 and 63 inclusive;
deeper roots are rejected because the bounded in-kernel ancestry walk cannot
inspect them.

In block or dry-run mode, explicit `block` rules may not use either cgroup
selector. Linux cgroup IDs change when a selected path is deleted and
recreated, so an ID-based scoped deny would otherwise fail open until userspace
noticed the replacement. Cgroup selectors remain available on `allow` rules:
combine them with a section-level `default: block` where supported. A missing
or recreated allow selector then remains fail-closed. In observe-only mode,
cgroup-scoped block rules are accepted for telemetry because they cannot make
an enforcement promise. The 30-second rescan repairs observation and allow
entries after cgroup changes; it is not an admission-control boundary.

### Egress rule expansion

Rules are expanded into kernel map entries across selected identities, address
families, CIDRs, protocols, and ports. Very large Cartesian products can exceed
the 16,384-entry capacity for an action/address-family map and are rejected.
Prefer a CIDR over listing many individual addresses, and split policies by
workload when practical.

## Shared enforcement semantics

Egress and the five additional kernel policy sections use the same decision
order:

1. any matching explicit `allow` rule;
2. any matching explicit `block` rule;
3. the section default.

Rule order is irrelevant. Values within one selector list are alternatives;
UID and cgroup selectors used together must both match. An omitted selector
makes a rule global. Cgroup selectors in every enforcement section are included
in the same 30-second reconciliation pass described above.

Sections that contain a block rule, or support and select `default: block`, are
active only with `-block` or `-dry-run`. An allow-only section with the default
`allow` remains disabled. In dry-run mode a deny is logged but permitted. In
block mode it is rejected even when a full event ring buffer prevents logging.

The exec, file, and unix sections accept a deliberately small enforced path
syntax:

| Form | Example | Meaning |
| --- | --- | --- |
| Exact | `/etc/shadow` | Matches that path only. A trailing NUL in the kernel key prevents it from matching `/etc/shadow.bak`. |
| Descendant prefix | `/tmp/**` | Matches `/tmp`, `/tmp/`, and descendants such as `/tmp/tool`, but not `/tmp2`. |
| Abstract Unix exact | `"@docker.sock"` | Unix policy only; `@` represents the kernel's leading NUL. |

Shell wildcards such as `/tmp/*`, `*.so`, and `/usr/bin/python*` are not valid
for enforcement. Exact paths are limited to 240 bytes. A `/**` stem must be a
clean path between 4 and 240 bytes and cannot be root. These byte limits are
enforced by TraceGuard even if an editor's JSON Schema counts Unicode
characters instead.

Optional kernel hooks are loaded and attached independently. Their absence does
not prevent the required TraceGuard monitor from starting. A policy that
requests a deny from an unavailable hook is rejected, however, so the operator
never receives a false claim that requested enforcement is active. The previous
complete policy stays in place after such a rejection.

## Exec policy

Exec policy mediates the resolved executable path with the BPF LSM
`bprm_check_security` hook:

```yaml
exec:
  default: allow
  rules:
    - id: block-temp-exec
      action: block
      selectors:
        uids: [1000]
      match:
        path_globs:
          - /tmp/**
          - /dev/shm/**
```

`exec.default` may only be `allow`. Every allow or block rule requires at least
one `match.path_globs` entry; there is no empty-match or wildcard deny-all.

This is a MAC LSM hook and is host-wide—it does not inherit `-cgroup-path`.
UID and cgroup selectors still scope individual rules inside the program, but
TraceGuard refuses exec enforcement unless `-cgroup-path` is exactly
`/sys/fs/cgroup`. Use `traceguard -doctor` to check `lsm-scope`, then confirm
`lsm_exec_attached=true` in the startup feature log or
`traceguard_hook_healthy{hook="lsm-exec"}` at runtime.

TraceGuard resolves the executable through `bpf_d_path`. Most resolution
errors fail open without an event. A true kernel `ENAMETOOLONG` result produces
a `truncated` decision and is denied in block mode. A successfully resolved
path longer than the policy key limit is not automatically denied: prefix
rules can still match its first 241 bytes, and no match remains allowed.
The TraceGuard daemon's own thread-group ID is exempt so it can publish a
recovery policy. The kernel identifies the daemon by its host PID and boot-time
start, so exec and file enforcement are refused when TraceGuard runs outside
the host PID or time namespace (for example, in a container without host PID).

## File policy

File policy uses the BPF LSM `file_open` hook and the same host-wide
scope rules as exec policy:

```yaml
file:
  default: allow
  rules:
    - id: block-sensitive-auth-write
      action: block
      match:
        path_globs:
          - /etc/shadow
          - /etc/sudoers
          - /etc/sudoers.d/**
        access: [write]
```

`file.default` may only be `allow`, and every rule needs at least one path.
`match.access` accepts `read` and `write`. Omit it, or list both values, to
match either access class. TraceGuard classifies read-only opens without
`O_CREAT` or `O_TRUNC` as `read` and `O_RDWR` opens as both `read` and `write`;
all other opens are `write`. An `O_RDWR` open is denied when either its read or
its write access is denied, so a `read` block rule also stops read-write opens.

The policy covers `security_file_open` only. It does not mediate `chmod`,
`unlink`, standalone `truncate`, or a later writable `mmap` of a file opened
read-only. On the supported Linux 6.12 baseline, `O_PATH` returns before the
LSM `file_open` hook and is not denied. The separate open-syscall audit
tracepoints can still report attempts that this policy cannot mediate.

## Bind policy

Bind policy mediates the local tuple supplied to IPv4 and IPv6 `bind()` for TCP
and UDP:

```yaml
bind:
  default: allow
  rules:
    - id: block-workload-ssh-listener
      action: block
      selectors:
        uids: [2000]
      endpoints:
        cidrs: [0.0.0.0/0, "::/0"]
        ports: [22]
        protocols: [tcp]
```

The `endpoints` fields use the same syntax as egress destinations, but describe
the requested local address and port. Omitted CIDRs cover IPv4 and IPv6;
omitted ports match any port, including port `0` for an ephemeral allocation
(an explicit `0` is rejected because it would also match every fixed port);
omitted protocols cover TCP and UDP. Other protocols are allowed.

`bind.default` may be `allow` or `block`. IPv6-only rules require only the
bind6 hook. IPv4 rules, omitted CIDRs, and a default-block posture require both
hooks, because IPv4-mapped IPv6 addresses are evaluated as IPv4 in bind6. A
wildcard `::` bind can also accept IPv4 connections on a dual-stack socket, so
it must pass both the IPv4 wildcard (`0.0.0.0`) and IPv6 `::` policy. The hook
cannot see `IPV6_V6ONLY`, so v6-only wildcard binds are checked the same way. TraceGuard does
not rewrite an address or port. A permitted bind still reaches the existing
post-bind listener cache; a denied bind does not.

## Unix policy

Unix policy mediates AF_UNIX connect and sendmsg operations and audits recvmsg:

```yaml
unix:
  default: allow
  rules:
    - id: block-docker-socket
      action: block
      match:
        path_globs:
          - /var/run/docker.sock
          - "@docker.sock"
        operations: [connect, sendmsg]
```

`match.operations` accepts `connect`, `sendmsg`, and `recvmsg`; omitting it
selects all three. Connect and sendmsg each have their own optional attachment
and policy readiness check. The kernel does not allow `cgroup/recvmsg_unix` to
deny a receive, so `recvmsg` decisions are audit-only: a matching block rule or
`default: block` emits `unix_would_block` in every mode and the receive
proceeds. A missing recvmsg attachment therefore does not block policy
readiness. Pathname sockets use exact paths or `/**` prefixes. Abstract
socket names use `@` instead of the leading kernel NUL and may contain at most
107 name bytes. The `@name/**` form is also available for slash-delimited
abstract-name prefixes. Quote `@...` values in YAML.

The programs use the AF_UNIX sock-addr kfunc interface available since Linux
6.7. Unnamed sockets, sockaddrs shorter than `sun_path`, unreadable addresses,
and relative pathname sockets fail open without a policy event. There is no
Unix bind hook in this policy version.

## Sockopt policy

Sockopt policy can deny selected `setsockopt` level/name pairs without reading
or changing the option value:

```yaml
sockopt:
  default: allow
  rules:
    - id: block-socket-mark
      action: block
      match:
        levels: [socket]
        optnames: [so_mark]
```

Both lists are required. Supported level aliases are:

| YAML level | Kernel level |
| --- | --- |
| `socket`, `sol_socket` | `SOL_SOCKET` |
| `ip`, `sol_ip` | `SOL_IP` |
| `ipv6`, `sol_ipv6` | `SOL_IPV6` |

Supported names and their levels are `so_mark` and `so_reuseport` at
`socket`, `ip_transparent` at `ip`, and `ipv6_transparent` at `ipv6`. Each name
matches only at its own level: kernel option numbers overlap between levels
(for example `SOL_IP` option 36 is `IP_DROP_MEMBERSHIP`, not `SO_MARK`), so
TraceGuard never crosses the listed levels with the listed names. Every name's
level must appear in `levels`, and every listed level must be used by at least
one listed name. Unknown names are rejected during policy
parsing. `sockopt.default` may be `allow` or `block`.

## Detection rules

Detection rules consume TraceGuard events and emit alerts. They never block
activity. Security selectors use only fields captured for the event in-kernel;
later `/proc` and Kubernetes enrichment remains available in logs but is not a
detection identity.

A rule can alert immediately:

```yaml
detections:
  - id: execution-from-temp
    severity: warning
    events: [exec_blocked, exec_would_block]
    match:
      executable_globs:
        - /tmp/**
        - /var/tmp/**
    cooldown: 5m
    message: temporary-directory execution was blocked or would be blocked
    tags: [execution, suspicious-path]
```

Or after a threshold:

```yaml
- id: repeated-metadata-access
  severity: warning
  events: [connection]
  match:
    directions: [outbound]
    destination_cidrs: [169.254.169.254/32]
    ports: [80]
  exclude:
    uids: [0]
  threshold:
    count: 3
    within: 1m
    group_by: [cgroup, executable]
  cooldown: 5m
  message: repeated metadata access
  tags: [cloud, credential-access]
```

### Detection fields

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Stable rule ID. |
| `enabled` | No | Defaults to `true`. Use `false` to disable a custom or overlaid remote rule. |
| `severity` | Yes when enabled | Syslog severity: `debug`, `informational`, `notice`, `warning`, `error`, `critical`, `alert`, or `emergency`. |
| `events` | Yes when enabled | One or more supported source event names. |
| `match` | No | Conditions that must all match. An omitted block matches every selected event. |
| `exclude` | No | If all configured exclusion conditions match, the event is ignored. |
| `threshold` | No | Count, time window, and grouping needed before an alert. Defaults to one event. |
| `cooldown` | No | Suppresses another alert for the same rule and group for this duration. |
| `message` | Yes when enabled | Human-readable alert text. |
| `tags` | No | Up to 16 labels, each at most 64 characters. |
| `mitre` | No | MITRE ATT&CK mapping: `tactics` such as `TA0005` and `techniques` such as `T1055` or `T1055.008`, up to 16 each. |
| `compliance` | No | Up to 16 free-form control references, such as `pci-dss:10.2.7`, each at most 64 characters. |

As with egress rules, values within one match list are OR conditions and
different non-empty fields are AND conditions. The `exclude` block uses the
same rule: every configured exclusion field must match for the event to be
excluded.

### Supported events

| Event | Description |
| --- | --- |
| `dns` | Observed outbound plaintext DNS query, including DNS dry-run decisions. |
| `blocked` | DNS query denied in block mode. |
| `exec` | Process execution, with the requested path, command line, and executable source. |
| `resolver` | Observed DoH or DoT resolver connection. |
| `resolver_blocked` | DoH or DoT resolver connection denied in block mode. |
| `connection` | Inbound or outbound connection telemetry. |
| `file_access` | Audited file open without create intent. |
| `file_created` | Audited open with create intent. |
| `egress_blocked` | Outbound operation denied by egress policy. |
| `egress_would_block` | Outbound operation that egress policy would deny in dry-run mode. |
| `exec_blocked`, `exec_would_block` | Resolved executable path denied or evaluated in dry-run mode. |
| `file_blocked`, `file_would_block` | File open denied or evaluated in dry-run mode. |
| `bind_blocked`, `bind_would_block` | Local inet bind denied or evaluated in dry-run mode. |
| `unix_blocked`, `unix_would_block` | AF_UNIX operation denied or evaluated in dry-run mode. |
| `sockopt_blocked`, `sockopt_would_block` | Socket option denied or evaluated in dry-run mode. |
| `tcp_sockops` | Observe-only TCP established, listen, retransmit, or close lifecycle signal. |
| `memfd_create` | Anonymous memory file created, a common first step of fileless execution. |
| `ptrace` | Ptrace attach, seize, traceme, or poke request. |
| `process_vm` | `process_vm_readv` or `process_vm_writev` against another process. |
| `module_load` | `init_module` or `finit_module` kernel module load request. |
| `bpf_prog_load` | BPF program load through `bpf(BPF_PROG_LOAD)`. |
| `io_uring_setup` | io_uring instance created. |
| `mount` | `mount` request. |
| `namespace_change` | `setns` or `unshare` request. |
| `privilege_change` | `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `setresgid`, or `capset` request. |
| `file_change` | Path-based unlink, rmdir, rename, chmod, chown, or truncate request, observed with file auditing. |
| `file_integrity` | A watched file was created, modified, deleted, or changed attributes. See [file integrity monitoring](#file-integrity-monitoring). |

`memfd_create` through `privilege_change` are [security events](#security-events).

### Match and exclude conditions

| YAML field | Matches |
| --- | --- |
| `actions` | Event `action`, or its policy decision such as `allow` or `block`. |
| `directions` | `inbound` or `outbound`. |
| `transports` | TraceGuard transport, such as `tcp`, `udp`, `doh`, or `dot`. |
| `protocols` | Socket protocol: `tcp` or `udp`. |
| `uids` | Event-time kernel UID. |
| `domains` | Exact domain, case-insensitive and without a trailing dot. |
| `domain_suffixes` | A suffix and all its subdomains. A leading `*.` is optional. |
| `destination_cidrs` | Peer IPv4 or IPv6 address ranges. For inbound connections this is the remote source address. |
| `ports` | Peer ports. For inbound connections this is the remote source port, not the listening port. |
| `local_ports` | Local ports, such as the listening port of an inbound connection or the requested port of a bind decision; valid only with `connection`, `egress_blocked`, `egress_would_block`, `bind_blocked`, `bind_would_block`, and `tcp_sockops`. |
| `executable_globs` | Kernel-resolved executable path globs; valid only with `exec_blocked` and `exec_would_block`. |
| `command_globs` | Globs over the redacted command line joined with spaces, where `*` also matches `/`; valid only with `exec`. See [exec command lines](#exec-command-lines). |
| `exec_sources` | `path`, or `fd` for an executable named by file descriptor; valid only with `exec`. |
| `mount_fstypes` | Requested filesystem type, such as `debugfs`; valid only with `mount`. |
| `capabilities` | Matches when any listed capability is in a `capset` request's `requested_capabilities`; valid only with `privilege_change`. Names are lowercase without the `cap_` prefix, such as `sys_admin`. |
| `file_path_globs` | Resolved file path globs; valid only with `file_blocked`, `file_would_block`, and `file_integrity`. |
| `unix_path_globs` | AF_UNIX socket paths; valid only with `unix_blocked` and `unix_would_block`. |
| `file_access` | `read`, `write`, or `unknown`. |
| `operations` | Event operation; valid only with `ptrace`, `process_vm`, `module_load`, `namespace_change`, `privilege_change`, and `file_change`, and each value must be one those events carry. See [security events](#security-events) and [file changes](#file-change-events). |
| `changes` | `created`, `modified`, `deleted`, or `attributes`; valid only with `file_integrity`. |

Detection path patterns must be either a clean absolute exact path or a clean
absolute literal stem ending in `/**`. The stem is limited to 247 bytes so it
is always complete in the event ABI. For example, `/etc/ssh/**` matches
`/etc/ssh` and descendants even when the remainder of a very long canonical
path is truncated. Other wildcard shapes are rejected. Truncated enforcement
events include `path_truncated=true`, and never satisfy an exact-path selector.

`unix_path_globs` use the same patterns as `unix.rules[].match.path_globs`: a
clean absolute exact path, an abstract name beginning with `@`, or either form
ending in `/**`. They match the socket address the caller supplied, which is
the same value Unix enforcement evaluates; it is not resolved through
symlinks. Characters such as `[` and `?` are literal, because abstract names may
contain them.

Inbound TCP `connection` events are emitted once per received SYN, so a
threshold on them counts connection attempts. For example, this alerts when one
remote address opens ten SSH connections to port 2222 within a minute:

```yaml
version: 1
detections:
  - id: inbound-ssh-bruteforce-alt-port
    severity: warning
    events: [connection]
    match:
      directions: [inbound]
      protocols: [tcp]
      local_ports: [2222]
    threshold:
      count: 10
      within: 1m
      group_by: [peer]
    cooldown: 10m
    message: a remote address opened repeated SSH connections
```

SSH clients can try several passwords on one connection, up to the server's
`MaxAuthTries`, so a connection count detects scanning and high-rate guessing
rather than every authentication failure.

When a hook runs in a current-task context, `program`, `uid`, `cgroup_id`, and
`process_start_ticks` are captured together in the kernel. Socket metadata
cached at connect or bind time can become stale after exec, a UID change, or a
cgroup migration. TraceGuard therefore exposes it only as `cached_*` telemetry
with `identity_source=socket-cache`; it never supplies detection identity.
`/proc` and Kubernetes enrichment is accepted only when the PID still has the
captured start time and is exposed as `current_*` fields such as `current_exe`,
`current_cmdline`, `current_cgroup`, and `current_k8s_namespace`. Those values
describe the process at consumption time and are never used by detection
matching or grouping.

Process-identity availability is validated when policy is loaded:

| Event scope | Detection process identity |
| --- | --- |
| `exec`, `resolver`, `resolver_blocked`, `file_access`, `file_created`, security events, and enforcement decisions | Contemporaneous kernel snapshot. |
| Outbound `connection`, or UDP `connection` in either direction | Contemporaneous kernel snapshot. |
| Inbound TCP `connection` | Listener-cache telemetry only; UID matching and process-identity grouping require the rule to exclude this scope. |
| `dns`, `blocked`, `tcp_sockops`, `file_integrity` | Unavailable or cache-only; UID matching and process-identity grouping are rejected. A `file_integrity` change carries its triggering process as `actor_*` fields, but rescan findings have none. |

For `connection`, a UID selector or `group_by` value of `cgroup`, `executable`,
`program`, or `uid` must restrict the effective rule to `directions: [outbound]`
or `protocols: [udp]`. Cgroup-path, service, container, Kubernetes, and
LSM-label detection selectors are rejected until those values can be captured
as event-time snapshots. `command_globs` match the exec event's own command
line, captured in the kernel at syscall entry, never the `/proc` command line.

Syscall audit events expose `requested_path` with
`path_source=syscall-requested`. It may be relative, use a symlink, or name an
`openat` alias and is therefore not eligible for `executable_globs`,
`file_path_globs`, or `group_by: [path]`. LSM enforcement events expose the
resolved canonical path as `path` or `exe` and are the supported source for
path-based detections.

### Exec command lines

`exec` events carry what the process asked to run, read in the kernel at
`execve` or `execveat` entry:

| Field | Meaning |
| --- | --- |
| `requested_path` | The path argument, as given. |
| `exec_syscall` | `execve` or `execveat`. |
| `command_line` | Up to 32 arguments and 255 bytes, redacted like `current_cmdline`. |
| `command_line_truncated` | Present and `true` when arguments or bytes were dropped. |
| `exec_source` | `path`, or `fd` when the executable was named by descriptor. |
| `exec_fd` | The descriptor, for `exec_source=fd`. |

`exec_source=fd` covers `execveat` with `AT_EMPTY_PATH` and an empty path, and
paths under `/proc/<pid>/fd/`, `/proc/self/fd/`, and `/dev/fd/`, which is how
`fexecve` runs an executable that may exist only in memory, such as a memfd.

`command_globs` match the redacted command line, so a rule cannot be used to
detect a secret's value. A glob that depends on arguments past the captured
limit cannot match a truncated command line. Like other syscall-entry values,
the arguments can change between capture and the kernel reading them, so treat
the command line as what was requested.

```yaml
version: 1
detections:
  - id: shell-download-pipe
    severity: warning
    events: [exec]
    match:
      command_globs:
        - "* -c *curl *|*sh*"
        - "* -c *wget *|*sh*"
    message: a shell command piped a download into a shell
```

### Security events

With `-security-events`, enabled by default, TraceGuard attaches observe-only
syscall-entry tracepoints for operations used in kernel tampering, fileless
execution, process injection, container escape, and privilege changes. Each
syscall attaches independently, so one that an architecture lacks is skipped
without affecting the others, and none of them denies anything.

Values come from the syscall's requested arguments at entry, marked
`value_source=syscall-requested`; an event does not mean the call succeeded.
High-rate requests are filtered in the kernel: `ptrace` emits only `traceme`,
`attach`, `seize`, and the `poke*` writes, and `bpf` emits only program loads.

| Event | Fields | `operations` |
| --- | --- | --- |
| `memfd_create` | `memfd_name`, `memfd_flags` (`cloexec`, `allow_sealing`, `hugetlb`, `noexec_seal`, `exec`) | — |
| `ptrace` | `operation`, `target_pid` | `traceme`, `poketext`, `pokedata`, `pokeuser`, `attach`, `seize` |
| `process_vm` | `operation`, `target_pid` | `read`, `write` |
| `module_load` | `operation`, `module_param_names` (parameter names only; values are dropped because they can hold credentials); for `finit_module` also `module_fd`, `module_flags`, and `module_path` when the descriptor can be read from `/proc` | `init_module`, `finit_module` |
| `bpf_prog_load` | `bpf_prog_type`, such as `kprobe`, `tracepoint`, `xdp`, or `lsm` | — |
| `io_uring_setup` | `io_uring_entries`, `io_uring_flags` | — |
| `mount` | `mount_source`, `mount_target`, `mount_fstype`, `mount_flags` | — |
| `namespace_change` | `operation`, `namespace_types` (`mount`, `uts`, `ipc`, `user`, `pid`, `net`, `cgroup`, `time`, or `any` for `setns` without a type); `setns_fd` for `setns` | `setns`, `unshare` |
| `privilege_change` | `operation`; `requested_uid` or `requested_gid`, the requested effective ID, omitted when the call leaves it unchanged; `requested_capabilities` for `capset`, from the low 32 capability bits | `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `setresgid`, `capset` |

These events carry a contemporaneous kernel identity, so `uids` selectors and
process-identity grouping work on them. Resolving `module_path` reads
`/proc/<pid>/fd`, which needs ptrace access to the loading process; the field is
omitted when that fails. Disable the group with `-security-events=false` or
`TRACEGUARD_SECURITY_EVENTS=false` if their volume is unwanted; `setuid`-family
calls from login and cron services are the most frequent.

### Thresholds and grouping

`threshold.count` defaults to `1`. When it is greater than one:

- `within` is required and must be no more than one hour;
- `group_by` is required;
- each group keeps an independent event window and cooldown.

Supported `group_by` values are:

| Value | Group identity |
| --- | --- |
| `cgroup` | Event-time kernel cgroup ID, falling back to event-time process identity when that ID is unavailable. |
| `executable` | The acting process: its kernel-resolved executable path when present, otherwise event-time `program`. Exec decision events use the calling `program`, because their `exe` is the denied target. |
| `program` | Process command name. |
| `uid` | Event-time kernel UID. |
| `domain` | DNS domain. |
| `destination` | Peer address. |
| `peer` | Peer address; the remote source address for inbound connections. Equivalent to `destination`. |
| `path` | Kernel-resolved enforcement path. |

Policy loading rejects process-identity group fields for event scopes without
a contemporaneous snapshot. A configured numeric match never treats a missing
field as zero. For an otherwise supported event with a missing cgroup ID,
grouping falls back to its event-time PID, process start ticks, and program
instead of collapsing unrelated processes.

Threshold counts are limited to 10,000. TraceGuard keeps at most 16,384 active
detection groups and 65,536 retained timestamps globally, evicting old samples
and group state at those caps. Count-one rules without cooldown do not allocate
persistent group state.

### Built-in baseline detections

The baseline rules are enabled by default:

| Rule ID | Detects |
| --- | --- |
| `baseline.cloud-metadata-access` | An outbound connection on port 80 or 443 to a cloud metadata or credential endpoint: `169.254.169.254`, AWS IPv6 IMDS `fd00:ec2::254`, AWS ECS `169.254.170.2`, AWS EKS Pod Identity `169.254.170.23` and `fd00:ec2::23`, or Alibaba Cloud `100.100.100.200`. Alerts are grouped by cgroup and executable with a one-hour cooldown, so a polling guest agent cannot hide another process's first access. |
| `baseline.direct-email-egress` | A direct outbound TCP connection on SMTP/submission ports 25, 465, or 587. |
| `baseline.inbound-ssh-bruteforce` | Twenty inbound TCP connection attempts to local port 22 from the same remote address within one minute, with a ten-minute cooldown per address. Redefine it with your SSH port or threshold, or disable it on bastion hosts that legitimately receive many connections from one address. |
| `baseline.policy-denial-burst` | Five resolver, egress, exec, file, bind, Unix, or sockopt denials within one minute for the same cgroup and executable. Plaintext DNS packet decisions are excluded because their process identity may be cache-only. |

Baseline rules carry MITRE ATT&CK mappings: `baseline.cloud-metadata-access`
is `TA0006`/`T1552.005`, `baseline.direct-email-egress` is `TA0010`, `TA0011`
/`T1048`, `T1071.003`, and `baseline.inbound-ssh-bruteforce` is
`TA0006`/`T1110`.

Disable a baseline rule:

```yaml
version: 1
disabled_rule_ids:
  - baseline.cloud-metadata-access
```

Customize a baseline rule by defining the same ID:

```yaml
version: 1
detections:
  - id: baseline.policy-denial-burst
    severity: warning
    events: [resolver_blocked, egress_blocked, exec_blocked, file_blocked]
    threshold:
      count: 10
      within: 2m
      group_by: [cgroup, executable]
    cooldown: 15m
    message: sustained policy denial burst
    tags: [baseline, policy]
```

### Runtime detection profile

The `runtime` profile adds detections over [security events](#security-events)
and exec command sources. It is off by default, so upgrading never changes
which alerts a host raises; enable it explicitly:

```yaml
version: 1
builtin_profiles: [runtime]
```

Every runtime rule except `runtime.persistence-file-change` groups by the
acting cgroup and executable with a cooldown, so one noisy process cannot hide
another's first occurrence.

| Rule ID | Severity | Detects | ATT&CK |
| --- | --- | --- | --- |
| `runtime.kernel-module-load` | warning | An `init_module` or `finit_module` request. | `TA0003`, `TA0005` / `T1547.006` |
| `runtime.bpf-program-load` | notice | A BPF program load. Container networking and observability agents load programs routinely; add exceptions for them. | `TA0005` / `T1014` |
| `runtime.ptrace-attach` | warning | Ptrace `attach`, `seize`, or a `poke*` write into another process. | `TA0004`, `TA0005` / `T1055.008` |
| `runtime.process-memory-write` | warning | `process_vm_writev` into another process. | `TA0004`, `TA0005` / `T1055` |
| `runtime.fileless-exec` | warning | An exec of a file descriptor instead of a path, as from a memfd. runc re-executes itself this way when it starts a container. | `TA0005` / `T1620` |
| `runtime.namespace-join` | notice | `setns` into another namespace, as `nsenter` does. Container runtimes do this routinely. | `TA0004` / `T1611` |
| `runtime.sensitive-filesystem-mount` | warning | A `debugfs`, `tracefs`, or `securityfs` mount. systemd mounts these once at boot. | `TA0004` / `T1611` |
| `runtime.persistence-file-change` | warning | A created, modified, or attribute-changed cron, systemd, init, sudoers, PAM, `ld.so.preload`, account, `sshd_config`, or root SSH file. Fires only for paths `file_integrity` watches; groups by path. | `TA0003`, `TA0004` / `T1053.003`, `T1543.002`, `T1548.003`, `T1556.003`, `T1574.006`, `T1136.001`, `T1098.004` |
| `runtime.sensitive-capability-request` | notice | A `capset` request for `sys_admin`, `sys_module`, `sys_ptrace`, or `sys_rawio`. | `TA0004` / `T1548` |

Tune them with [exceptions](#detection-exceptions), for example for runc on a
container host:

```yaml
version: 1
builtin_profiles: [runtime]
detection_exceptions:
  - id: runc-self-reexec
    rules: [runtime.fileless-exec]
    reason: runc re-executes itself from a memfd at container start
    match:
      uids: [0]
      command_globs: ["runc init"]
```

The command line is chosen by the process that calls exec, so any root process
can present `runc init`; the exception narrows the rule, it does not
authenticate runc. Check the command line your runtime records, which varies by
runtime and version, before copying the glob.

Measure a profile's noise on recorded events with
[replay](#testing-rules-with-replay) before enabling it on a fleet.

### Detection exceptions

An exception suppresses named rules for matching events, with a recorded reason
and an optional expiry. Prefer an exception to disabling a rule or widening its
`exclude`: the rule keeps firing for everything else, the reason travels with the
policy, and an expiry forces the decision to be revisited.

```yaml
version: 1
detection_exceptions:
  - id: guest-agent-imds
    rules: [baseline.cloud-metadata-access]
    reason: the root-owned guest agent polls instance metadata (CHG-1234)
    expires: 2026-12-31T00:00:00Z
    match:
      uids: [0]
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Exception ID, unique among exceptions, using the rule ID format. |
| `rules` | Yes | Built-in or custom detection rule IDs the exception applies to. Naming a rule that is neither built in nor defined is an error; naming a disabled rule is allowed. |
| `reason` | Yes | Why the exception exists, up to 512 bytes. |
| `expires` | No | RFC 3339 instant after which the exception stops applying. Without it the exception never expires. |
| `match` | Yes | Conditions using the same fields as a rule's `match`. It must not be empty, and it must only use fields that every event of each named rule carries at event time. |

An event that a rule matches and an active exception also matches raises no
alert and does not count toward that rule's threshold. Expiry is evaluated
against the event's own timestamp.

Exception IDs merge like rule IDs: a local overlay exception replaces a remote
one with the same ID. Each exception reports through:

- `traceguard_detection_suppressed_total{exception}`, its cumulative suppressed
  events, kept across policy reloads while the exception remains defined;
- `traceguard_detection_exceptions{state="active"|"expired"}`;
- one `detection exception expired` record when it expires;
- the heartbeat's `detection_exceptions` and `expired_detection_exceptions`
  fields.

### Detection sequences

A sequence alerts when its steps match in order for the same key within a time
window, which single-event rules cannot express:

```yaml
version: 1
detection_sequences:
  - id: web-shell-egress
    severity: critical
    key: cgroup
    within: 5m
    steps:
      - events: [exec]
        match:
          command_globs: ["sh -c *", "bash -c *"]
      - events: [connection]
        match:
          directions: [outbound]
    cooldown: 30m
    message: a shell started in a cgroup that then connected out
    mitre:
      tactics: [TA0002, TA0011]
      techniques: [T1059.004]
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Unique among rules and sequences. |
| `key` | Yes | `process` follows one process by its event-time PID and start time, across execs; `cgroup` follows its event-time cgroup ID, such as one container or service. |
| `within` | Yes | Window from the first step's event, at most one hour. |
| `steps` | Yes | Two to eight steps, each with `events` and optional `match` and `exclude`, using the same fields as rules. |
| `cooldown` | No | Suppresses another alert for the same key. |
| `severity`, `message`, `tags`, `mitre`, `compliance`, `enabled` | As for rules | |

Both keys come from the kernel's event-time snapshot, so every step must use
events with that identity: DNS packet events, sockops, file integrity
changes, and connection steps that may match inbound TCP are rejected.

An event advances a key's progress by at most one step, and only if it is no
earlier than the step before it and within the window of the first step.
Events that match no step, or a later step out of order, are ignored. For each
number of completed steps a key keeps the match that started latest, so a new
first step can complete even while an older one is waiting to expire. A
completed sequence starts over. The alert carries the final event's fields,
`threshold_count` as the step count, `threshold_window`, and
`sequence_started`. Exceptions may name a sequence; their match is checked
against the final event. At most 64 sequences and 16,384 in-progress keys are
kept, each until its own sequence's window passes; when that is full, new
sequences start only as old ones expire. Cooldown records have the same limit;
when it is full, the record closest to expiring makes room.

### Testing rules with replay

`-replay` evaluates detection rules over a JSONL event archive written by
`-event-archive-path`, then exits. It is offline: it loads no eBPF programs and
needs no privileges beyond reading the files.

```bash
traceguard -replay /var/log/traceguard/events.jsonl \
  -policy-path /etc/traceguard/candidate-policy.yaml > alerts.jsonl
```

Each alert is written to standard output as one JSON line in the same shape as
a live `detection_alert`. A summary goes to standard error: records read,
evaluated, skipped, and malformed, then every rule that alerted with its alert
count, noisiest first, and each exception's suppressed count and expiry state.

`-policy-path` supplies detection rules, `disabled_rule_ids`, and exceptions;
without it only the built-in baseline runs. Archives ending in `.gz` are read
as gzip. Records that are not kernel events, such as alerts, heartbeats, and
daemon status, are skipped. Replay sees fields only as the archive recorded
them: strings over the 4 KiB telemetry limit are truncated and fields beyond a
record's limits are dropped, so rules matching such values can count
differently than they did live, where detection runs before those limits.
Replayed alerts are recorded with the live alert envelope,
`message=detection-alert` and `level=info`.

### Detection alert output

Alerts use `event=detection_alert`. They retain the source event fields and add:

- `source_event`;
- `alert_id`, a random identifier unique to the alert;
- `detection_rule_id`;
- `severity`;
- `detection_message`;
- `tags`;
- `threshold_count` and, for threshold rules, `threshold_window`;
- `mitre_tactics`, `mitre_techniques`, and `compliance`, when the rule sets them.

Telemetry is bounded before it reaches any sink: messages and individual
strings are limited to 4 KiB, records to 128 fields and 32 KiB serialized,
HTTPS export batches to 1 MiB, and UDP syslog datagrams to 8 KiB. When content
must be reduced, the record includes `telemetry_truncated=true` and a truncated
field count.

## File integrity monitoring

`file_integrity` names files whose content and attributes TraceGuard records
and compares when they change:

```yaml
version: 1
file_integrity:
  paths:
    - /etc/**
    - /root/.ssh/**
    - /usr/bin/sudo
  exclude:
    - /etc/mtab
  hash: true
  max_hash_bytes: 16777216
  rescan_interval: 1h
```

| Field | Default | Meaning |
| --- | --- | --- |
| `paths` | — | Exact clean absolute paths, or subtrees ending in `/**`. Watching starts when at least one is set. |
| `exclude` | — | Paths or subtrees within `paths` to skip. |
| `hash` | `true` | Record a SHA-256 of each regular file. |
| `max_hash_bytes` | 16 MiB | Larger files are compared by size and modification time instead; at most 1 GiB. `0` selects the default. |
| `rescan_interval` | `1h` | Period of the full rescan; `0` disables it, otherwise at least `1m`. |

A remote base and local overlay watch the union of their `paths` and
`exclude` lists; the overlay's `hash`, `max_hash_bytes`, and
`rescan_interval` win when set. `paths` and `exclude` together are limited to
256 entries.

### How changes are found

When policy is applied, TraceGuard scans the watched paths into a baseline
without reporting anything. Symlinks are recorded, never followed, and only
regular files are hashed, through a non-blocking, no-follow open, so a path
swapped for a FIFO or symlink cannot stall or redirect the scan. The baseline
holds at most 100,000 entries; beyond that `traceguard_file_integrity_truncated`
is `1` and a `file integrity baseline truncated` error is recorded.

Changes are then found two ways:

- A [file change event](#file-change-events) on a watched path, or on a
  directory above one, such as a renamed parent, queues that path, as does a
  write or create open when file auditing is on. One second later
  TraceGuard rechecks it and compares it with the baseline, so a burst of writes
  produces one report. Relative paths are resolved through the process's
  `/proc` working directory or descriptor, which needs ptrace access to the
  process; paths that cannot be resolved wait for the rescan. Events from
  processes in another mount namespace, such as a container's, are skipped,
  because their paths name that namespace's files; the rescan covers writes
  they make to host files through bind mounts.
- Every `rescan_interval`, a full rescan reports any difference events missed,
  such as writes through a descriptor opened earlier.

With file auditing off, writes reach file integrity monitoring only through
the rescan, and TraceGuard records an error saying so when the policy is
applied; with `rescan_interval: 0` as well, content changes go unseen.

Each difference is recorded as a `file_integrity` event and evaluated by
detection rules:

| Field | Meaning |
| --- | --- |
| `path` | The watched path. |
| `change` | `created`, `modified` (content or file type), `deleted`, or `attributes` (mode, owner, or group). |
| `changed` | Which of `content`, `type`, `mode`, `owner`, and `group` differ. |
| `detection_source` | `event` for a queued check, `rescan` for a periodic finding. |
| `file_type`, `mode`, `owner_uid`, `owner_gid`, `size`, `mtime`, `link_target` | The current state. |
| `sha256`, or `hash_skipped` | The digest, or why there is none: `disabled`, `size`, `not_regular`, or `unreadable`. |
| `previous_*` | The same fields from the baseline. |
| `actor_*` | The triggering event's `event`, `operation`, `pid`, `program`, `kernel_uid`, `cgroup_id`, `process_start_ticks`, and `current_*` enrichment, for `detection_source=event`. |

Content comparison uses digests when both states were hashed and falls back to
size and modification time otherwise. Metrics are
`traceguard_file_integrity_files`, `traceguard_file_integrity_truncated`,
`traceguard_file_integrity_changes_total{change}`, and
`traceguard_file_integrity_dropped_checks_total`; when more than 4,096 paths are
queued at once, the overflow is dropped and a full rescan runs instead.

File integrity monitoring only observes; it never restores or blocks a file.
Hashing reads every watched file at each policy change and rescan, so prefer
specific subtrees to `/**`.

### File change events

The file change hooks attach whether or not file auditing is on, so file
integrity monitoring always sees these requests; `file_change` events are
recorded only with file auditing. They report path-based unlink, rmdir,
rename, chmod, chown, and truncate requests at syscall entry, with
`requested_path`, `operation`, and as relevant `new_path`, `requested_mode`,
`requested_uid`, `requested_gid`, `truncate_length`, `requested_dirfd`, and
`requested_flags`. Like `file_access`, the path is as requested and may be
relative. Descriptor-based variants such as `fchmod` and `ftruncate` are not
observed; the rescan covers them. TraceGuard's own file activity is excluded
from file audit and file change events, because hashing would otherwise audit
itself.

## Threat intelligence feeds

`threat_intel` names local files of indicators. TraceGuard never downloads
feeds: fetch and verify them with your own tooling, for example a timer that
downloads, checks a signature, and atomically replaces the file.

```yaml
version: 1
threat_intel:
  feeds:
    - id: phishing
      path: /var/lib/traceguard/feeds/phishing-domains.txt
      type: domains
    - id: c2
      path: /var/lib/traceguard/feeds/c2-addresses.txt
      type: addresses
      severity: critical
      block: true
      cooldown: 1h
```

| Field | Default | Meaning |
| --- | --- | --- |
| `id` | — | Feed ID, at most 46 characters; alerts carry `detection_rule_id: threat_intel.<id>`. |
| `path` | — | Clean absolute path to the feed file. |
| `type` | — | `domains`, one hostname per line, or `addresses`, one IP address or CIDR prefix per line. |
| `severity` | `warning` | Alert severity. |
| `block` | `false` | Also enforce the feed in the kernel. See below. |
| `cooldown` | `10m` | Suppresses repeat alerts for one indicator in one cgroup, by event-time or socket-cache cgroup ID. |

Blank lines and text after `#` are ignored. A feed may hold up to 1,000,000
indicators in up to 64 MiB, and a policy up to 32 feeds. A feed that is
missing, unreadable, or invalid does not reject the policy, so it cannot stop
TraceGuard from starting: it keeps its last good contents, or is empty until it
can be read. TraceGuard records a `threat intel feed unavailable` error and sets
`traceguard_policy_source_healthy{source="threat_intel"}` to `0` until every
feed loads.

A domain indicator matches the domain and its subdomains on `dns` and
`blocked` events. An address indicator matches the peer address of
`connection`, `resolver`, `resolver_blocked`, `egress_blocked`, and
`egress_would_block` events, using the longest matching prefix. Alerts are
ordinary `detection_alert` records with `threat_intel_feed` and
`threat_intel_indicator`, also evaluated by `-replay`.
`traceguard_threat_intel_indicators{feed}` reports each feed's size, and
`-doctor` loads every feed and reports `threat-intel-feeds`.

With `block: true`, domain indicators are added as DNS suffix block rules and
address indicators as egress block rules named `threat_intel.<id>.<n>`, 256
prefixes each. They follow the same enforcement mode as written policy:
`-dry-run` reports would-block decisions and only `-block` denies. Blocking
feeds count toward the DNS and egress rule limits, so a policy whose blocking
feeds do not fit is rejected; keep large feeds alert-only.

Feed files are checked every minute and on `SIGHUP` for a changed inode, size,
or modification or change time, so an atomic replace that keeps the size and
timestamp is still seen; an unchanged feed is not re-read. A change re-applies
policy with the new contents, and the policy digest changes with it. Detection
rule thresholds, cooldowns, sequence progress, and feed alert cooldowns carry
over. A reload that fails, such as one whose blocking feeds no longer fit the
rule limits, keeps the previous policy and is retried on the next check.

## Responses

A response runs a reversible action when one of its rules alerts:

```yaml
version: 1
responses:
  - id: block-ssh-scanner
    rules: [baseline.inbound-ssh-bruteforce]
    action: block_peer
    duration: 1h
  - id: freeze-injector
    rules: [runtime.process-memory-write, runtime.ptrace-attach]
    action: freeze_cgroup
    duration: 10m
```

| Field | Meaning |
| --- | --- |
| `id` | Response ID, unique among responses. |
| `rules` | Detection rule, sequence, or `threat_intel.<feed>` IDs. A name that nothing defines rejects the policy. |
| `action` | `block_peer` or `freeze_cgroup`. |
| `duration` | How long the action lasts, at most `24h`. |

`-response-mode` / `TRACEGUARD_RESPONSE_MODE` controls whether actions run:

| Mode | Behavior |
| --- | --- |
| `dry-run` | Default. Records `response would apply` without changing anything. |
| `enforce` | Applies actions. |
| `off` | Ignores responses. `-emergency-allow` forces this mode. |

**`block_peer`** drops traffic to and from the alert's `peer_address`, or
`address` for resolver events, in the cgroup packet hooks, so it covers the
processes under `-cgroup-path`. The kernel entry carries its own deadline, so
it stops applying even if TraceGuard cannot remove it. Loopback, unspecified,
and multicast addresses are never blocked. Packets dropped are counted in
`traceguard_response_peer_drops_total{direction}`.

**`freeze_cgroup`** writes `1` to the alert's event-time cgroup's
`cgroup.freeze`, stopping every process in it until it is thawed. It needs
`-cgroup-path` at the cgroup v2 root and refuses the root, top-level slices
such as `system.slice`, `init.scope`, and any cgroup containing TraceGuard.
Alerts without an event-time `cgroup_id`, such as DNS packet events, skip it.

An action's duration counts from when it is applied. A repeat alert for an
active action extends it rather than stacking a second one; when several
responses apply the same action to the same target, it lasts as long as the
latest one asks and is listed under each `response_ids`. At most 1,024 actions
are active at once. Responses run in the background, with up to 256 alerts
waiting; an alert that finds the queue full is skipped. A cgroup that is
refused, or has gone, is not rescanned for the same response until its
deadline.

Each action is undone when it expires, when every response holding it is
removed from the policy or changed, or when TraceGuard stops. An undo that
fails stays tracked, and the expiry check, which runs every five seconds,
retries it once its deadline has passed; shutdown retries it twice more. After
a crash, the next start clears every peer block and thaws the cgroups recorded
in `-response-state-path` for the same boot. A thaw checks that the path still
names the frozen cgroup, so a replacement at the same path is left alone.
Every step is recorded as an `event=response` record: `response applied` or
`response would apply`, `response extended`, `response reverted` with its
`reason` (`expired`, `policy_removed`, `policy_changed`, `shutdown`, or
`restart`), `response skipped` with its `reason`, and `response failed` or
`response revert failed` with the error.
`traceguard_response_actions_total{action,step}` and
`traceguard_response_active` report the same.

Start in `dry-run` and check the `response would apply` records, ideally with
[replay](#testing-rules-with-replay) evidence that the rules are quiet, before
enabling `enforce`.

## Local and remote policy configuration

### Local policy

`-policy-path` must be an absolute path:

```bash
sudo ./traceguard -dry-run \
  -policy-path /etc/traceguard/policy.yaml
```

### Remote policy

Remote policy requires HTTPS:

```bash
sudo ./traceguard -dry-run \
  -policy-url https://policy.example/traceguard/v1
```

An authorization header, custom CA roots, and mTLS are supported. Set the
authorization header value with `TRACEGUARD_POLICY_AUTHORIZATION`, for example
in the root-only `/etc/traceguard/traceguard.env`, rather than with
`-policy-authorization`: command-line values are visible to local users in
process listings.

To keep the value out of the environment too, store it in a file and set
`-policy-authorization-file` or `TRACEGUARD_POLICY_AUTHORIZATION_FILE` to the
file's absolute path. The file is read once at startup and must be a regular
file, not a symlink, owned by root with no group or other permissions (`0600`
or `0400`). It holds a single line of at most 8 KiB; one trailing newline is
removed. Setting both the value and the file is rejected.

With systemd, `LoadCredential=` copies the file into the service's credentials
directory. systemd does not expand variables in `EnvironmentFile=` values, so
TraceGuard expands a leading `${CREDENTIALS_DIRECTORY}` itself:

```ini
# /etc/systemd/system/traceguard.service.d/credentials.conf
[Service]
LoadCredential=policy-authorization:/etc/traceguard/credentials/policy-authorization
```

```bash
# /etc/traceguard/traceguard.env
TRACEGUARD_POLICY_AUTHORIZATION_FILE=${CREDENTIALS_DIRECTORY}/policy-authorization
```

An `Environment=TRACEGUARD_POLICY_AUTHORIZATION_FILE=%d/policy-authorization`
line in the drop-in works too; `%d` is systemd's credentials directory
specifier.

```bash
sudo ./traceguard -dry-run \
  -policy-url https://policy.example/traceguard/v1 \
  -policy-ca-path /etc/traceguard/policy-ca.crt \
  -policy-client-cert /etc/traceguard/policy-client.crt \
  -policy-client-key /etc/traceguard/policy-client.key
```

The client certificate and key must be configured together. All file paths must
be absolute.

### Signed remote policy

TLS authenticates the policy server, not the policy author. Set
`-policy-signing-key` or `TRACEGUARD_POLICY_SIGNING_KEY` to a PEM Ed25519
public key and TraceGuard accepts a remote document only with a valid detached
signature, so a compromised or misconfigured policy server cannot push policy
it was not given.

The signature is fetched from the policy URL with `.sig` appended to its path,
keeping any query string, using the same credentials. It is the base64
encoding of an Ed25519 signature over the exact document bytes:

```bash
openssl genpkey -algorithm ed25519 -out policy-signing.pem
openssl pkey -in policy-signing.pem -pubout -out /etc/traceguard/policy.pub
openssl pkeyutl -sign -rawin -inkey policy-signing.pem -in traceguard.yaml \
  | base64 -w0 > traceguard.yaml.sig
```

Publish `traceguard.yaml` and `traceguard.yaml.sig` together, and keep the
private key off the policy server. A missing, malformed, or non-verifying
signature fails that fetch like any other refresh error: the last validated
policy stays active. The signature is cached beside the policy cache as
`policy.yaml.sig`, and a stale cache is used only if it still verifies.

Signing applies to the remote base only. A local `-policy-path` overlay is
trusted through its file ownership, and the signing key requires
`-policy-url`.

### Configuration reference

| CLI flag | Environment variable | Purpose |
| --- | --- | --- |
| `-block` | `TRACEGUARD_BLOCK` | Enforce DNS and kernel policy denies. |
| `-dry-run` | `TRACEGUARD_DRY_RUN` | Evaluate denies and emit would-block events without rejecting operations. |
| `-emergency-allow` | `TRACEGUARD_EMERGENCY_ALLOW` | Clear persistent state before startup sinks, ignore policy sources, publish empty enforcement maps, and keep the daemon running. |
| `-cgroup-path` | `TRACEGUARD_CGROUP_PATH` | Root for cgroup eBPF attachments and selector scanning. Exec/file MAC LSM hooks remain host-wide. |
| `-pin-ebpf` | `TRACEGUARD_PIN_EBPF` | Keep compatible maps, programs, and cgroup/tracepoint `bpf_link` objects pinned across daemon restarts; host-wide LSM links remain lifecycle-bound. |
| `-ebpf-stats` | `TRACEGUARD_EBPF_STATS` | Collect kernel program runtime statistics; disabled by default because it has a system-wide performance cost. |
| `-unpin` | — | Remove `/sys/fs/bpf/traceguard` and exit. |
| `-policy-path` | `TRACEGUARD_POLICY_PATH` | Local YAML overlay path. |
| `-policy-url` | `TRACEGUARD_POLICY_URL` | Remote HTTPS base policy URL. |
| `-policy-cache-path` | `TRACEGUARD_POLICY_CACHE_PATH` | Validated remote cache; defaults to `/var/lib/traceguard/policy.yaml`. |
| `-policy-refresh-interval` | `TRACEGUARD_POLICY_REFRESH_INTERVAL` | Remote refresh interval; defaults to `5m`. |
| `-policy-authorization` | `TRACEGUARD_POLICY_AUTHORIZATION` | Optional HTTP `Authorization` header value. Prefer the environment variable or the file; command-line values are visible in process listings. |
| `-policy-authorization-file` | `TRACEGUARD_POLICY_AUTHORIZATION_FILE` | Optional absolute path to a root-only file holding the `Authorization` header value, such as `${CREDENTIALS_DIRECTORY}/policy-authorization`. Cannot be combined with `-policy-authorization`. |
| `-policy-ca-path` | `TRACEGUARD_POLICY_CA_PATH` | Optional additional CA bundle. |
| `-policy-client-cert` | `TRACEGUARD_POLICY_CLIENT_CERT` | Optional mTLS client certificate. |
| `-policy-client-key` | `TRACEGUARD_POLICY_CLIENT_KEY` | Optional mTLS client key. |
| `-policy-signing-key` | `TRACEGUARD_POLICY_SIGNING_KEY` | Optional absolute path to a PEM Ed25519 public key. Remote documents must then carry a valid detached signature at `<policy-url>.sig`. Requires `-policy-url`. |
| `-strict-hooks` | `TRACEGUARD_STRICT_HOOKS` | Refuse to start when any optional eBPF hook cannot be loaded or attached, instead of running with reduced coverage. |
| `-heartbeat-interval` | `TRACEGUARD_HEARTBEAT_INTERVAL` | Interval between heartbeat events; defaults to `5m`, and `0` disables them. |
| `-connection-dedupe-window` | `TRACEGUARD_CONNECTION_DEDUPE_WINDOW` | Window for suppressing repeated connection and TCP retransmit events from the same flow; defaults to `1m`, at most `1h`, and `0` disables suppression. |
| `-response-mode` | `TRACEGUARD_RESPONSE_MODE` | `dry-run` (default), `enforce`, or `off` for [responses](#responses). |
| `-response-state-path` | `TRACEGUARD_RESPONSE_STATE_PATH` | Absolute path recording frozen cgroups so the next start can thaw them after a crash; defaults to `/var/lib/traceguard/responses.json`, and empty disables it. |
| `-event-schema` | `TRACEGUARD_EVENT_SCHEMA` | Record format for HTTPS export and syslog: `traceguard` (default) or `ocsf` for OCSF 1.3.0 events. |
| `-security-events` | `TRACEGUARD_SECURITY_EVENTS` | Attach the observe-only [security event](#security-events) tracepoints; enabled by default. |
| `-replay` | — | Evaluate detection rules over an absolute-path JSONL archive and exit. See [Testing rules with replay](#testing-rules-with-replay). |

### Refresh, cache, and health behavior

Remote requests:

- use a 30-second overall timeout;
- use ETag and Last-Modified conditional requests;
- limit redirect chains;
- require redirects to remain on the original HTTPS origin;
- reject responses larger than 4 MiB.

A remote response is cached atomically with mode `0600`, and its ETag and
Last-Modified values are remembered, only after the effective policy built from
it passes every mode check (aggregate limits, cgroup-scoped block rules,
resolver hostnames, and detection rules). A rejected document is not cached and
does not suppress a later conditional request. The cache is a startup fallback
only: if the first remote request fails, TraceGuard may load the last valid
cache and marks remote health unhealthy. After any remote policy has been
accepted in this process, a refresh failure keeps that remote document as the
base, reports the `last_known` source with remote health unhealthy, and never
rolls back to an older cache. Local overlay changes are still applied on top of
it, so an urgent local exception can be loaded with `SIGHUP` during an outage. If neither
the remote source nor a valid cache is available during startup, startup fails.

The local overlay is read and validated on every load. A local read or
validation error does not fall back to an older local file.

Send `SIGHUP` for an immediate local and remote reload:

```bash
sudo kill -HUP "$(pidof traceguard)"
```

Remote policy is also refreshed on the configured interval. Failed scheduled
or SIGHUP reloads leave the previous complete policy active.

## Operational controls

### Emergency allow

Use `-emergency-allow` when a new explicit deny prevents normal operation. It
ignores local and remote YAML, clears persistent eBPF state before opening log
sinks or listeners, starts fresh observation hooks, atomically publishes empty
maps with every enforcement domain disabled, and remains available for health
and event telemetry:

```bash
sudo ./traceguard -emergency-allow
```

For a pinned deployment, stop the existing daemon before launching this mode;
open link descriptors held by a still-running process keep its policy active.
Host-wide LSM links are intentionally lifecycle-bound and are never pinned, so
they detach when the previous daemon exits and cannot block the recovery
process before its non-reusable daemon identity is published.

### eBPF pinning

`-pin-ebpf` pins maps, programs, and cgroup/tracepoint links beneath
`/sys/fs/bpf/traceguard`. A small pinned map named `layout` records layout
version 7, the 32-byte settings ABI, the 632-byte event ABI, and the selected
eBPF object. Missing metadata, unreadable pins, or an incompatible layout are
discarded and loaded fresh. Compatible maps are adopted, missing maps are
created, programs are replaced, and existing persistent links are updated,
avoiding a second stacked attachment.

Pinning is off by default and requires bpffs at `/sys/fs/bpf`. It also requires
real `bpf_link` support; TraceGuard refuses startup rather than pretending a
legacy, non-pinnable cgroup attachment is persistent. The packaged systemd unit
grants optional write access to bpffs, and TraceGuard creates its private
`0700` directory only when pinning is enabled. An ordinary unpinned start does
not attempt to create or chmod a bpffs directory. If that directory already
exists, unpinned startup fails with `-unpin` guidance so stale persistent links
cannot remain active beside a second collection. Normal daemon shutdown does
not remove persistent pins. If startup fails after creating a new pin set, that
pin set is removed so its links cannot keep policy attached without a daemon;
pins adopted from a previous run are left in place. LSM links close with the daemon, and no pins survive
a host reboot.

To disable pinning, uninstall, or recover, stop the service and remove its pins
before the next unpinned start:

```bash
sudo systemctl stop traceguard
sudo traceguard -unpin
```

Starting without a policy source explicitly publishes an empty policy, so a
pinned policy cannot remain active merely because policy configuration was
removed.

### Sockops and program statistics

When the kernel accepts it, TraceGuard attaches an observe-only sockops program
for TCP active/passive establishment, listen, retransmit, and close signals.
Retransmit signals, like connection events, are deduplicated for
`-connection-dedupe-window`, one minute by default. RTT and TCP-connect
callbacks are intentionally not enabled, and sockops never denies traffic.

`-ebpf-stats` enables `BPF_STATS_RUN_TIME` and polls every loaded program at
startup and every 15 seconds. It exports runtime nanoseconds, run count, and
recursion misses under a `program` label. Kernel runtime accounting has a
system-wide performance cost, so enable it only while the measurements are
useful.

Runtime readiness is exposed through `traceguard_hook_healthy` for `lsm-exec`,
`lsm-file`, `bind`, `unix`, and `sockopt`. A missing optional hook remains
healthy when no policy requests it; it becomes unhealthy, and policy apply is
rejected, when the hook is required. Startup logs distinguish feature probes
from the real per-hook attach state. With `-strict-hooks`, any unavailable
optional hook stops startup instead.

### Heartbeat and policy digest

Every applied policy has a SHA-256 digest of the effective merged policy, so
hosts running the same rules report the same digest regardless of how the
source documents are formatted or split between remote base and local overlay.
It is exported as `traceguard_policy_info{sha256}` and included in the
`policy loaded` record.

A `heartbeat` event is recorded at startup and then every
`-heartbeat-interval`, five minutes by default, through every configured sink.
Its fields are:

| Field | Meaning |
| --- | --- |
| `policy_sha256` | Digest of the active policy. Compare across a fleet to find drift. |
| `policy_mode` | `observe`, `dry_run`, or `block`. |
| `uptime_seconds` | Time since the daemon started. |
| `healthy` | The same verdict as `/health`. |
| `unavailable_hooks` | Optional eBPF hooks that failed to load or attach. |
| `ringbuf_dropped_events` | Events lost to a full ring buffer since startup. |
| `ringbuf_unread_bytes` | Ring buffer bytes waiting to be read at the last sample. |
| `detection_rules`, `detection_state_groups` | Active detection rules and threshold groups. |
| `detection_exceptions`, `expired_detection_exceptions` | Installed exception count and the IDs that have expired. |

A host whose heartbeats stop, whose digest differs from its peers, or whose
`unavailable_hooks` is not empty needs attention, and a SIEM can alert on each
without a central TraceGuard manager.

## Validation rules and limits

TraceGuard rejects:

- unknown YAML fields;
- multiple YAML documents in one file;
- unsupported policy versions;
- duplicate or malformed rule IDs;
- unsupported actions, protocols, events, severities, or grouping fields;
- malformed CIDRs, cgroup paths, durations, or glob syntax;
- documents larger than 4 MiB.

Important limits:

| Item | Limit |
| --- | --- |
| Egress rules | 1,024 |
| Exec, file, bind, unix, and sockopt rules | 1,024 per section |
| Enforced exact path | 1–240 bytes; root is rejected; the kernel key stores a trailing NUL to keep the match exact |
| Enforced `/**` prefix | Clean non-root stem between 4 and 240 bytes |
| Exec, file, and unix path match | At least one `path_glob`; no empty-match deny-all or other `*` syntax |
| Abstract Unix exact name | `@` plus 1–107 bytes |
| Sockopt match | At least one level and one optname |
| Exec and file default | `allow` only |
| Detection rules | 256 |
| Detection exceptions | 256 |
| Detection exception reason | 512 bytes |
| Detection sequences | 64, with 2 to 8 steps each |
| In-progress sequence keys | 16,384 |
| Threat intelligence feeds | 32, each up to 1,000,000 indicators and 64 MiB |
| Responses | 64; at most 1,024 active actions, each up to 24 hours |
| File integrity paths and excludes | 256 |
| File integrity baseline | 100,000 entries |
| Values in one rule list | 256 |
| Detection tags | 16 |
| Detection message | 4,096 bytes |
| Detection path literal/prefix stem | 247 bytes |
| Threshold count | 10,000 |
| Threshold window | 1 hour |
| Active detection groups | 16,384 |
| Retained detection timestamps | 65,536 across all groups |
| Merged DNS rules | 4,096 |
| Merged resolver hostnames | 256 (observe-only; enforced modes require literals) |
| Merged cgroup selectors | 4,096 |
| Cgroup prefix root hierarchy level | 0–63 |
| Enforced suffix wire length | 64 bytes |
| Policy document | 4 MiB |

The schema is useful for editor feedback, but TraceGuard's own parser and
runtime compilation are authoritative because they also validate cgroup
resolution, resolver hostname resolution, and kernel map capacity.

## Troubleshooting

### The policy parses but nothing is blocked

Use `-block` to enforce. `-dry-run` evaluates the same policy but permits the
operation. With neither option, detections and observation still run but policy
denies are disabled. An allow-only section with `default: allow` is also
intentionally inactive.

### Exec or file rules block nothing

Confirm all of the following:

- `-block` or `-dry-run` is enabled;
- `-cgroup-path` is exactly `/sys/fs/cgroup`;
- the host's active LSM list contains `bpf`;
- the startup log reports the corresponding real LSM hook attached;
- TraceGuard runs in the host PID and time namespaces;
- the path uses an exact value or a valid `/**` prefix.

MAC LSM attachment is host-wide even when rules have UID or cgroup selectors.
TraceGuard rejects requested enforcement if scope or attachment readiness is
wrong; it does not silently downgrade the rule.

### Doctor and remote policy

`traceguard -doctor` does not fetch the remote policy. When `-policy-url` is
configured it evaluates the cached remote policy at `-policy-cache-path` merged
with the local `-policy-path` overlay (honouring `disabled_rule_ids`) for the
`lsm-scope`, `exec-enforce-ready`, `file-enforce-ready`, and host-wide-rule
checks. Without a valid cache it reports `WARN policy-remote-cache`, and those
checks cover only the local policy.

### Doctor fails `lsm-scope`

The configured cgroup path selects where cgroup networking programs attach,
but it cannot scope the MAC LSM hooks. Use `/sys/fs/cgroup` for an
exec/file enforcement deployment, or remove those block rules when operating
TraceGuard on a slice-specific cgroup root.

### A file rule misses an operation

File policy covers the LSM file-open hook. It cannot deny `O_PATH`, `chmod`,
`unlink`, standalone `truncate`, or a writable mapping created after a
read-only open. Use the file audit events for visibility and another LSM or
filesystem control where those operations must be prevented.

### A Unix rule misses a socket

Unnamed, too-short, unreadable, and relative AF_UNIX addresses fail open.
Abstract addresses must use quoted `"@name"` policy syntax. There is no Unix
bind policy. Check the independent connect/sendmsg/recvmsg attach fields when a
specific operation is missing.

### A cgroup-scoped rule does not match

Verify that the selector starts with `/` and matches the path relative to the
configured cgroup root, and that the selected path exists. Exact paths do not
include descendants. In block or dry-run mode, cgroup selectors may scope only
`allow` rules; use a section-level default block where supported so a missing
or recreated cgroup remains fail-closed. Prefix roots must be between hierarchy
levels 0 and 63.

### A detection never fires

Check that:

- its `events` value matches the source event;
- every field in `match` is present and matches;
- the entire `exclude` block is not matching;
- threshold `group_by` fields exist on the event;
- path selectors use only the matching LSM blocked/would-block event kinds;
- the rule does not rely on `current_*` or `requested_path` aliases, which are
  intentionally unavailable to detection selectors;
- the rule ID is not in `disabled_rule_ids`.

### A remote refresh is unhealthy

Check `/health`, the policy source metrics, and TraceGuard logs. During stale
cache fallback at startup, enforcement uses the validated cached document while
the remote source remains unhealthy. After startup, a failed refresh keeps the
last accepted remote document, merges the current local overlay over it, and
does not reread the cache.

### Applying policy reports map capacity errors

Reduce the product of selectors, CIDRs, ports, and protocols. Broad CIDRs and
omitted destination dimensions usually require fewer kernel entries than long
lists of individual combinations.

The same expansion limit applies to bind, path, and sockopt policy maps. Reduce
the product of identities, paths or endpoints, access/operation values, and
option names.

### Pinning does not start

Run `traceguard -doctor -pin-ebpf` and check `PASS pin-dir`. Verify bpffs is
mounted at `/sys/fs/bpf`, the service can write there, and the kernel supports
pinnable cgroup `bpf_link` attachments. Stop the service and run
`traceguard -unpin` to discard incompatible pins before retrying.
When pinning is disabled, `traceguard -doctor` also fails `pin-dir` if the
TraceGuard pin root still exists or cannot be inspected, matching startup's
protection against stacked persistent and unpinned collections.
