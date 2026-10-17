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
| `builtin_profiles` | Explicitly lists built-in detection profiles. The only supported profile is `baseline`, which is enabled by default. |
| `disabled_rule_ids` | Removes enforcement, custom detection, or built-in detection rule IDs after policy sources are merged. |
| `dns` | Domain and encrypted-resolver block/allow entries. |
| `egress` | Outbound TCP/UDP policy, including the default action. |
| `exec` | Host-wide BPF LSM execution-path policy. |
| `file` | Host-wide BPF LSM file-open policy. |
| `bind` | Local IPv4/IPv6 TCP and UDP bind policy. |
| `unix` | AF_UNIX connect/sendmsg/recvmsg policy. |
| `sockopt` | Selected `setsockopt` level/name policy. |
| `detections` | Alert-only rules evaluated against enriched TraceGuard events. |

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
omitted ports match any port, including port `0` for an ephemeral allocation;
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

As with egress rules, values within one match list are OR conditions and
different non-empty fields are AND conditions. The `exclude` block uses the
same rule: every configured exclusion field must match for the event to be
excluded.

### Supported events

| Event | Description |
| --- | --- |
| `dns` | Observed outbound plaintext DNS query, including DNS dry-run decisions. |
| `blocked` | DNS query denied in block mode. |
| `exec` | Process execution. |
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
| `destination_cidrs` | Destination IPv4 or IPv6 address ranges. |
| `ports` | Destination ports. |
| `executable_globs` | Kernel-resolved executable path globs; valid only with `exec_blocked` and `exec_would_block`. |
| `file_path_globs` | Kernel-resolved file path globs; valid only with `file_blocked` and `file_would_block`. |
| `file_access` | `read`, `write`, or `unknown`. |

Detection path patterns must be either a clean absolute exact path or a clean
absolute literal stem ending in `/**`. The stem is limited to 247 bytes so it
is always complete in the event ABI. For example, `/etc/ssh/**` matches
`/etc/ssh` and descendants even when the remainder of a very long canonical
path is truncated. Other wildcard shapes are rejected. Truncated enforcement
events include `path_truncated=true`, and never satisfy an exact-path selector.

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
| `exec`, `resolver`, `resolver_blocked`, `file_access`, `file_created`, and enforcement decisions | Contemporaneous kernel snapshot. |
| Outbound `connection`, or UDP `connection` in either direction | Contemporaneous kernel snapshot. |
| Inbound TCP `connection` | Listener-cache telemetry only; UID matching and process-identity grouping require the rule to exclude this scope. |
| `dns`, `blocked`, `tcp_sockops` | Unavailable or cache-only; UID matching and process-identity grouping are rejected. |

For `connection`, a UID selector or `group_by` value of `cgroup`, `executable`,
`program`, or `uid` must restrict the effective rule to `directions: [outbound]`
or `protocols: [udp]`. `command_globs`, cgroup-path, service, container,
Kubernetes, and LSM-label detection selectors are rejected until those values
can be captured as event-time snapshots.

Syscall audit events expose `requested_path` with
`path_source=syscall-requested`. It may be relative, use a symlink, or name an
`openat` alias and is therefore not eligible for `executable_globs`,
`file_path_globs`, or `group_by: [path]`. LSM enforcement events expose the
resolved canonical path as `path` or `exe` and are the supported source for
path-based detections.

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
| `destination` | Peer/destination address. |
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
| `baseline.policy-denial-burst` | Five resolver, egress, exec, file, bind, Unix, or sockopt denials within one minute for the same cgroup and executable. Plaintext DNS packet decisions are excluded because their process identity may be cache-only. |

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

### Detection alert output

Alerts use `event=detection_alert`. They retain the source event fields and add:

- `source_event`;
- `detection_rule_id`;
- `severity`;
- `detection_message`;
- `tags`;
- `threshold_count` and, for threshold rules, `threshold_window`.

Telemetry is bounded before it reaches any sink: messages and individual
strings are limited to 4 KiB, records to 128 fields and 32 KiB serialized,
HTTPS export batches to 1 MiB, and UDP syslog datagrams to 8 KiB. When content
must be reduced, the record includes `telemetry_truncated=true` and a truncated
field count.

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

An authorization header, custom CA roots, and mTLS are supported:

```bash
sudo ./traceguard -dry-run \
  -policy-url https://policy.example/traceguard/v1 \
  -policy-authorization 'Bearer token' \
  -policy-ca-path /etc/traceguard/policy-ca.crt \
  -policy-client-cert /etc/traceguard/policy-client.crt \
  -policy-client-key /etc/traceguard/policy-client.key
```

The client certificate and key must be configured together. All file paths must
be absolute.

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
| `-policy-authorization` | `TRACEGUARD_POLICY_AUTHORIZATION` | Optional HTTP `Authorization` header value. |
| `-policy-ca-path` | `TRACEGUARD_POLICY_CA_PATH` | Optional additional CA bundle. |
| `-policy-client-cert` | `TRACEGUARD_POLICY_CLIENT_CERT` | Optional mTLS client certificate. |
| `-policy-client-key` | `TRACEGUARD_POLICY_CLIENT_KEY` | Optional mTLS client key. |

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
version 5, the 32-byte settings ABI, the 632-byte event ABI, and the selected
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
Retransmit signals are deduplicated for 60 seconds. RTT and TCP-connect
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
from the real per-hook attach state.

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
