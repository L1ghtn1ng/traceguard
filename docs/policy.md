# YAML policy

TraceGuard policy files combine three controls in one strict, versioned YAML
document:

- DNS and encrypted-resolver block/allow rules;
- outbound TCP and UDP egress rules;
- alert-only detection rules.

Start with the [complete example](../examples/policy.yaml). The
[JSON Schema](policy.schema.json) can provide validation and completion in an
editor.

## Contents

- [Quick start](#quick-start)
- [Document structure](#document-structure)
- [How policy sources combine](#how-policy-sources-combine)
- [DNS policy](#dns-policy)
- [Egress policy](#egress-policy)
- [Detection rules](#detection-rules)
- [Local and remote policy configuration](#local-and-remote-policy-configuration)
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

`-dry-run` and `-block` use the same policy. Dry-run records DNS
`would-block` events and egress `egress_would_block` events; block mode denies
the matching operation and records blocked events. Detection rules are always
alert-only.

## Document structure

Every document requires `version: 1`. All other top-level fields are optional.

| Field | Purpose |
| --- | --- |
| `version` | Policy format version. The only supported value is `1`. |
| `builtin_profiles` | Explicitly lists built-in detection profiles. The only supported profile is `baseline`, which is enabled by default. |
| `disabled_rule_ids` | Removes rule IDs after policy sources are merged. It can disable egress, custom detection, or built-in detection rules. |
| `dns` | Domain and encrypted-resolver block/allow entries. |
| `egress` | Outbound TCP/UDP policy, including the default action. |
| `detections` | Alert-only rules evaluated against enriched TraceGuard events. |

A minimal document is:

```yaml
version: 1
```

Rule IDs are shared by egress and detection rules. They must:

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
| Detection rules | A local rule replaces a remote rule with the same `id`. `enabled: false` is a convenient way to replace and disable one. |
| `egress.default` | The local value wins when it is present; otherwise the remote value is retained. The final default is `allow` when neither source sets it. |
| `builtin_profiles` | Values from both sources are combined. |
| `disabled_rule_ids` | Values from both sources are combined, then applied to the merged rules and built-in detections. |

Policy commits are atomic: packet and connection hooks see either the previous
complete policy or the next complete policy. A failed refresh or failed apply
leaves the last successful policy active.

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

Endpoint hostnames are resolved when policy is applied. If resolution fails,
the new policy is rejected and the previous policy remains active. Use stable
IP or CIDR entries when DNS resolution during a policy update is undesirable.

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
    - id: block-workload-metadata
      action: block
      selectors:
        uids:
          - 1000
        cgroup_prefixes:
          - /kubepods.slice
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

For example, this blocks TCP ports 22 and 3389 for either UID, but only inside
the selected service:

```yaml
- id: block-service-admin-network
  action: block
  selectors:
    uids: [1001, 1002]
    cgroup_paths:
      - /system.slice/example-api.service
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
        cgroup_prefixes:
          - /system.slice/traceguard-batch
      destinations:
        cidrs: [0.0.0.0/0, "::/0"]

    - id: allow-batch-api
      action: allow
      selectors:
        cgroup_prefixes:
          - /system.slice/traceguard-batch
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
- `cgroup_prefixes` matches the named path and its descendants.
- paths must be absolute and clean: `/system.slice/app.service` is valid;
  `system.slice/app.service` and `/system.slice/../app.service` are rejected.

A rule with cgroup selectors has no kernel entries while none of its paths
exist. TraceGuard rescans cgroups every 30 seconds, so newly created matching
workloads receive the rule without a restart.

### Egress rule expansion

Rules are expanded into kernel map entries across selected identities, address
families, CIDRs, protocols, and ports. Very large Cartesian products can exceed
the 16,384-entry capacity for an action/address-family map and are rejected.
Prefer a CIDR over listing many individual addresses, and split policies by
workload when practical.

## Detection rules

Detection rules consume enriched TraceGuard events and emit alerts. They never
block activity.

A rule can alert immediately:

```yaml
detections:
  - id: execution-from-temp
    severity: warning
    events: [exec]
    match:
      executable_globs:
        - /tmp/**
        - /var/tmp/**
    cooldown: 5m
    message: process executed from a temporary directory
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

### Match and exclude conditions

| YAML field | Matches |
| --- | --- |
| `actions` | Event `action`, or its policy decision such as `allow` or `block`. |
| `directions` | `inbound` or `outbound`. |
| `transports` | TraceGuard transport, such as `tcp`, `udp`, `doh`, or `dot`. |
| `protocols` | Socket protocol: `tcp` or `udp`. |
| `uids` | Kernel UID when available, otherwise the enriched process UID. |
| `domains` | Exact domain, case-insensitive and without a trailing dot. |
| `domain_suffixes` | A suffix and all its subdomains. A leading `*.` is optional. |
| `destination_cidrs` | Destination IPv4 or IPv6 address ranges. |
| `ports` | Destination ports. |
| `executable_globs` | Executable path globs. |
| `command_globs` | Globs matched against the joined command line. |
| `file_path_globs` | File path globs. |
| `file_access` | `read`, `write`, or `unknown`. |
| `cgroup_prefixes` | Exact cgroup path or a descendant. |
| `services` | Exact enriched service names. |
| `container_ids` | Exact container IDs. |
| `pod_uids` | Exact pod UIDs inferred from cgroups. |
| `k8s_namespaces` | Exact Kubernetes namespaces. |
| `k8s_pods` | Exact Kubernetes pod names. |
| `k8s_service_accounts` | Exact Kubernetes service accounts. |
| `k8s_owners` | Exact enriched Kubernetes owner names. |
| `k8s_apps` | Exact enriched Kubernetes app labels. |
| `lsm_sources` | Exact LSM metadata source names. |
| `lsm_labels` | Exact SELinux/AppArmor label values. |

Globs use shell-style matching. `*` does not cross a `/`; a pattern ending in
`/**` matches the directory and everything beneath it. For example,
`/etc/ssh/**` matches `/etc/ssh` and descendant paths.

Kubernetes match fields are populated only when Kubernetes enrichment is
enabled and the event can be attributed to a known pod. File path and access
fields require file auditing.

### Thresholds and grouping

`threshold.count` defaults to `1`. When it is greater than one:

- `within` is required and must be no more than one hour;
- `group_by` is required;
- each group keeps an independent event window and cooldown.

Supported `group_by` values are:

| Value | Group identity |
| --- | --- |
| `cgroup` | Cgroup path. |
| `executable` | Executable path, falling back to the event filename. |
| `program` | Process command name. |
| `uid` | Kernel UID, falling back to process UID. |
| `domain` | DNS domain. |
| `destination` | Peer/destination address. |
| `path` | Audited file path. |
| `service` | Enriched service name. |
| `container` | Container ID. |
| `pod` | Pod UID, falling back to pod name. |
| `k8s_namespace` | Kubernetes namespace. |

Choose fields that are present on the selected events. Missing fields collapse
into an empty group value, which can combine otherwise unrelated activity.

Threshold counts are limited to 10,000. TraceGuard keeps at most 16,384 active
detection groups and evicts old group state when the cap is reached.

### Built-in baseline detections

The baseline rules are enabled by default:

| Rule ID | Detects |
| --- | --- |
| `baseline.exec-from-shared-memory` | Execution from `/dev/shm` or `/run/shm`. |
| `baseline.sensitive-auth-file-write` | Writes to authentication-sensitive files such as `/etc/shadow`, sudoers files, or root SSH configuration. |
| `baseline.policy-denial-burst` | Five DNS, resolver, or egress denials within one minute for the same cgroup and executable. |

Disable a baseline rule:

```yaml
version: 1
disabled_rule_ids:
  - baseline.exec-from-shared-memory
```

Customize a baseline rule by defining the same ID:

```yaml
version: 1
detections:
  - id: baseline.policy-denial-burst
    severity: warning
    events: [blocked, resolver_blocked, egress_blocked]
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

A valid remote response is atomically cached with mode `0600`. If a later
remote request fails, TraceGuard loads the last valid cache and keeps enforcing
it. The remote policy health remains unhealthy until the source recovers. If
neither the remote source nor a valid cache is available during startup, startup
fails.

The local overlay is read and validated on every load. A local read or
validation error does not fall back to an older local file.

Send `SIGHUP` for an immediate local and remote reload:

```bash
sudo kill -HUP "$(pidof traceguard)"
```

Remote policy is also refreshed on the configured interval. Failed scheduled
or SIGHUP reloads leave the previous complete policy active.

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
| Detection rules | 256 |
| Values in one rule list | 256 |
| Detection tags | 16 |
| Threshold count | 10,000 |
| Threshold window | 1 hour |
| Active detection groups | 16,384 |
| Enforced suffix wire length | 64 bytes |
| Policy document | 4 MiB |

The schema is useful for editor feedback, but TraceGuard's own parser and
runtime compilation are authoritative because they also validate cgroup
resolution, resolver hostname resolution, and kernel map capacity.

## Troubleshooting

### The policy parses but nothing is blocked

Use `-block` to enforce. `-dry-run` evaluates the same policy but permits the
operation. With neither option, detections still run but DNS and egress blocks
are not enforced.

### A cgroup-scoped rule does not match

Verify that the selector starts with `/` and matches the path relative to the
configured cgroup root. Exact paths do not include descendants; use
`cgroup_prefixes` when child cgroups should match. Newly created cgroups can
take up to 30 seconds to be reconciled.

### A detection never fires

Check that:

- its `events` value matches the source event;
- every field in `match` is present and matches;
- the entire `exclude` block is not matching;
- threshold `group_by` fields exist on the event;
- file auditing or Kubernetes enrichment is enabled when the rule needs those
  fields;
- the rule ID is not in `disabled_rule_ids`.

### A remote refresh is unhealthy

Check `/health`, the policy source metrics, and TraceGuard logs. During stale
cache fallback, enforcement continues with the last valid remote document while
the remote source remains unhealthy.

### Applying an egress policy reports map capacity errors

Reduce the product of selectors, CIDRs, ports, and protocols. Broad CIDRs and
omitted destination dimensions usually require fewer kernel entries than long
lists of individual combinations.
