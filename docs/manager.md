# Connecting an agent to TraceGuard Manager

[TraceGuard Manager](https://github.com/L1ghtn1ng/traceguard-manager) is a fleet
console for TraceGuard agents. An agent sends it alerts and heartbeats over the
HTTPS event export. It can also fetch a signed policy from the manager and take
commands from it. This guide shows how to set up each of these on an installed
agent. Commands and `TRACEGUARD_EVENT_EXPORT_EVENTS=alerts` need TraceGuard 1.9
or later.

| Feature | Agent settings | Needed |
| --- | --- | --- |
| Alerts and fleet health | `TRACEGUARD_EVENT_EXPORT_*`, `TRACEGUARD_EVENT_SCHEMA` | Yes |
| Central policy | `TRACEGUARD_POLICY_URL`, `TRACEGUARD_POLICY_AUTHORIZATION`, `TRACEGUARD_POLICY_SIGNING_KEY` | Optional |
| Commands (block, freeze, lift, refresh) | `TRACEGUARD_COMMAND_URL`, `TRACEGUARD_COMMAND_ACTIONS` | Optional |

All three use the same agent token. The `TRACEGUARD_*` settings below go in
`/etc/traceguard/traceguard.env`, which the packaged systemd unit reads.

## Before you start

- **The manager must be served over HTTPS.** TraceGuard exports only to
  `https://` URLs. Put the manager behind a TLS reverse proxy, and see the
  manager's README for `serve --trust-proxy` and `TGM_CSRF_TRUSTED_ORIGINS`.
- **The agent must be able to reach that address.** Test it from the agent
  host: `curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://manager.example/api/v1/events`
  should print `401`. That means the agent can reach the manager and TLS
  works, but no token was sent.
- **The proxy must allow long requests.** A command poll can stay open for up
  to 25 seconds, and the agent gives up after 40 seconds. Set the proxy's
  read timeout to more than 40 seconds for `/api/v1/commands`. Export batches
  are at most 1 MiB, so the proxy's body size limit must be at least that.

## 1. Enrol the agent

In the manager, open **Fleet → Enrol agent** and give the agent a name, such as
its hostname. The token is shown once, with the settings to copy.

You can also enrol from the manager host:

```bash
uv run traceguard-manager create-agent web-01
```

The command line prints only the token line
(`TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer tgm_...`). Add the URL and the
other settings from step 2 yourself.

The dashboard builds its URLs from the address you opened it at. If you signed
in through an internal address, such as `http://127.0.0.1:8000`, change the
URLs to the HTTPS address the agent uses.

Each agent needs its own token. The manager knows an agent by its token, not by
the hostname it reports, so never share a token between hosts.

## 2. Send alerts and heartbeats

Add these lines to `/etc/traceguard/traceguard.env`:

```bash
TRACEGUARD_EVENT_EXPORT_URL=https://manager.example/api/v1/events
TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer tgm_...
TRACEGUARD_EVENT_EXPORT_EVENTS=alerts
TRACEGUARD_EVENT_SCHEMA=traceguard
```

- `TRACEGUARD_EVENT_EXPORT_EVENTS=alerts` sends only what the manager uses:
  detection alerts, blocks and would-blocks, responses, command records,
  errors, heartbeats and the `agent stopping` record. The manager accepts
  routine telemetry but does not store it, and it would compete with alerts
  for the export queue.
- Keep `TRACEGUARD_EVENT_SCHEMA=traceguard`. The manager does not accept OCSF,
  and it flags an agent that sends OCSF on the agent's page.
- Keep the spool on (`TRACEGUARD_EVENT_EXPORT_SPOOL=true`, the default). Alerts
  raised while the manager is unreachable are then sent when it comes back,
  and the manager ignores any it already has.
- Heartbeats are what mark the agent online, so leave
  `TRACEGUARD_HEARTBEAT_INTERVAL` set (`5m` by default). An agent is shown
  offline when its heartbeats stop for longer than the manager's
  `TGM_AGENT_OFFLINE_SECONDS`.

### Keep the token out of the environment (recommended)

The agent can read the header from a root-only file instead of the environment.
Save `Bearer tgm_...` as a single line, owned by root, with mode `0600` or
`0400`. Then pass it in with a systemd credential:

```bash
sudo install -d -m 0700 /etc/traceguard/credentials
printf 'Bearer %s\n' 'tgm_...' | sudo tee /etc/traceguard/credentials/manager-token >/dev/null
sudo chmod 0400 /etc/traceguard/credentials/manager-token
sudo systemctl edit traceguard
```

```ini
[Service]
LoadCredential=manager-token:/etc/traceguard/credentials/manager-token
```

```bash
# /etc/traceguard/traceguard.env: replace TRACEGUARD_EVENT_EXPORT_AUTHORIZATION with
TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE=${CREDENTIALS_DIRECTORY}/manager-token
```

Set either the value or the file, never both. Commands use the export's
credentials, so they need nothing more. For central policy, also set
`TRACEGUARD_POLICY_AUTHORIZATION_FILE=${CREDENTIALS_DIRECTORY}/manager-token`
instead of `TRACEGUARD_POLICY_AUTHORIZATION`.

### A private CA or mTLS

If the manager's certificate comes from a private CA, point the agent at that
CA. The policy source has its own TLS settings, so set both:

```bash
TRACEGUARD_EVENT_EXPORT_CA_PATH=/etc/traceguard/manager-ca.crt
TRACEGUARD_POLICY_CA_PATH=/etc/traceguard/manager-ca.crt
```

If the proxy requires client certificates, set
`TRACEGUARD_EVENT_EXPORT_CLIENT_CERT` and `TRACEGUARD_EVENT_EXPORT_CLIENT_KEY`.
For central policy, also set `TRACEGUARD_POLICY_CLIENT_CERT` and
`TRACEGUARD_POLICY_CLIENT_KEY`. Commands use the export's TLS settings.

## 3. Restart and check

Run `-doctor` with the service's settings, because it does not read the env
file itself. `CREDENTIALS_DIRECTORY` stands in for the systemd credential, and
only matters if you set the token up as one:

```bash
sudo env CREDENTIALS_DIRECTORY=/etc/traceguard/credentials \
  sh -c 'set -a; . /etc/traceguard/traceguard.env; exec traceguard -doctor'
sudo systemctl restart traceguard
```

`-doctor` checks the settings, certificates and file paths, but does not
contact the manager.

In the enrol dialog, *Waiting for the agent to connect* changes once the first
heartbeat arrives, and **Fleet** then lists the agent as online. If it stays
pending:

- Check the agent's log: `journalctl -u traceguard` or
  `/var/log/traceguard/traceguard.log`.
- On the agent, run
  `curl -s 127.0.0.1:9091/metrics | grep traceguard_event_export_total`.
  - `status="success"` going up means batches are arriving.
  - `error`, `spooled` or `replay_error` going up means they are failing and
    being kept in the spool for later.
  - `rejected` means the manager refused the batch itself (a `400`, `413`,
    `415` or `422` reply). The agent sets that batch aside instead of
    retrying it.
- A `401` means the token is wrong, was rotated, or belongs to a disabled
  agent. Rotate the token on the agent's page and update the agent.
- A `429` means the agent stored more than `TGM_INGEST_MAX_ALERTS_PER_HOUR`
  new alerts in the last hour. The agent keeps the batch in the spool and
  retries it.

## 4. Optional: central policy

On the manager, create a signing key once (see the manager's README, *Central
policy*). Then download the public key from **Administration → Policies**, or
print it with `traceguard-manager policy-key public <key file>`. Copy it to
each agent:

```bash
sudo install -m 0644 manager-policy.pub /etc/traceguard/manager-policy.pub
```

```bash
TRACEGUARD_POLICY_URL=https://manager.example/api/v1/policy
TRACEGUARD_POLICY_AUTHORIZATION=Bearer tgm_...
TRACEGUARD_POLICY_SIGNING_KEY=/etc/traceguard/manager-policy.pub
```

Use the same token as the export. The agent fetches `<url>.sig` and accepts
only a policy signed with that key. It refreshes every
`TRACEGUARD_POLICY_REFRESH_INTERVAL` (`5m` by default), or at once on `SIGHUP`
or a **Refresh policy** command. A policy it rejects is reported to the
manager as an error alert, and the agent keeps its previous policy.

If `TRACEGUARD_POLICY_PATH` is also set, the manager's policy is the base and
the local file is laid over it. An agent with no policy assigned and no
default policy gets an empty one, so it runs on its local file alone. The
agent's page in the manager says whether the agent has taken its assigned
policy. See [policy](policy.md) for the document format.

## 5. Optional: commands

```bash
TRACEGUARD_COMMAND_URL=https://manager.example/api/v1/commands
# Optional: accept fewer than all four actions.
TRACEGUARD_COMMAND_ACTIONS=block_peer,freeze_cgroup,lift_response,refresh_policy
```

- The command URL must use the same host and port as
  `TRACEGUARD_EVENT_EXPORT_URL`, because commands use the export's token and TLS
  settings. The agent refuses to start if it doesn't.
- Commands need a response state file. The packaged default is
  `/var/lib/traceguard/responses.json`, so leave `TRACEGUARD_RESPONSE_STATE_PATH`
  unset. If it is set to an empty value, the agent refuses to start with
  commands on. The agent keeps a journal next to that file, so each command
  runs at most once, even across a restart.
- `TRACEGUARD_RESPONSE_MODE` decides what started actions do. `dry-run`, the
  default, only records `response would apply`, and the manager shows the
  result as a dry run. Set it to `enforce` for blocks and freezes to take
  effect. `off` refuses them. The mode applies only to `block_peer` and
  `freeze_cgroup`.
- The agent still refuses unsafe targets: loopback, unspecified, multicast
  and zoned IPv6 addresses, the manager's own address, and protected or
  TraceGuard's own cgroups.

After a restart, the agent's page in the manager shows *Commands: accepted*.
If it shows *off*, commands sent to that agent expire unread after 10 minutes.

See the [README](../README.md#manager-commands) for how commands are journalled,
retried and reported.

## Full example

An agent that sends alerts, takes its policy from the manager and accepts
commands, with the token in a systemd credential:

```bash
# /etc/traceguard/traceguard.env
TRACEGUARD_EVENT_EXPORT_URL=https://manager.example/api/v1/events
TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE=${CREDENTIALS_DIRECTORY}/manager-token
TRACEGUARD_EVENT_EXPORT_EVENTS=alerts
TRACEGUARD_EVENT_SCHEMA=traceguard

TRACEGUARD_POLICY_URL=https://manager.example/api/v1/policy
TRACEGUARD_POLICY_AUTHORIZATION_FILE=${CREDENTIALS_DIRECTORY}/manager-token
TRACEGUARD_POLICY_SIGNING_KEY=/etc/traceguard/manager-policy.pub

TRACEGUARD_COMMAND_URL=https://manager.example/api/v1/commands
TRACEGUARD_RESPONSE_MODE=enforce
```

## Removing an agent

Stop sending first: clear `TRACEGUARD_EVENT_EXPORT_URL`,
`TRACEGUARD_POLICY_URL`, `TRACEGUARD_POLICY_SIGNING_KEY` and
`TRACEGUARD_COMMAND_URL`, then restart the agent. The signing key must go too,
because the agent refuses to start with a signing key and no policy URL.
Then disable the agent on its page in the manager, or delete it. A disabled
agent's token is refused at once, and an agent still using it gets `401`
replies and keeps its alerts in the spool. Deleting an agent also deletes all
of its alerts, and cannot be undone.
