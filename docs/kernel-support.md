# Kernel support

TraceGuard requires Linux 6.12 or newer with cgroup v2 mounted and kernel BTF
at `/sys/kernel/btf/vmlinux`. It refuses to start on an older kernel instead of
running with coverage it cannot report accurately.

## Why 6.12

TraceGuard's features use kernel facilities added across several releases.
Linux 6.12 is the oldest long-term kernel line that has all of them, so one set
of eBPF objects covers every supported host. Supporting older kernels would
need separate objects per feature set, each verified on each kernel line,
and hosts on those kernels would silently lose hooks such as AF_UNIX policy.
The minimum stays at 6.12; [the doctor](#checking-a-host) shows what a given
host supports.

## What each feature needs

| Feature | Kernel facilities | Host configuration |
| --- | --- | --- |
| DNS, connection, and resolver telemetry; DNS blocking | `cgroup_skb` and `cgroup/sock_addr` programs, the BPF ring buffer, `bpf_loop` | cgroup v2 |
| Exec, file audit, file change, and security events | Syscall entry tracepoints | Tracepoint perf-event access: `CAP_PERFMON`, or a lowered `kernel.perf_event_paranoid` |
| Egress, bind, and sockopt policy; cgroup ancestry selectors | `cgroup/sock_addr` and `cgroup/setsockopt` programs, `bpf_get_current_ancestor_cgroup_id`, `bpf_loop` | cgroup v2 |
| AF_UNIX policy | `cgroup/connect_unix` and `sendmsg_unix` programs (Linux 6.7), the `bpf_cast_to_kern_ctx` and `bpf_rdonly_cast` kfuncs; `recvmsg_unix` only adds audit events and is not needed for enforcement | — |
| Exec and file enforcement | BPF LSM programs, task storage, `bpf_d_path` | `CONFIG_BPF_LSM=y` and `bpf` in the `lsm=` list; host-wide, so `TRACEGUARD_CGROUP_PATH=/sys/fs/cgroup` |
| TCP lifecycle telemetry | `sockops` programs | — |
| Enhanced telemetry fields | The Linux 7.1 object, which adds `socket_cookie` and reports `kernel_feature_set=linux71` instead of `legacy` | None; TraceGuard falls back to the standard object automatically |
| Persistent attachments with `-pin-ebpf` | `bpf_link` for cgroup and tracepoint attachments | bpffs at `/sys/fs/bpf` |
| Program statistics with `-ebpf-stats` | `BPF_ENABLE_STATS` | — |

Compatibility variants of the eBPF object work around verifier differences in
the DNS and `recvmsg` programs. On 6.12 kernels TraceGuard loads the DNS
compatibility variant directly; on other kernels, including with the Linux 7.1
object, it tries the default variant first and falls back to the DNS or
`recvmsg` variants when the verifier rejects those programs. TraceGuard picks
the variant automatically and logs it as `selected_bpf_object`.

On Linux 6.19 up to, but not including, 7.2, a kernel change can stop syscall
tracepoint programs from running on any CPU but the one their perf event was
opened on. On those kernels TraceGuard opens one extra counting perf event per
syscall tracepoint per online CPU, so it needs one file descriptor for each:
up to 43 tracepoints times the CPU count. If the open file limit is too low,
startup fails and asks you to raise `LimitNOFILE`; the packaged systemd unit
sets `LimitNOFILE=131072`. A CPU brought online after startup is covered from
the next start.

## When something is unavailable

Every optional program loads and attaches on its own, so one the kernel rejects
does not take others with it:

- An unavailable hook is recorded as an `optional eBPF hook unavailable` error
  and listed in the heartbeat's `unavailable_hooks`.
- An exec, file, bind, AF_UNIX, or socket-option enforcement policy whose
  hook is not attached is rejected, and `traceguard_hook_healthy` for that hook
  is `0`.
- With `-strict-hooks`, any unavailable optional hook stops startup instead.

Syscall tracepoints attach individually too. An architecture without a syscall,
such as arm64, which has no `open`, `creat`, `unlink`, `rename`, `chmod`, or
`chown`, skips that tracepoint; the `*at` variants those architectures use are
observed.

## Checking a host

`traceguard -doctor` reports, before deployment:

- the kernel release and whether BTF and BPF LSM are available;
- which eBPF object variant loads; optional hooks are verified by their real
  attach when the daemon starts, and reported as described above;
- tracepoint perf-event access;
- advisory host posture: BPF LSM, `kernel.unprivileged_bpf_disabled`, kernel
  lockdown, module signature enforcement, and Yama `ptrace_scope`.

Posture lines are `INFO` or `WARN` and never fail the doctor: they describe
the host TraceGuard protects, not whether TraceGuard can run on it.

## Testing

CI runs the eBPF integration tests on GitHub's `ubuntu-latest` runners. They
load the standard and Linux 7.1 objects through the verifier and exercise their
programs, and also load the variant the runner's kernel selects; unit tests
check that every embedded variant has the expected programs and maps, but do
not verifier-load them. The 6.12 DNS compatibility path and the other
compatibility variants are verified only on a kernel that selects them, so run
the tests on each target kernel before rollout:

```bash
sudo make test-ebpf
```
