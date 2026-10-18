#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "include/bpf_endian.h"
#include "include/bpf_helpers.h"

#define DNS_PORT 53
#define DOT_PORT 853
#define HTTPS_PORT 443
#define POLICY_SLOT_COUNT 2
#define POLICY_MAX_ENTRIES_PER_SLOT 16384
#define POLICY_MAP_MAX_ENTRIES (POLICY_SLOT_COUNT * POLICY_MAX_ENTRIES_PER_SLOT)
#define MAX_DOMAIN_LEN 255
#define DOMAIN_KEY_SIZE (MAX_DOMAIN_LEN + 1)
#define MAX_SUFFIX_LABELS 128
#define MAX_SUFFIX_WIRE_LEN 64
#define MAX_FILENAME_LEN 248
#define NSEC_PER_USER_HZ_TICK 10000000ULL
#define EVENT_DNS 1
#define EVENT_BLOCKED 2
#define EVENT_EXEC 3
#define EVENT_RESOLVER 4
#define EVENT_RESOLVER_BLOCKED 5
#define EVENT_CONNECTION 6
#define EVENT_FILE_ACCESS 7
#define EVENT_EGRESS_BLOCKED 8
#define EVENT_EGRESS_WOULD_BLOCK 9
#define EVENT_EXEC_BLOCKED 10
#define EVENT_EXEC_WOULD_BLOCK 11
#define EVENT_FILE_BLOCKED 12
#define EVENT_FILE_WOULD_BLOCK 13
#define EVENT_BIND_BLOCKED 14
#define EVENT_BIND_WOULD_BLOCK 15
#define EVENT_UNIX_BLOCKED 16
#define EVENT_UNIX_WOULD_BLOCK 17
#define EVENT_SOCKOPT_BLOCKED 18
#define EVENT_SOCKOPT_WOULD_BLOCK 19
#define EVENT_SOCKOPS 20
#define EVENT_MEMFD_CREATE 21
#define EVENT_PTRACE 22
#define EVENT_PROCESS_VM 23
#define EVENT_MODULE_LOAD 24
#define EVENT_BPF_PROG_LOAD 25
#define EVENT_IO_URING_SETUP 26
#define EVENT_MOUNT 27
#define EVENT_NAMESPACE_CHANGE 28
#define EVENT_PRIVILEGE_CHANGE 29
#define EVENT_FILE_CHANGE 30
#define EVENT_KIND_MAX EVENT_FILE_CHANGE

/* Security events reuse generic event fields: rule_id carries the
 * operation, file_flags the flags argument, file_mode the target PID or
 * requested ID, filename the primary string argument, and domain a
 * secondary string argument. Values are the syscall's requested arguments
 * at entry, not its outcome.
 */
#define PROCESS_VM_READ 0
#define PROCESS_VM_WRITE 1
#define MODULE_LOAD_INIT 0
#define MODULE_LOAD_FINIT 1
#define NAMESPACE_SETNS 0
#define NAMESPACE_UNSHARE 1
#define PRIVILEGE_SETUID 0
#define PRIVILEGE_SETGID 1
#define PRIVILEGE_SETREUID 2
#define PRIVILEGE_SETREGID 3
#define PRIVILEGE_SETRESUID 4
#define PRIVILEGE_SETRESGID 5
#define PRIVILEGE_CAPSET 6

/* File change events carry the operation in rule_id, the path in filename,
 * the dirfd in file_mode, AT_* flags in file_flags, and the operation's value
 * in socket_cookie: the mode for chmod, uid | gid << 32 for chown, the length
 * for truncate, and the new dirfd for rename, whose new path is in domain.
 */
#define FILE_CHANGE_UNLINK 0
#define FILE_CHANGE_RENAME 1
#define FILE_CHANGE_CHMOD 2
#define FILE_CHANGE_CHOWN 3
#define FILE_CHANGE_TRUNCATE 4
#define TRACEGUARD_AT_REMOVEDIR 0x200
#define TRACEGUARD_AT_SYMLINK_NOFOLLOW 0x100
#define MOUNT_SOURCE_LEN 192
#define MOUNT_FSTYPE_OFFSET MOUNT_SOURCE_LEN
#define TRACEGUARD_BPF_PROG_LOAD 5
#define TRACEGUARD_PTRACE_TRACEME 0
#define TRACEGUARD_PTRACE_POKETEXT 4
#define TRACEGUARD_PTRACE_POKEDATA 5
#define TRACEGUARD_PTRACE_POKEUSER 6
#define TRACEGUARD_PTRACE_ATTACH 16
#define TRACEGUARD_PTRACE_SEIZE 0x4206

/* Exec events carry the command line in domain as NUL-terminated arguments,
 * the captured argument count in port, the execveat dirfd in file_mode, and
 * the execveat flags in file_flags. rule_id names the syscall.
 */
#define EXEC_SYSCALL_EXECVE 0
#define EXEC_SYSCALL_EXECVEAT 1
#define EXEC_ARGV_MAX 32
#define EXEC_ARGV_BYTES (MAX_DOMAIN_LEN + 1)
#define EXEC_ARGV_TRUNCATED (1U << 31)
#define TRACEGUARD_AT_FDCWD (-100)
#define POLICY_DECISION_NONE 0
#define POLICY_DECISION_ALLOW 1
#define POLICY_DECISION_BLOCK 2
#define TRANSPORT_UDP 1
#define TRANSPORT_TCP 2
#define TRANSPORT_DOT 3
#define TRANSPORT_DOH 4
#define FAMILY_IPV4 4
#define FAMILY_IPV6 6
#define FAMILY_UNIX 1
#define DIRECTION_INBOUND 1
#define DIRECTION_OUTBOUND 2
#define SOCKET_PROTOCOL_UDP 1
#define SOCKET_PROTOCOL_TCP 2
#define ATTRIBUTION_KERNEL_SKB 1
#define ATTRIBUTION_KERNEL_SENDMSG 2
#define ATTRIBUTION_KERNEL_CONNECT 3
#define ATTRIBUTION_KERNEL_RECVMSG 4
#define ATTRIBUTION_KERNEL_INGRESS 5
#define DNS_PARSE_OK 0
#define DNS_PARSE_PASS 1
#define DNS_PARSE_DROP 2
#define IPV6_EXT_HEADERS_EXHAUSTED -2
#define SOCKET_HOOK_CGROUP_SKB 1
#define SOCKET_HOOK_CGROUP_SENDMSG4 2
#define SOCKET_HOOK_CGROUP_SENDMSG6 3
#define SOCKET_HOOK_CGROUP_CONNECT4 4
#define SOCKET_HOOK_CGROUP_CONNECT6 5
#define SOCKET_HOOK_CGROUP_SKB_INGRESS 6
#define SOCKET_HOOK_CGROUP_RECVMSG4 7
#define SOCKET_HOOK_CGROUP_RECVMSG6 8
#define SOCKET_HOOK_CGROUP_POST_BIND4 9
#define SOCKET_HOOK_CGROUP_POST_BIND6 10
#define SOCKET_HOOK_CGROUP_BIND4 11
#define SOCKET_HOOK_CGROUP_BIND6 12
#define SOCKET_HOOK_CGROUP_UNIX_CONNECT 13
#define SOCKET_HOOK_CGROUP_UNIX_SENDMSG 14
#define SOCKET_HOOK_CGROUP_UNIX_RECVMSG 15
#define SOCKET_HOOK_CGROUP_SETSOCKOPT 16
#define SOCKET_HOOK_SOCKOPS 17
#define EVENT_SOURCE_SYSCALL_TRACEPOINT 1
#define EVENT_SOURCE_CGROUP_SKB 2
#define EVENT_SOURCE_CGROUP_SOCK_ADDR 3
#define EVENT_SOURCE_CGROUP_SOCK 4
#define EVENT_SOURCE_LSM_MAC 5
#define EVENT_SOURCE_SOCKOPS 6
#define EVENT_SOURCE_CGROUP_SOCKOPT 7
#define KERNEL_FEATURE_SET_LEGACY 1
#define KERNEL_FEATURE_SET_LINUX71 2
#define UID_SOURCE_NONE 0
#define UID_SOURCE_KERNEL 1
#define UID_SOURCE_SOCKET_CACHE 2
#define SOCKET_INFO_MAX_ENTRIES 16384
#define LISTENER_INFO_MAX_ENTRIES 16384
#define CONNECTION_DEDUPE_MAX_ENTRIES 32768
#define EGRESS_IDENTITY_BYTES 17
#define EGRESS_IDENTITY_GLOBAL 0
#define EGRESS_IDENTITY_UID 1
#define EGRESS_IDENTITY_CGROUP 2
#define EGRESS_IDENTITY_UID_CGROUP 3
#define EGRESS_IDENTITY_CGROUP_ANCESTOR 4
#define EGRESS_IDENTITY_UID_CGROUP_ANCESTOR 5
#define MAX_CGROUP_ANCESTORS 64
#define MAX_POLICY_RULE_ID_LEN 64
#define PATH_LPM_FIXED 15
#define PATH_LPM_MAX 241
#define UNIX_OP_CONNECT 1
#define UNIX_OP_SENDMSG 2
#define UNIX_OP_RECVMSG 4
#define FILE_ACCESS_ANY 0
#define FILE_ACCESS_READ 1
#define FILE_ACCESS_WRITE 2
/* Lookup-only value: O_RDWR opens must pass both read and write policy. */
#define FILE_ACCESS_READ_WRITE (FILE_ACCESS_READ | FILE_ACCESS_WRITE)
#define TRACEGUARD_EPERM 1
#define TRACEGUARD_ENAMETOOLONG 36
#define TRACEGUARD_O_ACCMODE 03
#define TRACEGUARD_O_RDONLY 00
#define FILE_ACCESS_FLAG_UNKNOWN (1U << 31)
#define PATH_EVENT_FLAG_TRUNCATED (1U << 31)
#define TRACEGUARD_O_WRONLY 01
#define TRACEGUARD_O_RDWR 02
#define TRACEGUARD_O_CREAT 0100
#define TRACEGUARD_O_TRUNC 01000
#define TRACEGUARD_CREAT_FLAGS (TRACEGUARD_O_WRONLY | TRACEGUARD_O_CREAT | TRACEGUARD_O_TRUNC)

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct vfsmount;
struct dentry;
struct sock;
struct sockaddr;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	__u32 f_flags;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

struct bpf_sock_addr_kern {
	struct sock *sk;
	struct sockaddr *uaddr;
	__u32 t_ctx;
	__u32 flags;
	__u32 uaddrlen;
} __attribute__((preserve_access_index));

struct sockaddr_un {
	__u16 sun_family;
	char sun_path[108];
} __attribute__((preserve_access_index));

#ifndef TRACEGUARD_DNS_NO_CURRENT_COMM
#define TRACEGUARD_DNS_NO_CURRENT_COMM 0
#endif

#ifndef TRACEGUARD_CONNECTION_NO_RECVMSG
#define TRACEGUARD_CONNECTION_NO_RECVMSG 0
#endif

#ifndef TRACEGUARD_LINUX71_TELEMETRY
#define TRACEGUARD_LINUX71_TELEMETRY 0
#endif

#ifndef TRACEGUARD_KERNEL_HELPER_TELEMETRY
#define TRACEGUARD_KERNEL_HELPER_TELEMETRY 0
#endif

struct endpoint4_key {
	__u32 addr;
	__u16 port;
	__u8 transport;
	__u8 _pad;
};

struct endpoint6_key {
	__u8 addr[16];
	__u16 port;
	__u8 transport;
	__u8 _pad;
};

struct endpoint4_cidr_key {
	__u32 prefixlen;
	__u8 data[7];
	__u8 _pad;
};

struct endpoint6_cidr_key {
	__u32 prefixlen;
	__u8 data[19];
	__u8 _pad;
};

struct egress4_key {
	__u32 prefixlen;
	__u8 data[21];
	__u8 _pad[3];
};

struct egress6_key {
	__u32 prefixlen;
	__u8 data[33];
	__u8 _pad[3];
};

struct path_lpm_key {
	__u32 prefixlen;
	__u8 data[256];
};

struct sockopt_key {
	__u8 slot;
	__u8 kind;
	__u8 _pad[2];
	__u32 uid;
	__u64 cgroup_id;
	__u32 level;
	__u32 optname;
};

struct lsm_path_value {
	char path[4096];
};

struct task_struct {
	struct task_struct *group_leader;
	__u64 start_boottime;
} __attribute__((preserve_access_index));

struct domain_key {
	__u8 domain[DOMAIN_KEY_SIZE];
};

struct domain_suffix_key {
	__u64 hash;
	__u16 length;
	__u8 policy_slot;
	__u8 _pad0;
	__u32 _pad1;
};

struct settings {
	__u8 block_enabled;
	__u8 block_all_domains;
	__u8 block_all_resolvers;
	__u8 allow_suffixes_enabled;
	__u8 active_policy_slot;
	__u8 block_suffixes_enabled;
	__u8 egress_enabled;
	__u8 egress_enforce;
	__u8 egress_default_block;
	__u8 exec_enabled;
	__u8 exec_enforce;
	__u8 exec_default_block;
	__u8 file_enabled;
	__u8 file_enforce;
	__u8 file_default_block;
	__u8 bind_enabled;
	__u8 bind_enforce;
	__u8 bind_default_block;
	__u8 unix_enabled;
	__u8 unix_enforce;
	__u8 unix_default_block;
	__u8 sockopt_enabled;
	__u8 sockopt_enforce;
	__u8 sockopt_default_block;
	__u32 policy_generation;
	__u32 _pad;
};

struct daemon_process_identity {
	__u32 tgid;
	__u32 _pad;
	__u64 start_ticks;
};

struct policy_guard {
	struct settings cfg;
	__u64 *readers;
};

struct policy_snapshot {
	__u8 block_enabled;
	__u8 block_all_domains;
	__u8 block_all_resolvers;
	__u8 allow_suffix_rules_enabled;
	__u8 block_suffix_rules_enabled;
	__u8 policy_mask;
};

struct rule_name_key {
	__u8 policy_slot;
	__u8 _pad[3];
	__u32 rule_id;
};

struct rule_name_value {
	char name[MAX_POLICY_RULE_ID_LEN + 1];
};

struct dns_parse_result {
	struct domain_key key;
	__u16 qname_length;
	__u8 allow_suffix_match;
	__u8 block_suffix_match;
	__u8 _pad[4];
};

struct socket_info_key {
	__u32 pid;
	__u16 port;
	__u8 family;
	__u8 protocol;
	__u8 addr[16];
};

struct socket_info_value {
	__u64 process_start_time;
	__u64 cgroup_id;
	__u32 uid;
	char comm[16];
	__u8 hook;
	__u8 family;
	__u8 protocol;
	__u8 _pad;
};

struct listener_info_key {
	__u16 port;
	__u8 family;
	__u8 protocol;
	__u8 addr[16];
};

struct listener_info_value {
	__u64 process_start_time;
	__u64 cgroup_id;
	__u32 pid;
	__u32 uid;
	char comm[16];
};

struct connection_dedupe_key {
	__u32 pid;
	__u16 port;
	__u16 local_port;
	__u8 family;
	__u8 protocol;
	__u8 direction;
	__u8 _pad;
	__u8 addr[16];
	__u8 local_addr[16];
};

struct connection_dedupe_value {
	__u64 last_seen_ns;
};

struct connection_event_params {
	__u8 direction;
	__u8 family;
	__u8 protocol;
	__u8 hook;
	__u8 attribution;
	__u16 port;
	__u16 local_port;
	__u8 addr[16];
	__u8 local_addr[16];
};

struct egress_lookup {
	__u32 uid;
	__u64 cgroup_id;
	__u16 port;
	__u8 policy_slot;
	__u8 protocol;
	__u8 addr[16];
};

struct event {
	__u64 timestamp_ns;
	__u32 kind;
	__u32 pid;
	char comm[16];
	char domain[MAX_DOMAIN_LEN + 1];
	char filename[MAX_FILENAME_LEN];
	__u64 process_start_time;
	__u8 transport;
	__u8 family;
	__u8 socket_protocol;
	__u8 attribution;
	__u8 socket_hook;
	__u8 direction;
	__u16 port;
	__u16 local_port;
	__u32 file_flags;
	__u32 file_mode;
	__u32 kernel_uid;
	__u32 event_source;
	__u32 kernel_feature_set;
	__u32 uid_source;
	__u32 rule_id;
	__u64 cgroup_id;
	__u64 socket_cookie;
	__u8 addr[16];
	__u8 local_addr[16];
};

struct dns_header {
	__be16 id;
	__be16 flags;
	__be16 qdcount;
	__be16 ancount;
	__be16 nscount;
	__be16 arcount;
};

struct trace_event_raw_sys_enter {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long id;
	unsigned long args[6];
};

struct traceguard_open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

struct ipv6_ext_header {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct ipv6_frag_header {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Set by userspace at load time; 0 disables connection event deduplication. */
volatile const __u64 connection_dedupe_window_ns = 60000000000ULL;

/* Indexed by event kind; counts events lost because the ring buffer was full. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EVENT_KIND_MAX + 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_drops SEC(".maps");

static __always_inline struct event *reserve_event(__u32 kind)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	__u64 *drops;

	if (!event) {
		drops = bpf_map_lookup_elem(&ringbuf_drops, &kind);
		if (drops) {
			__sync_fetch_and_add(drops, 1);
		}
	}
	return event;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct domain_key);
	__type(value, __u8);
} blocklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct domain_key);
	__type(value, __u8);
} allowlist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct domain_suffix_key);
	__type(value, __u8);
} allow_suffixes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct domain_suffix_key);
	__type(value, __u8);
} block_suffixes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct settings);
} settings SEC(".maps");

/* Updating an existing hash entry replaces the immutable selector value under
 * RCU. Each lookup therefore observes one complete generation:slot snapshot;
 * no in-place array-value copy is part of the policy publication boundary.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} policy_selector SEC(".maps");

/* This identity also changes across daemon restarts, so publish it through an
 * RCU-replaced hash entry rather than rewriting an array value in place.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct daemon_process_identity);
} daemon_identity SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct rule_name_key);
	__type(value, struct rule_name_value);
} rule_names SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} policy_readers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_parse_result);
} dns_scratch SEC(".maps");

/* Twice the copied size, so each argument read may use all the remaining
 * space without the verifier having to relate offset and length.
 */
struct exec_argv_scratch {
	char buf[2 * EXEC_ARGV_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_argv_scratch);
} exec_argv_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SOCKET_INFO_MAX_ENTRIES);
	__type(key, struct socket_info_key);
	__type(value, struct socket_info_value);
} socket_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, LISTENER_INFO_MAX_ENTRIES);
	__type(key, struct listener_info_key);
	__type(value, struct listener_info_value);
} listener_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CONNECTION_DEDUPE_MAX_ENTRIES);
	__type(key, struct connection_dedupe_key);
	__type(value, struct connection_dedupe_value);
} connection_dedupe SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint4_key);
	__type(value, __u8);
} endpoint4_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint4_key);
	__type(value, __u8);
} endpoint4_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint4_cidr_key);
	__type(value, __u8);
} endpoint4_cidr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint4_cidr_key);
	__type(value, __u8);
} endpoint4_cidr_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint6_key);
	__type(value, __u8);
} endpoint6_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint6_key);
	__type(value, __u8);
} endpoint6_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint6_cidr_key);
	__type(value, __u8);
} endpoint6_cidr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct endpoint6_cidr_key);
	__type(value, __u8);
} endpoint6_cidr_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct egress4_key);
	__type(value, __u32);
} egress4_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct egress4_key);
	__type(value, __u32);
} egress4_block_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct egress6_key);
	__type(value, __u32);
} egress6_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct egress6_key);
	__type(value, __u32);
} egress6_block_rules SEC(".maps");

#define PATH_POLICY_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__uint(max_entries, POLICY_MAP_MAX_ENTRIES); \
		__type(key, struct path_lpm_key); \
		__type(value, __u32); \
	} name SEC(".maps")

PATH_POLICY_MAP(exec_allow_paths);
PATH_POLICY_MAP(exec_block_paths);
PATH_POLICY_MAP(file_allow_paths);
PATH_POLICY_MAP(file_block_paths);
PATH_POLICY_MAP(unix_allow_paths);
PATH_POLICY_MAP(unix_block_paths);

#define BIND4_POLICY_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__uint(max_entries, POLICY_MAP_MAX_ENTRIES); \
		__type(key, struct egress4_key); \
		__type(value, __u32); \
	} name SEC(".maps")

#define BIND6_POLICY_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE); \
		__uint(map_flags, BPF_F_NO_PREALLOC); \
		__uint(max_entries, POLICY_MAP_MAX_ENTRIES); \
		__type(key, struct egress6_key); \
		__type(value, __u32); \
	} name SEC(".maps")

BIND4_POLICY_MAP(bind4_allow_rules);
BIND4_POLICY_MAP(bind4_block_rules);
BIND6_POLICY_MAP(bind6_allow_rules);
BIND6_POLICY_MAP(bind6_block_rules);

#define SOCKOPT_POLICY_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_HASH); \
		__uint(max_entries, POLICY_MAP_MAX_ENTRIES); \
		__type(key, struct sockopt_key); \
		__type(value, __u32); \
	} name SEC(".maps")

SOCKOPT_POLICY_MAP(sockopt_allow);
SOCKOPT_POLICY_MAP(sockopt_block);

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lsm_path_value);
} lsm_path_buf SEC(".maps");

#define PATH_DOMAIN_EXEC 1
#define PATH_DOMAIN_FILE 2
#define PATH_DOMAIN_UNIX 3

static __always_inline void init_event(struct event *event, __u32 kind, __u8 transport, __u32 source);

static __always_inline int lsm_mac_verdict(__u8 deny)
{
	return deny ? -TRACEGUARD_EPERM : 0;
}

static __always_inline int cgroup_verdict(__u8 deny)
{
	return deny ? 0 : 1;
}

static __always_inline int identity_has_uid(__u8 kind)
{
	return kind == EGRESS_IDENTITY_UID || kind == EGRESS_IDENTITY_UID_CGROUP ||
		kind == EGRESS_IDENTITY_UID_CGROUP_ANCESTOR;
}

static __always_inline int identity_has_cgroup(__u8 kind)
{
	return kind == EGRESS_IDENTITY_CGROUP || kind == EGRESS_IDENTITY_UID_CGROUP ||
		kind == EGRESS_IDENTITY_CGROUP_ANCESTOR || kind == EGRESS_IDENTITY_UID_CGROUP_ANCESTOR;
}

/* Pin a policy slot while it is being read. Settings are immutable while their
 * slot is active or has readers. Rechecking the RCU-replaced selector closes
 * the pre-pin race, while the reader counter prevents reuse of the old slot.
 */
static __always_inline int acquire_policy_guard(struct policy_guard *guard)
{
	__u32 zero = 0;

#pragma unroll
	for (int attempt = 0; attempt < 4; attempt++) {
		__u64 *selector = bpf_map_lookup_elem(&policy_selector, &zero);
		__u64 snapshot;
		__u32 slot;
		__u32 generation;
		__u64 *readers;
		struct settings *cfg;

		if (!selector) {
			return 0;
		}
		snapshot = *selector;
		slot = (__u32)snapshot;
		generation = (__u32)(snapshot >> 32);
		if (slot > 1) {
			return 0;
		}
		readers = bpf_map_lookup_elem(&policy_readers, &slot);
		if (!readers) {
			return 0;
		}
		__sync_fetch_and_add(readers, 1);
		selector = bpf_map_lookup_elem(&policy_selector, &zero);
		if (selector && *selector == snapshot) {
			cfg = bpf_map_lookup_elem(&settings, &slot);
			if (!cfg || cfg->active_policy_slot != slot || cfg->policy_generation != generation) {
				__sync_fetch_and_sub(readers, 1);
				return 0;
			}
			__builtin_memcpy(&guard->cfg, cfg, sizeof(guard->cfg));
			guard->readers = readers;
			return 1;
		}
		__sync_fetch_and_sub(readers, 1);
	}
	return 0;
}

static __always_inline void release_policy_guard(struct policy_guard *guard)
{
	if (guard->readers) {
		__sync_fetch_and_sub(guard->readers, 1);
		guard->readers = 0;
	}
}

static __always_inline void set_event_rule(struct event *event, __u8 policy_slot, __u32 rule_id)
{
	struct rule_name_key key = {
		.policy_slot = policy_slot,
		.rule_id = rule_id,
	};
	struct rule_name_value *value;

	event->rule_id = rule_id;
	if (!rule_id) {
		return;
	}
	value = bpf_map_lookup_elem(&rule_names, &key);
	if (value) {
		__builtin_memcpy(event->domain, value->name, sizeof(value->name));
	}
}

static __always_inline __u32 lookup_path_map(__u8 domain, __u8 allow, struct path_lpm_key *key)
{
	__u32 *rule = 0;

	if (domain == PATH_DOMAIN_EXEC) {
		rule = allow ? bpf_map_lookup_elem(&exec_allow_paths, key) : bpf_map_lookup_elem(&exec_block_paths, key);
	} else if (domain == PATH_DOMAIN_FILE) {
		rule = allow ? bpf_map_lookup_elem(&file_allow_paths, key) : bpf_map_lookup_elem(&file_block_paths, key);
	} else if (domain == PATH_DOMAIN_UNIX) {
		rule = allow ? bpf_map_lookup_elem(&unix_allow_paths, key) : bpf_map_lookup_elem(&unix_block_paths, key);
	}
	return rule ? *rule : 0;
}

struct path_lookup_context {
	const char *path;
	__u64 cgroup_id;
	__u32 uid;
	__u32 path_len;
	__u8 domain;
	__u8 policy_slot;
	__u8 access_or_op;
};

static __always_inline __u32 lookup_path_kind(const struct path_lookup_context *ctx, __u8 allow,
	__u8 kind, __u64 cgroup_id)
{
	struct path_lpm_key key = {0};
	/* 64-bit so the bounds check below applies to the size register itself. */
	__u64 copy_len = (__u64)ctx->path_len + 1;
	__u32 rule;

	if (copy_len > PATH_LPM_MAX || copy_len == 0) {
		copy_len = PATH_LPM_MAX;
	}
	barrier_var(copy_len);
	if (copy_len > PATH_LPM_MAX) {
		return 0;
	}
	key.prefixlen = (__u32)((PATH_LPM_FIXED + copy_len) * 8);
	key.data[0] = ctx->policy_slot;
	key.data[1] = kind;
	if (identity_has_uid(kind)) {
		__builtin_memcpy(&key.data[2], &ctx->uid, sizeof(ctx->uid));
	}
	if (identity_has_cgroup(kind)) {
		__builtin_memcpy(&key.data[6], &cgroup_id, sizeof(cgroup_id));
	}
	key.data[14] = ctx->access_or_op;
	if (bpf_probe_read_kernel(&key.data[PATH_LPM_FIXED], (__u32)copy_len, ctx->path) < 0) {
		return 0;
	}
	rule = lookup_path_map(ctx->domain, allow, &key);
	if (rule || ctx->access_or_op == 0) {
		return rule;
	}
	key.data[14] = 0;
	return lookup_path_map(ctx->domain, allow, &key);
}

struct path_ancestor_context {
	const struct path_lookup_context *lookup;
	__u32 rule;
	__u8 allow;
	__u8 kind;
};

static long lookup_path_ancestor(__u32 level, void *data)
{
	struct path_ancestor_context *ctx = data;
	const struct path_lookup_context *lookup = ctx->lookup;
	__u64 cgroup_id = bpf_get_current_ancestor_cgroup_id(level);

	if (!cgroup_id) {
		return 1;
	}
	ctx->rule = lookup_path_kind(lookup, ctx->allow, ctx->kind, cgroup_id);
	return ctx->rule ? 1 : 0;
}

static __always_inline __u32 lookup_path_ancestor_policy(const struct path_lookup_context *lookup,
	__u8 allow, __u8 kind)
{
	struct path_ancestor_context ctx = {
		.lookup = lookup,
		.allow = allow,
		.kind = kind,
	};

	if (bpf_loop(MAX_CGROUP_ANCESTORS, lookup_path_ancestor, &ctx, 0) < 0) {
		return 0;
	}
	return ctx.rule;
}

static __noinline __u32 lookup_path_policy(const struct path_lookup_context *ctx, __u8 allow)
{
	__u32 rule;

	rule = lookup_path_kind(ctx, allow, EGRESS_IDENTITY_UID_CGROUP, ctx->cgroup_id);
	if (rule) {
		return rule;
	}
	rule = lookup_path_ancestor_policy(ctx, allow, EGRESS_IDENTITY_UID_CGROUP_ANCESTOR);
	if (rule) {
		return rule;
	}
	rule = lookup_path_kind(ctx, allow, EGRESS_IDENTITY_UID, ctx->cgroup_id);
	if (rule) {
		return rule;
	}
	rule = lookup_path_kind(ctx, allow, EGRESS_IDENTITY_CGROUP, ctx->cgroup_id);
	if (rule) {
		return rule;
	}
	rule = lookup_path_ancestor_policy(ctx, allow, EGRESS_IDENTITY_CGROUP_ANCESTOR);
	if (rule) {
		return rule;
	}
	return lookup_path_kind(ctx, allow, EGRESS_IDENTITY_GLOBAL, ctx->cgroup_id);
}

static __always_inline int path_policy_denies(const struct path_lookup_context *ctx, __u8 default_block, __u32 *rule_id)
{
	if (lookup_path_policy(ctx, 1)) {
		return 0;
	}
	*rule_id = lookup_path_policy(ctx, 0);
	return *rule_id != 0 || default_block;
}

struct path_decision_context {
	const char *path;
	__u64 cgroup_id;
	__u32 uid;
	__u32 rule_id;
	__u32 path_len;
	__u32 file_flags;
	__u8 policy_slot;
	__u8 family;
	__u8 hook;
	__u8 operation;
	__u8 path_truncated;
};

static __always_inline void emit_path_decision(__u32 kind, __u32 source,
	const struct path_decision_context *decision)
{
	struct event *event = reserve_event(kind);
	__u64 copy_len = (__u64)decision->path_len + 1;

	if (!event) {
		return;
	}
	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, 0, source);
	event->kernel_uid = decision->uid;
	event->uid_source = UID_SOURCE_KERNEL;
	event->cgroup_id = decision->cgroup_id;
	set_event_rule(event, decision->policy_slot, decision->rule_id);
	event->file_flags = decision->operation ? decision->operation : decision->file_flags;
	event->family = decision->family;
	event->socket_hook = decision->hook;
	if (copy_len > sizeof(event->filename)) {
		copy_len = sizeof(event->filename);
		event->file_mode |= PATH_EVENT_FLAG_TRUNCATED;
	}
	if (decision->path_truncated) {
		event->file_mode |= PATH_EVENT_FLAG_TRUNCATED;
	}
	/* copy_len is at least 1, so only the upper bound needs checking. */
	barrier_var(copy_len);
	if (decision->path && copy_len <= sizeof(event->filename)) {
		bpf_probe_read_kernel(event->filename, (__u32)copy_len, decision->path);
	}
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_truncated_lsm_decision(__u32 kind, __u32 uid, __u64 cgroup_id, __u32 file_flags)
{
	static const char truncated[] = "truncated";
	const struct path_decision_context decision = {
		.path = truncated,
		.cgroup_id = cgroup_id,
		.uid = uid,
		.path_len = sizeof(truncated) - 1,
		.file_flags = file_flags,
		.path_truncated = 1,
	};

	emit_path_decision(kind, EVENT_SOURCE_LSM_MAC, &decision);
}

static __noinline int evaluate_lsm_path(struct file *file, const struct settings *cfg, __u8 domain,
	__u8 access, __u32 file_flags)
{
	void *task;
	struct lsm_path_value *storage;
	__u32 uid = (__u32)bpf_get_current_uid_gid();
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u32 rule_id = 0;
	__u32 kind;
	__u8 enforce = domain == PATH_DOMAIN_EXEC ? cfg->exec_enforce : cfg->file_enforce;
	__u8 default_block = domain == PATH_DOMAIN_EXEC ? cfg->exec_default_block : cfg->file_default_block;
	struct path_lookup_context lookup = {
		.uid = uid,
		.cgroup_id = cgroup_id,
		.domain = domain,
		.policy_slot = cfg->active_policy_slot,
		.access_or_op = access,
	};
	long length;
	int denied;

	if (!file) {
		return 0;
	}
	task = bpf_get_current_task_btf();
	storage = bpf_task_storage_get(&lsm_path_buf, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage) {
		return 0;
	}
	length = bpf_d_path(&file->f_path, storage->path, sizeof(storage->path));
	if (length == -TRACEGUARD_ENAMETOOLONG) {
		kind = domain == PATH_DOMAIN_EXEC
			? (enforce ? EVENT_EXEC_BLOCKED : EVENT_EXEC_WOULD_BLOCK)
			: (enforce ? EVENT_FILE_BLOCKED : EVENT_FILE_WOULD_BLOCK);
		emit_truncated_lsm_decision(kind, uid, cgroup_id, file_flags);
		return lsm_mac_verdict(enforce);
	}
	if (length <= 0) {
		return 0;
	}
	lookup.path = storage->path;
	lookup.path_len = (__u32)length - 1;
	if (access == FILE_ACCESS_READ_WRITE) {
		lookup.access_or_op = FILE_ACCESS_READ;
	}
	denied = path_policy_denies(&lookup, default_block, &rule_id);
	if (!denied && access == FILE_ACCESS_READ_WRITE) {
		lookup.access_or_op = FILE_ACCESS_WRITE;
		denied = path_policy_denies(&lookup, default_block, &rule_id);
	}
	if (!denied) {
		return 0;
	}
	kind = domain == PATH_DOMAIN_EXEC
		? (enforce ? EVENT_EXEC_BLOCKED : EVENT_EXEC_WOULD_BLOCK)
		: (enforce ? EVENT_FILE_BLOCKED : EVENT_FILE_WOULD_BLOCK);
	const struct path_decision_context decision = {
		.path = storage->path,
		.cgroup_id = cgroup_id,
		.uid = uid,
		.rule_id = rule_id,
		.path_len = (__u32)length - 1,
		.file_flags = file_flags,
		.policy_slot = cfg->active_policy_slot,
	};
	emit_path_decision(kind, EVENT_SOURCE_LSM_MAC, &decision);
	return lsm_mac_verdict(enforce);
}

static __always_inline __u32 active_kernel_feature_set(void)
{
#if TRACEGUARD_LINUX71_TELEMETRY
	return KERNEL_FEATURE_SET_LINUX71;
#else
	return KERNEL_FEATURE_SET_LEGACY;
#endif
}

static __always_inline __u64 current_process_start_time(void)
{
	struct task_struct *task = bpf_get_current_task();
	struct task_struct *group_leader = 0;
	__u64 start_boottime = 0;

	if (!task || bpf_probe_read_kernel(&group_leader, sizeof(group_leader),
		__builtin_preserve_access_index(&task->group_leader)) < 0 || !group_leader ||
		bpf_probe_read_kernel(&start_boottime, sizeof(start_boottime),
			__builtin_preserve_access_index(&group_leader->start_boottime)) < 0) {
		return 0;
	}
	return start_boottime / NSEC_PER_USER_HZ_TICK;
}

static __always_inline int daemon_is_exempt(const struct settings *cfg)
{
	__u32 zero = 0;
	struct daemon_process_identity *expected;
	__u32 tgid;
	__u64 start_time;

	(void)cfg;
	expected = bpf_map_lookup_elem(&daemon_identity, &zero);
	if (!expected || !expected->tgid || !expected->start_ticks) {
		return 0;
	}
	tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	start_time = current_process_start_time();
	return tgid == expected->tgid && start_time == expected->start_ticks;
}

static __always_inline void init_event_base(struct event *event, __u32 kind, __u8 transport, __u32 source)
{
	event->timestamp_ns = bpf_ktime_get_boot_ns();
	event->kind = kind;
	event->transport = transport;
	event->event_source = source;
	event->kernel_feature_set = active_kernel_feature_set();
}

static __always_inline void init_event(struct event *event, __u32 kind, __u8 transport, __u32 source)
{
	init_event_base(event, kind, transport, source);
	event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	event->process_start_time = current_process_start_time();
	event->kernel_uid = (__u32)bpf_get_current_uid_gid();
	event->uid_source = UID_SOURCE_KERNEL;
	event->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline void set_event_socket_meta(struct event *event, __u8 family, __u8 protocol, __u8 hook, __u8 attribution)
{
	event->family = family;
	event->socket_protocol = protocol;
	event->socket_hook = hook;
	event->attribution = attribution;
}

static __always_inline __u8 transport_for_socket_protocol(__u8 protocol)
{
	if (protocol == SOCKET_PROTOCOL_TCP) {
		return TRANSPORT_TCP;
	}
	if (protocol == SOCKET_PROTOCOL_UDP) {
		return TRANSPORT_UDP;
	}
	return 0;
}

static __always_inline void copy_socket_addr(__u8 dst[16], __u8 family, const void *addr)
{
	__builtin_memset(dst, 0, 16);
	if (!addr) {
		return;
	}
	if (family == FAMILY_IPV4) {
		__builtin_memcpy(dst, addr, 4);
		return;
	}
	if (family == FAMILY_IPV6) {
		__builtin_memcpy(dst, addr, 16);
	}
}

static __always_inline void cache_socket_info(__u8 family, __u8 protocol, __u16 port, const void *addr, __u8 hook)
{
	struct socket_info_key key = {0};
	struct socket_info_value value = {0};

	key.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	key.port = port;
	key.family = family;
	key.protocol = protocol;
	copy_socket_addr(key.addr, family, addr);

	value.hook = hook;
	value.family = family;
	value.protocol = protocol;
	value.process_start_time = current_process_start_time();
	value.cgroup_id = bpf_get_current_cgroup_id();
	value.uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(value.comm, sizeof(value.comm));
	bpf_map_update_elem(&socket_info, &key, &value, BPF_ANY);
}

static __always_inline void set_event_peer(struct event *event, __u8 family, __u16 port, const void *addr)
{
	event->port = port;
	copy_socket_addr(event->addr, family, addr);
}

static __always_inline void set_event_local(struct event *event, __u8 family, __u16 port, const void *addr)
{
	event->local_port = port;
	copy_socket_addr(event->local_addr, family, addr);
}

static __always_inline void apply_socket_info(struct event *event, __u8 family, __u8 protocol, __u16 port, const void *addr)
{
	struct socket_info_key key = {0};
	struct socket_info_value *value;

	key.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	key.port = port;
	key.family = family;
	key.protocol = protocol;
	copy_socket_addr(key.addr, family, addr);

	set_event_socket_meta(event, family, protocol, SOCKET_HOOK_CGROUP_SKB, ATTRIBUTION_KERNEL_SKB);

	value = bpf_map_lookup_elem(&socket_info, &key);
	if (value && value->process_start_time && value->process_start_time == current_process_start_time()) {
		event->pid = key.pid;
		__builtin_memcpy(event->comm, value->comm, sizeof(event->comm));
		event->process_start_time = value->process_start_time;
		event->kernel_uid = value->uid;
		event->uid_source = UID_SOURCE_SOCKET_CACHE;
		event->cgroup_id = value->cgroup_id;
		event->socket_hook = value->hook;
		event->attribution = value->hook == SOCKET_HOOK_CGROUP_CONNECT4 || value->hook == SOCKET_HOOK_CGROUP_CONNECT6
			? ATTRIBUTION_KERNEL_CONNECT
			: ATTRIBUTION_KERNEL_SENDMSG;
		return;
	}

#if !TRACEGUARD_DNS_NO_CURRENT_COMM
	bpf_get_current_comm(event->comm, sizeof(event->comm));
#endif
}

static __always_inline void cache_listener_info(__u8 family, __u8 protocol, __u16 port, const void *addr)
{
	struct listener_info_key key = {0};
	struct listener_info_value value = {0};

	key.port = port;
	key.family = family;
	key.protocol = protocol;
	copy_socket_addr(key.addr, family, addr);

	value.process_start_time = current_process_start_time();
	value.cgroup_id = bpf_get_current_cgroup_id();
	value.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	value.uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(value.comm, sizeof(value.comm));
	bpf_map_update_elem(&listener_info, &key, &value, BPF_ANY);
}

static __always_inline struct listener_info_value *lookup_listener_info(__u8 family, __u8 protocol, __u16 port, const void *addr)
{
	struct listener_info_key key = {0};
	struct listener_info_value *value;

	key.port = port;
	key.family = family;
	key.protocol = protocol;
	copy_socket_addr(key.addr, family, addr);

	value = bpf_map_lookup_elem(&listener_info, &key);
	if (value) {
		return value;
	}

	__builtin_memset(key.addr, 0, sizeof(key.addr));
	return bpf_map_lookup_elem(&listener_info, &key);
}

static __always_inline int should_emit_connection_event(const struct connection_event_params *params, __u32 pid)
{
	struct connection_dedupe_key key = {0};
	struct connection_dedupe_value value = {0};
	struct connection_dedupe_value *existing;
	__u64 window = connection_dedupe_window_ns;
	__u64 now = bpf_ktime_get_ns();

	if (!window) {
		return 1;
	}
	key.pid = pid;
	key.port = params->port;
	key.local_port = params->local_port;
	key.family = params->family;
	key.protocol = params->protocol;
	key.direction = params->direction;
	copy_socket_addr(key.addr, params->family, params->addr);
	copy_socket_addr(key.local_addr, params->family, params->local_addr);

	existing = bpf_map_lookup_elem(&connection_dedupe, &key);
	if (existing && now >= existing->last_seen_ns && now - existing->last_seen_ns < window) {
		return 0;
	}

	value.last_seen_ns = now;
	bpf_map_update_elem(&connection_dedupe, &key, &value, BPF_ANY);
	return 1;
}

static __always_inline int emit_connection_event_identity(const struct connection_event_params *params,
	const struct listener_info_value *identity, __u64 socket_cookie)
{
	struct event *event;
	__u32 pid = identity ? identity->pid : 0;

	if (!should_emit_connection_event(params, pid)) {
		return 1;
	}

	event = reserve_event(EVENT_CONNECTION);
	if (!event) {
		return 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, EVENT_CONNECTION, transport_for_socket_protocol(params->protocol), EVENT_SOURCE_CGROUP_SKB);
	event->pid = pid;
	event->process_start_time = identity ? identity->process_start_time : 0;
	event->kernel_uid = identity ? identity->uid : 0;
	event->uid_source = identity ? UID_SOURCE_SOCKET_CACHE : UID_SOURCE_NONE;
	event->cgroup_id = identity ? identity->cgroup_id : 0;
	event->socket_cookie = socket_cookie;
	if (identity) {
		__builtin_memcpy(event->comm, identity->comm, sizeof(event->comm));
	}
	set_event_socket_meta(event, params->family, params->protocol, params->hook, params->attribution);
	event->direction = params->direction;
	set_event_peer(event, params->family, params->port, params->addr);
	set_event_local(event, params->family, params->local_port, params->local_addr);
	bpf_ringbuf_submit(event, 0);
	return 1;
}

static __always_inline int emit_connection_event_current(const struct connection_event_params *params, __u32 source, __u64 socket_cookie)
{
	struct event *event;
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

	if (!should_emit_connection_event(params, pid)) {
		return 1;
	}

	event = reserve_event(EVENT_CONNECTION);
	if (!event) {
		return 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, EVENT_CONNECTION, transport_for_socket_protocol(params->protocol), source);
	event->socket_cookie = socket_cookie;
	set_event_socket_meta(event, params->family, params->protocol, params->hook, params->attribution);
	event->direction = params->direction;
	set_event_peer(event, params->family, params->port, params->addr);
	set_event_local(event, params->family, params->local_port, params->local_addr);
	bpf_ringbuf_submit(event, 0);
	return 1;
}

static __always_inline void encode_egress_identity(__u8 *data, __u8 policy_slot, __u8 kind, __u32 uid, __u64 cgroup_id, __u8 protocol, __u16 port)
{
	__be16 network_port = bpf_htons(port);

	data[0] = policy_slot;
	data[1] = kind;
	__builtin_memcpy(&data[2], &uid, sizeof(uid));
	__builtin_memcpy(&data[6], &cgroup_id, sizeof(cgroup_id));
	data[14] = protocol;
	__builtin_memcpy(&data[15], &network_port, sizeof(network_port));
}

static __always_inline __u32 lookup_egress4_kind(__u8 allow, __u8 kind, const struct egress_lookup *lookup)
{
	struct egress4_key key = {
		.prefixlen = sizeof(key.data) * 8,
	};
	__u32 *rule;
	__u32 uid = identity_has_uid(kind) ? lookup->uid : 0;
	__u64 cgroup_id = identity_has_cgroup(kind) ? lookup->cgroup_id : 0;

	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, lookup->port);
	__builtin_memcpy(&key.data[EGRESS_IDENTITY_BYTES], lookup->addr, 4);
	if (allow) {
		rule = bpf_map_lookup_elem(&egress4_allow_rules, &key);
	} else {
		rule = bpf_map_lookup_elem(&egress4_block_rules, &key);
	}
	if (rule) {
		return *rule;
	}
	if (lookup->port == 0) {
		return 0;
	}
	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, 0);
	if (allow) {
		rule = bpf_map_lookup_elem(&egress4_allow_rules, &key);
	} else {
		rule = bpf_map_lookup_elem(&egress4_block_rules, &key);
	}
	return rule ? *rule : 0;
}

static __always_inline __u32 lookup_egress6_kind(__u8 allow, __u8 kind, const struct egress_lookup *lookup)
{
	struct egress6_key key = {
		.prefixlen = sizeof(key.data) * 8,
	};
	__u32 *rule;
	__u32 uid = identity_has_uid(kind) ? lookup->uid : 0;
	__u64 cgroup_id = identity_has_cgroup(kind) ? lookup->cgroup_id : 0;

	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, lookup->port);
	__builtin_memcpy(&key.data[EGRESS_IDENTITY_BYTES], lookup->addr, 16);
	if (allow) {
		rule = bpf_map_lookup_elem(&egress6_allow_rules, &key);
	} else {
		rule = bpf_map_lookup_elem(&egress6_block_rules, &key);
	}
	if (rule) {
		return *rule;
	}
	if (lookup->port == 0) {
		return 0;
	}
	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, 0);
	if (allow) {
		rule = bpf_map_lookup_elem(&egress6_allow_rules, &key);
	} else {
		rule = bpf_map_lookup_elem(&egress6_block_rules, &key);
	}
	return rule ? *rule : 0;
}

struct egress_ancestor_context {
	struct egress_lookup lookup;
	__u32 rule;
	__u8 allow;
	__u8 kind;
	__u8 family;
};

static long lookup_egress_ancestor(__u32 level, void *data)
{
	struct egress_ancestor_context *ctx = data;
	__u64 cgroup_id = bpf_get_current_ancestor_cgroup_id(level);

	if (!cgroup_id) {
		return 1;
	}
	ctx->lookup.cgroup_id = cgroup_id;
	ctx->rule = ctx->family == FAMILY_IPV4
		? lookup_egress4_kind(ctx->allow, ctx->kind, &ctx->lookup)
		: lookup_egress6_kind(ctx->allow, ctx->kind, &ctx->lookup);
	return ctx->rule ? 1 : 0;
}

static __always_inline __u32 lookup_egress_ancestor_policy(__u8 allow, __u8 kind, __u8 family,
	const struct egress_lookup *lookup)
{
	struct egress_ancestor_context ctx = {
		.lookup = *lookup,
		.allow = allow,
		.kind = kind,
		.family = family,
	};

	if (bpf_loop(MAX_CGROUP_ANCESTORS, lookup_egress_ancestor, &ctx, 0) < 0) {
		return 0;
	}
	return ctx.rule;
}

static __always_inline __u32 lookup_egress4(__u8 allow, const struct egress_lookup *lookup)
{
	__u32 rule;

	rule = lookup_egress4_kind(allow, EGRESS_IDENTITY_UID_CGROUP, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress_ancestor_policy(allow, EGRESS_IDENTITY_UID_CGROUP_ANCESTOR, FAMILY_IPV4, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress4_kind(allow, EGRESS_IDENTITY_UID, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress4_kind(allow, EGRESS_IDENTITY_CGROUP, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress_ancestor_policy(allow, EGRESS_IDENTITY_CGROUP_ANCESTOR, FAMILY_IPV4, lookup);
	if (rule) {
		return rule;
	}
	return lookup_egress4_kind(allow, EGRESS_IDENTITY_GLOBAL, lookup);
}

static __always_inline __u32 lookup_egress6(__u8 allow, const struct egress_lookup *lookup)
{
	__u32 rule;

	rule = lookup_egress6_kind(allow, EGRESS_IDENTITY_UID_CGROUP, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress_ancestor_policy(allow, EGRESS_IDENTITY_UID_CGROUP_ANCESTOR, FAMILY_IPV6, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress6_kind(allow, EGRESS_IDENTITY_UID, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress6_kind(allow, EGRESS_IDENTITY_CGROUP, lookup);
	if (rule) {
		return rule;
	}
	rule = lookup_egress_ancestor_policy(allow, EGRESS_IDENTITY_CGROUP_ANCESTOR, FAMILY_IPV6, lookup);
	if (rule) {
		return rule;
	}
	return lookup_egress6_kind(allow, EGRESS_IDENTITY_GLOBAL, lookup);
}

static __always_inline int emit_egress_decision(struct bpf_sock_addr *ctx, const struct connection_event_params *params, const struct settings *cfg, __u32 rule_id, const struct egress_lookup *lookup)
{
	__u32 kind = cfg->egress_enforce ? EVENT_EGRESS_BLOCKED : EVENT_EGRESS_WOULD_BLOCK;
	struct event *event = reserve_event(kind);

	if (!event) {
		return cfg->egress_enforce ? 0 : 1;
	}
	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, transport_for_socket_protocol(params->protocol), EVENT_SOURCE_CGROUP_SOCK_ADDR);
	event->kernel_uid = lookup->uid;
	event->uid_source = UID_SOURCE_KERNEL;
	event->cgroup_id = lookup->cgroup_id;
	set_event_rule(event, cfg->active_policy_slot, rule_id);
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
	event->socket_cookie = bpf_get_socket_cookie(ctx);
#else
	(void)ctx;
#endif
	set_event_socket_meta(event, params->family, params->protocol, params->hook, params->attribution);
	event->direction = params->direction;
	set_event_peer(event, params->family, params->port, params->addr);
	set_event_local(event, params->family, params->local_port, params->local_addr);
	bpf_ringbuf_submit(event, 0);
	return cfg->egress_enforce ? 0 : 1;
}

static __always_inline int evaluate_egress4(struct bpf_sock_addr *ctx, const struct connection_event_params *params, __u32 addr)
{
	struct policy_guard guard = {0};
	const struct settings *cfg;
	struct egress_lookup lookup = {0};
	__u32 rule;
	int verdict;

	if (!acquire_policy_guard(&guard)) {
		return 1;
	}
	cfg = &guard.cfg;
	if (!cfg->egress_enabled) {
		release_policy_guard(&guard);
		return 1;
	}
	lookup.uid = (__u32)bpf_get_current_uid_gid();
	lookup.cgroup_id = bpf_get_current_cgroup_id();
	lookup.policy_slot = cfg->active_policy_slot;
	lookup.protocol = params->protocol;
	lookup.port = params->port;
	__builtin_memcpy(lookup.addr, &addr, sizeof(addr));
	if (lookup_egress4(1, &lookup)) {
		release_policy_guard(&guard);
		return 1;
	}
	rule = lookup_egress4(0, &lookup);
	if (!rule && !cfg->egress_default_block) {
		release_policy_guard(&guard);
		return 1;
	}
	verdict = emit_egress_decision(ctx, params, cfg, rule, &lookup);
	release_policy_guard(&guard);
	return verdict;
}

static __always_inline int evaluate_egress6(struct bpf_sock_addr *ctx, const struct connection_event_params *params, const __u8 addr[16])
{
	__u32 mapped_ipv4 = 0;
	struct policy_guard guard = {0};
	const struct settings *cfg;
	struct egress_lookup lookup = {0};
	__u32 rule;
	int verdict;

	if (!addr[0] && !addr[1] && !addr[2] && !addr[3] && !addr[4] && !addr[5] &&
	    !addr[6] && !addr[7] && !addr[8] && !addr[9] && addr[10] == 0xff && addr[11] == 0xff) {
		__builtin_memcpy(&mapped_ipv4, &addr[12], sizeof(mapped_ipv4));
		return evaluate_egress4(ctx, params, mapped_ipv4);
	}
	if (!acquire_policy_guard(&guard)) {
		return 1;
	}
	cfg = &guard.cfg;
	if (!cfg->egress_enabled) {
		release_policy_guard(&guard);
		return 1;
	}
	lookup.uid = (__u32)bpf_get_current_uid_gid();
	lookup.cgroup_id = bpf_get_current_cgroup_id();
	lookup.policy_slot = cfg->active_policy_slot;
	lookup.protocol = params->protocol;
	lookup.port = params->port;
	__builtin_memcpy(lookup.addr, addr, sizeof(lookup.addr));
	if (lookup_egress6(1, &lookup)) {
		release_policy_guard(&guard);
		return 1;
	}
	rule = lookup_egress6(0, &lookup);
	if (!rule && !cfg->egress_default_block) {
		release_policy_guard(&guard);
		return 1;
	}
	verdict = emit_egress_decision(ctx, params, cfg, rule, &lookup);
	release_policy_guard(&guard);
	return verdict;
}

static __always_inline __u32 lookup_bind4_kind(__u8 allow, __u8 kind, const struct egress_lookup *lookup)
{
	struct egress4_key key = {.prefixlen = sizeof(key.data) * 8};
	__u32 uid = identity_has_uid(kind) ? lookup->uid : 0;
	__u64 cgroup_id = identity_has_cgroup(kind) ? lookup->cgroup_id : 0;
	__u32 *rule;

	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, lookup->port);
	__builtin_memcpy(&key.data[EGRESS_IDENTITY_BYTES], lookup->addr, 4);
	rule = allow ? bpf_map_lookup_elem(&bind4_allow_rules, &key) : bpf_map_lookup_elem(&bind4_block_rules, &key);
	if (rule || lookup->port == 0) {
		return rule ? *rule : 0;
	}
	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, 0);
	rule = allow ? bpf_map_lookup_elem(&bind4_allow_rules, &key) : bpf_map_lookup_elem(&bind4_block_rules, &key);
	return rule ? *rule : 0;
}

static __always_inline __u32 lookup_bind6_kind(__u8 allow, __u8 kind, const struct egress_lookup *lookup)
{
	struct egress6_key key = {.prefixlen = sizeof(key.data) * 8};
	__u32 uid = identity_has_uid(kind) ? lookup->uid : 0;
	__u64 cgroup_id = identity_has_cgroup(kind) ? lookup->cgroup_id : 0;
	__u32 *rule;

	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, lookup->port);
	__builtin_memcpy(&key.data[EGRESS_IDENTITY_BYTES], lookup->addr, 16);
	rule = allow ? bpf_map_lookup_elem(&bind6_allow_rules, &key) : bpf_map_lookup_elem(&bind6_block_rules, &key);
	if (rule || lookup->port == 0) {
		return rule ? *rule : 0;
	}
	encode_egress_identity(key.data, lookup->policy_slot, kind, uid, cgroup_id, lookup->protocol, 0);
	rule = allow ? bpf_map_lookup_elem(&bind6_allow_rules, &key) : bpf_map_lookup_elem(&bind6_block_rules, &key);
	return rule ? *rule : 0;
}

struct bind_ancestor_context {
	struct egress_lookup lookup;
	__u32 rule;
	__u8 allow;
	__u8 kind;
	__u8 family;
};

static long lookup_bind_ancestor(__u32 level, void *data)
{
	struct bind_ancestor_context *ctx = data;
	__u64 cgroup_id = bpf_get_current_ancestor_cgroup_id(level);

	if (!cgroup_id) {
		return 1;
	}
	ctx->lookup.cgroup_id = cgroup_id;
	ctx->rule = ctx->family == FAMILY_IPV4
		? lookup_bind4_kind(ctx->allow, ctx->kind, &ctx->lookup)
		: lookup_bind6_kind(ctx->allow, ctx->kind, &ctx->lookup);
	return ctx->rule ? 1 : 0;
}

static __always_inline __u32 lookup_bind_ancestor_policy(__u8 allow, __u8 kind, __u8 family,
	const struct egress_lookup *lookup)
{
	struct bind_ancestor_context ctx = {
		.lookup = *lookup,
		.allow = allow,
		.kind = kind,
		.family = family,
	};

	if (bpf_loop(MAX_CGROUP_ANCESTORS, lookup_bind_ancestor, &ctx, 0) < 0) {
		return 0;
	}
	return ctx.rule;
}

static __always_inline __u32 lookup_bind4(__u8 allow, const struct egress_lookup *lookup)
{
	__u32 rule = lookup_bind4_kind(allow, EGRESS_IDENTITY_UID_CGROUP, lookup);
	if (rule) return rule;
	rule = lookup_bind_ancestor_policy(allow, EGRESS_IDENTITY_UID_CGROUP_ANCESTOR, FAMILY_IPV4, lookup);
	if (rule) return rule;
	rule = lookup_bind4_kind(allow, EGRESS_IDENTITY_UID, lookup);
	if (rule) return rule;
	rule = lookup_bind4_kind(allow, EGRESS_IDENTITY_CGROUP, lookup);
	if (rule) return rule;
	rule = lookup_bind_ancestor_policy(allow, EGRESS_IDENTITY_CGROUP_ANCESTOR, FAMILY_IPV4, lookup);
	if (rule) return rule;
	return lookup_bind4_kind(allow, EGRESS_IDENTITY_GLOBAL, lookup);
}

static __always_inline __u32 lookup_bind6(__u8 allow, const struct egress_lookup *lookup)
{
	__u32 rule = lookup_bind6_kind(allow, EGRESS_IDENTITY_UID_CGROUP, lookup);
	if (rule) return rule;
	rule = lookup_bind_ancestor_policy(allow, EGRESS_IDENTITY_UID_CGROUP_ANCESTOR, FAMILY_IPV6, lookup);
	if (rule) return rule;
	rule = lookup_bind6_kind(allow, EGRESS_IDENTITY_UID, lookup);
	if (rule) return rule;
	rule = lookup_bind6_kind(allow, EGRESS_IDENTITY_CGROUP, lookup);
	if (rule) return rule;
	rule = lookup_bind_ancestor_policy(allow, EGRESS_IDENTITY_CGROUP_ANCESTOR, FAMILY_IPV6, lookup);
	if (rule) return rule;
	return lookup_bind6_kind(allow, EGRESS_IDENTITY_GLOBAL, lookup);
}

static __always_inline int emit_bind_decision(struct bpf_sock_addr *ctx, const struct settings *cfg,
	const struct egress_lookup *lookup, __u32 rule_id, __u16 socket_meta)
{
	struct event *event = reserve_event(cfg->bind_enforce ? EVENT_BIND_BLOCKED : EVENT_BIND_WOULD_BLOCK);
	__u8 family = (__u8)(socket_meta >> 8);
	__u8 hook = (__u8)socket_meta;
	__u8 deny = cfg->bind_enforce;

	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		init_event(event, deny ? EVENT_BIND_BLOCKED : EVENT_BIND_WOULD_BLOCK,
			transport_for_socket_protocol(lookup->protocol), EVENT_SOURCE_CGROUP_SOCK_ADDR);
		event->kernel_uid = lookup->uid;
		event->uid_source = UID_SOURCE_KERNEL;
		event->cgroup_id = lookup->cgroup_id;
		set_event_rule(event, cfg->active_policy_slot, rule_id);
		set_event_socket_meta(event, family, lookup->protocol, hook, 0);
		set_event_local(event, family, lookup->port, lookup->addr);
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
		event->socket_cookie = bpf_get_socket_cookie(ctx);
#else
		(void)ctx;
#endif
		bpf_ringbuf_submit(event, 0);
	}
	return cgroup_verdict(deny);
}

static __always_inline int evaluate_bind4(struct bpf_sock_addr *ctx, __u32 addr, __u8 protocol, __u16 port, __u8 hook)
{
	struct policy_guard guard = {0};
	const struct settings *cfg;
	struct egress_lookup lookup = {0};
	__u32 rule;
	int verdict;

	if (!acquire_policy_guard(&guard)) return 1;
	cfg = &guard.cfg;
	if (!cfg->bind_enabled) {
		release_policy_guard(&guard);
		return 1;
	}
	lookup.uid = (__u32)bpf_get_current_uid_gid();
	lookup.cgroup_id = bpf_get_current_cgroup_id();
	lookup.policy_slot = cfg->active_policy_slot;
	lookup.protocol = protocol;
	lookup.port = port;
	__builtin_memcpy(lookup.addr, &addr, sizeof(addr));
	if (lookup_bind4(1, &lookup)) {
		release_policy_guard(&guard);
		return 1;
	}
	rule = lookup_bind4(0, &lookup);
	if (!rule && !cfg->bind_default_block) {
		release_policy_guard(&guard);
		return 1;
	}
	verdict = emit_bind_decision(ctx, cfg, &lookup, rule,
		(__u16)(((__u16)FAMILY_IPV4 << 8) | hook));
	release_policy_guard(&guard);
	return verdict;
}

static __always_inline int evaluate_bind6(struct bpf_sock_addr *ctx, const __u8 addr[16], __u8 protocol, __u16 port)
{
	__u32 mapped_ipv4 = 0;
	struct policy_guard guard = {0};
	const struct settings *cfg;
	struct egress_lookup lookup = {0};
	__u32 rule;
	int verdict;

	if (!addr[0] && !addr[1] && !addr[2] && !addr[3] && !addr[4] && !addr[5] &&
	    !addr[6] && !addr[7] && !addr[8] && !addr[9] && addr[10] == 0xff && addr[11] == 0xff) {
		__builtin_memcpy(&mapped_ipv4, &addr[12], sizeof(mapped_ipv4));
		return evaluate_bind4(ctx, mapped_ipv4, protocol, port, SOCKET_HOOK_CGROUP_BIND6);
	}
	if (!acquire_policy_guard(&guard)) return 1;
	cfg = &guard.cfg;
	if (!cfg->bind_enabled) {
		release_policy_guard(&guard);
		return 1;
	}
	lookup.uid = (__u32)bpf_get_current_uid_gid();
	lookup.cgroup_id = bpf_get_current_cgroup_id();
	lookup.policy_slot = cfg->active_policy_slot;
	lookup.protocol = protocol;
	lookup.port = port;
	__builtin_memcpy(lookup.addr, addr, 16);
	if (lookup_bind6(1, &lookup)) {
		release_policy_guard(&guard);
		return 1;
	}
	rule = lookup_bind6(0, &lookup);
	if (!rule && !cfg->bind_default_block) {
		release_policy_guard(&guard);
		return 1;
	}
	verdict = emit_bind_decision(ctx, cfg, &lookup, rule,
		(__u16)(((__u16)FAMILY_IPV6 << 8) | SOCKET_HOOK_CGROUP_BIND6));
	release_policy_guard(&guard);
	return verdict;
}

static __noinline int load_unix_path(struct bpf_sock_addr *ctx, char path[109], __u32 *path_len)
{
	struct bpf_sock_addr_kern *kctx = bpf_cast_to_kern_ctx(ctx);
	struct sockaddr_un *address;
	__u32 available;
	__u32 name_len;
	char first = 0;
	__u8 found = 0;

	if (!kctx || kctx->uaddrlen <= 2) {
		return 0;
	}
	address = bpf_rdonly_cast(kctx->uaddr, bpf_core_type_id_kernel(struct sockaddr_un));
	if (!address) {
		return 0;
	}
	available = kctx->uaddrlen - 2;
	if (available > sizeof(address->sun_path)) {
		available = sizeof(address->sun_path);
	}
	if (bpf_probe_read_kernel(&first, sizeof(first), &address->sun_path[0]) < 0) {
		return 0;
	}
	if (first == 0) {
		if (available <= 1) {
			return 0;
		}
		name_len = available - 1;
		if (name_len > 107) {
			name_len = 107;
		}
		path[0] = '@';
		if (bpf_probe_read_kernel(&path[1], name_len, &address->sun_path[1]) < 0) {
			return 0;
		}
		*path_len = name_len + 1;
		return 1;
	}
	if (first != '/') {
		return 0;
	}
	if (bpf_probe_read_kernel(path, available, &address->sun_path[0]) < 0) {
		return 0;
	}
	*path_len = available;
#pragma unroll
	for (int i = 0; i < 108; i++) {
		if ((__u32)i < available && !found && path[i] == 0) {
			*path_len = (__u32)i;
			found = 1;
		}
	}
	return *path_len > 0;
}

/*
 * Kept out of evaluate_unix so the decision context does not occupy stack in
 * the frame that stays live across the path lookup: evaluate_unix plus
 * lookup_path_kind must fit the verifier's 512-byte combined stack limit.
 */
static __noinline void emit_unix_decision(const struct path_lookup_context *lookup, __u32 rule_id,
	__u8 hook, __u8 enforce)
{
	const struct path_decision_context decision = {
		.path = lookup->path,
		.cgroup_id = lookup->cgroup_id,
		.uid = lookup->uid,
		.rule_id = rule_id,
		.path_len = lookup->path_len,
		.policy_slot = lookup->policy_slot,
		.family = FAMILY_UNIX,
		.hook = hook,
		.operation = lookup->access_or_op,
	};

	emit_path_decision(enforce ? EVENT_UNIX_BLOCKED : EVENT_UNIX_WOULD_BLOCK,
		EVENT_SOURCE_CGROUP_SOCK_ADDR, &decision);
}

static __always_inline int evaluate_unix(struct bpf_sock_addr *ctx, __u8 operation, __u8 hook)
{
	struct policy_guard guard = {0};
	const struct settings *cfg;
	char path[109] = {0};
	__u32 rule_id = 0;
	__u8 enforce;
	struct path_lookup_context lookup = {0};

	if (!acquire_policy_guard(&guard)) {
		return 1;
	}
	cfg = &guard.cfg;
	if (!cfg->unix_enabled) {
		release_policy_guard(&guard);
		return 1;
	}
	if (!load_unix_path(ctx, path, &lookup.path_len)) {
		release_policy_guard(&guard);
		return 1;
	}
	lookup.path = path;
	lookup.cgroup_id = bpf_get_current_cgroup_id();
	lookup.uid = (__u32)bpf_get_current_uid_gid();
	lookup.domain = PATH_DOMAIN_UNIX;
	lookup.policy_slot = cfg->active_policy_slot;
	lookup.access_or_op = operation;
	if (!path_policy_denies(&lookup, cfg->unix_default_block, &rule_id)) {
		release_policy_guard(&guard);
		return 1;
	}
	/* cgroup/recvmsg_unix may only return 1, so recvmsg decisions are audit-only. */
	enforce = cfg->unix_enforce && operation != UNIX_OP_RECVMSG;
	emit_unix_decision(&lookup, rule_id, hook, enforce);
	release_policy_guard(&guard);
	return cgroup_verdict(enforce);
}

SEC("cgroup/connect_unix")
int trace_connect_unix(struct bpf_sock_addr *ctx)
{
	return evaluate_unix(ctx, UNIX_OP_CONNECT, SOCKET_HOOK_CGROUP_UNIX_CONNECT);
}

SEC("cgroup/sendmsg_unix")
int trace_sendmsg_unix(struct bpf_sock_addr *ctx)
{
	return evaluate_unix(ctx, UNIX_OP_SENDMSG, SOCKET_HOOK_CGROUP_UNIX_SENDMSG);
}

SEC("cgroup/recvmsg_unix")
int trace_recvmsg_unix(struct bpf_sock_addr *ctx)
{
	evaluate_unix(ctx, UNIX_OP_RECVMSG, SOCKET_HOOK_CGROUP_UNIX_RECVMSG);
	return 1;
}

struct sockopt_lookup_context {
	__u64 cgroup_id;
	__u32 uid;
	__u32 level;
	__u32 optname;
	__u8 slot;
};

static __always_inline __u32 lookup_sockopt_kind(__u8 allow, __u8 kind,
	const struct sockopt_lookup_context *lookup)
{
	struct sockopt_key key = {
		.slot = lookup->slot,
		.kind = kind,
		.uid = identity_has_uid(kind) ? lookup->uid : 0,
		.cgroup_id = identity_has_cgroup(kind) ? lookup->cgroup_id : 0,
		.level = lookup->level,
		.optname = lookup->optname,
	};
	__u32 *rule = allow ? bpf_map_lookup_elem(&sockopt_allow, &key) : bpf_map_lookup_elem(&sockopt_block, &key);
	return rule ? *rule : 0;
}

struct sockopt_ancestor_context {
	struct sockopt_lookup_context lookup;
	__u32 rule;
	__u8 allow;
	__u8 kind;
};

static long lookup_sockopt_ancestor(__u32 level, void *data)
{
	struct sockopt_ancestor_context *ctx = data;
	__u64 cgroup_id = bpf_get_current_ancestor_cgroup_id(level);

	if (!cgroup_id) {
		return 1;
	}
	ctx->lookup.cgroup_id = cgroup_id;
	ctx->rule = lookup_sockopt_kind(ctx->allow, ctx->kind, &ctx->lookup);
	return ctx->rule ? 1 : 0;
}

static __always_inline __u32 lookup_sockopt_ancestor_policy(__u8 allow, __u8 kind,
	const struct sockopt_lookup_context *lookup)
{
	struct sockopt_ancestor_context ctx = {
		.lookup = *lookup,
		.allow = allow,
		.kind = kind,
	};

	if (bpf_loop(MAX_CGROUP_ANCESTORS, lookup_sockopt_ancestor, &ctx, 0) < 0) {
		return 0;
	}
	return ctx.rule;
}

static __always_inline __u32 lookup_sockopt(__u8 allow, const struct sockopt_lookup_context *lookup)
{
	__u32 rule = lookup_sockopt_kind(allow, EGRESS_IDENTITY_UID_CGROUP, lookup);
	if (rule) return rule;
	rule = lookup_sockopt_ancestor_policy(allow, EGRESS_IDENTITY_UID_CGROUP_ANCESTOR, lookup);
	if (rule) return rule;
	rule = lookup_sockopt_kind(allow, EGRESS_IDENTITY_UID, lookup);
	if (rule) return rule;
	rule = lookup_sockopt_kind(allow, EGRESS_IDENTITY_CGROUP, lookup);
	if (rule) return rule;
	rule = lookup_sockopt_ancestor_policy(allow, EGRESS_IDENTITY_CGROUP_ANCESTOR, lookup);
	if (rule) return rule;
	return lookup_sockopt_kind(allow, EGRESS_IDENTITY_GLOBAL, lookup);
}

SEC("cgroup/setsockopt")
int trace_setsockopt(struct bpf_sockopt *ctx)
{
	struct policy_guard guard = {0};
	const struct settings *cfg;
	__u32 uid;
	__u64 cgroup_id;
	__u32 level;
	__u32 optname;
	__u32 rule_id;
	struct event *event;
	struct sockopt_lookup_context lookup;
	int verdict;

	if (!acquire_policy_guard(&guard)) {
		return 1;
	}
	cfg = &guard.cfg;
	if (!cfg->sockopt_enabled) {
		release_policy_guard(&guard);
		return 1;
	}
	uid = (__u32)bpf_get_current_uid_gid();
	cgroup_id = bpf_get_current_cgroup_id();
	level = (__u32)ctx->level;
	optname = (__u32)ctx->optname;
	lookup = (struct sockopt_lookup_context){
		.cgroup_id = cgroup_id,
		.uid = uid,
		.level = level,
		.optname = optname,
		.slot = cfg->active_policy_slot,
	};
	if (lookup_sockopt(1, &lookup)) {
		release_policy_guard(&guard);
		return 1;
	}
	rule_id = lookup_sockopt(0, &lookup);
	if (!rule_id && !cfg->sockopt_default_block) {
		release_policy_guard(&guard);
		return 1;
	}
	event = reserve_event(cfg->sockopt_enforce ? EVENT_SOCKOPT_BLOCKED : EVENT_SOCKOPT_WOULD_BLOCK);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		init_event(event, cfg->sockopt_enforce ? EVENT_SOCKOPT_BLOCKED : EVENT_SOCKOPT_WOULD_BLOCK,
			0, EVENT_SOURCE_CGROUP_SOCKOPT);
		event->kernel_uid = uid;
		event->uid_source = UID_SOURCE_KERNEL;
		event->cgroup_id = cgroup_id;
		set_event_rule(event, cfg->active_policy_slot, rule_id);
		event->file_flags = level;
		event->file_mode = optname;
		event->socket_hook = SOCKET_HOOK_CGROUP_SETSOCKOPT;
		if (ctx->sk) {
			event->family = ctx->sk->family == AF_INET ? FAMILY_IPV4 :
				(ctx->sk->family == AF_INET6 ? FAMILY_IPV6 : 0);
		}
		bpf_ringbuf_submit(event, 0);
	}
	verdict = cgroup_verdict(cfg->sockopt_enforce);
	release_policy_guard(&guard);
	return verdict;
}

static __always_inline int should_emit_sockops_retrans(struct bpf_sock_ops *ctx)
{
	struct connection_dedupe_key key = {0};
	struct connection_dedupe_value value = {0};
	struct connection_dedupe_value *existing;
	__u64 window = connection_dedupe_window_ns;
	__u64 cookie;
	__u64 now;

	if (!window) {
		return 1;
	}
	cookie = bpf_get_socket_cookie(ctx);
	now = bpf_ktime_get_ns();
	key.direction = (__u8)BPF_SOCK_OPS_RETRANS_CB;
	__builtin_memcpy(key.addr, &cookie, sizeof(cookie));
	existing = bpf_map_lookup_elem(&connection_dedupe, &key);
	if (existing && now >= existing->last_seen_ns && now - existing->last_seen_ns < window) {
		return 0;
	}
	value.last_seen_ns = now;
	bpf_map_update_elem(&connection_dedupe, &key, &value, BPF_ANY);
	return 1;
}

static __always_inline void emit_sockops_event(struct bpf_sock_ops *ctx)
{
	struct event *event = reserve_event(EVENT_SOCKOPS);
	__u8 family;

	if (!event) {
		return;
	}
	family = ctx->family == AF_INET ? FAMILY_IPV4 : (ctx->family == AF_INET6 ? FAMILY_IPV6 : 0);
	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, EVENT_SOCKOPS, TRANSPORT_TCP, EVENT_SOURCE_SOCKOPS);
	set_event_socket_meta(event, family, SOCKET_PROTOCOL_TCP, SOCKET_HOOK_SOCKOPS, 0);
	event->file_flags = (__u32)ctx->op;
	if (ctx->op == BPF_SOCK_OPS_STATE_CB) {
		event->file_mode = ctx->args[1];
	}
	event->socket_cookie = bpf_get_socket_cookie(ctx);
	/* bpf_sock_ops address fields only allow full 4-byte context loads, so
	 * copy them into locals before the byte-wise event copy.
	 */
	if (family == FAMILY_IPV4) {
		__u32 remote4 = ctx->remote_ip4;
		__u32 local4 = ctx->local_ip4;

		set_event_peer(event, family, (__u16)bpf_ntohl(ctx->remote_port), &remote4);
		set_event_local(event, family, (__u16)ctx->local_port, &local4);
	} else if (family == FAMILY_IPV6) {
		__u32 remote6[4] = {ctx->remote_ip6[0], ctx->remote_ip6[1], ctx->remote_ip6[2], ctx->remote_ip6[3]};
		__u32 local6[4] = {ctx->local_ip6[0], ctx->local_ip6[1], ctx->local_ip6[2], ctx->local_ip6[3]};

		set_event_peer(event, family, (__u16)bpf_ntohl(ctx->remote_port), remote6);
		set_event_local(event, family, (__u16)ctx->local_port, local6);
	}
	bpf_ringbuf_submit(event, 0);
}

SEC("sockops")
int trace_sockops(struct bpf_sock_ops *ctx)
{
	switch (ctx->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		/* Preserve callbacks another sockops program enabled on this socket. */
		bpf_sock_ops_cb_flags_set(ctx, (int)(ctx->bpf_sock_ops_cb_flags |
			BPF_SOCK_OPS_RETRANS_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG));
		emit_sockops_event(ctx);
		break;
	case BPF_SOCK_OPS_RETRANS_CB:
		if (should_emit_sockops_retrans(ctx)) {
			emit_sockops_event(ctx);
		}
		break;
	case BPF_SOCK_OPS_STATE_CB:
		if (ctx->args[1] == BPF_TCP_CLOSE) {
			emit_sockops_event(ctx);
		}
		break;
	default:
		break;
	}
	return 1;
}

static __always_inline int load_sock_local4(struct bpf_sock *sk, __u32 *addr, __u16 *port)
{
	if (!sk || sk->family != AF_INET) {
		return 0;
	}
	*addr = sk->src_ip4;
	*port = (__u16)sk->src_port;
	return 1;
}

static __always_inline int load_sock_local6(struct bpf_sock *sk, __u8 addr[16], __u16 *port)
{
	if (!sk || sk->family != AF_INET6) {
		return 0;
	}
	__builtin_memcpy(addr, sk->src_ip6, sizeof(__u8) * 16);
	*port = (__u16)sk->src_port;
	return 1;
}

static __always_inline __u8 socket_protocol_from_ipproto(__u32 protocol)
{
	if (protocol == IPPROTO_TCP) {
		return SOCKET_PROTOCOL_TCP;
	}
	if (protocol == IPPROTO_UDP) {
		return SOCKET_PROTOCOL_UDP;
	}
	return 0;
}

static __always_inline int policy_rule_active(const __u8 *value, __u8 policy_mask)
{
	if (!value) {
		return 0;
	}
	return (*value & policy_mask) != 0;
}

static __always_inline void init_endpoint4_cidr_key(struct endpoint4_cidr_key *key, __u32 addr, __u16 port, __u8 transport)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->prefixlen = 24 + 32;
	key->data[0] = transport;
	key->data[1] = (__u8)(port >> 8);
	key->data[2] = (__u8)(port & 0xff);
	__builtin_memcpy(&key->data[3], &addr, sizeof(addr));
}

static __always_inline void init_endpoint6_cidr_key(struct endpoint6_cidr_key *key, const __u8 addr[16], __u16 port, __u8 transport)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->prefixlen = 24 + 128;
	key->data[0] = transport;
	key->data[1] = (__u8)(port >> 8);
	key->data[2] = (__u8)(port & 0xff);
	__builtin_memcpy(&key->data[3], addr, 16);
}

static __always_inline __u8 *lookup_endpoint4_cidr_rule(__u32 addr, __u16 port, __u8 transport, __u8 policy_mask)
{
	struct endpoint4_cidr_key key = {0};

	init_endpoint4_cidr_key(&key, addr, port, transport);
	__u8 *value = bpf_map_lookup_elem(&endpoint4_cidr_rules, &key);
	return policy_rule_active(value, policy_mask) ? value : 0;
}

static __always_inline __u8 *lookup_endpoint4_cidr_allow_rule(__u32 addr, __u16 port, __u8 transport, __u8 policy_mask)
{
	struct endpoint4_cidr_key key = {0};

	init_endpoint4_cidr_key(&key, addr, port, transport);
	__u8 *value = bpf_map_lookup_elem(&endpoint4_cidr_allow_rules, &key);
	return policy_rule_active(value, policy_mask) ? value : 0;
}

static __always_inline __u8 *lookup_endpoint6_cidr_rule(const __u8 addr[16], __u16 port, __u8 transport, __u8 policy_mask)
{
	struct endpoint6_cidr_key key = {0};

	init_endpoint6_cidr_key(&key, addr, port, transport);
	__u8 *value = bpf_map_lookup_elem(&endpoint6_cidr_rules, &key);
	return policy_rule_active(value, policy_mask) ? value : 0;
}

static __always_inline __u8 *lookup_endpoint6_cidr_allow_rule(const __u8 addr[16], __u16 port, __u8 transport, __u8 policy_mask)
{
	struct endpoint6_cidr_key key = {0};

	init_endpoint6_cidr_key(&key, addr, port, transport);
	__u8 *value = bpf_map_lookup_elem(&endpoint6_cidr_allow_rules, &key);
	return policy_rule_active(value, policy_mask) ? value : 0;
}

struct qname_load_context {
	struct __sk_buff *skb;
	struct dns_parse_result *parsed;
	__u32 start;
	__u8 cursor;
	__u8 label_remaining;
	__u8 done;
	__u8 failed;
};

static long load_qname_byte(__u64 index, void *data)
{
	struct qname_load_context *ctx = data;
	__u8 c;

	(void)index;
	if (bpf_skb_load_bytes(ctx->skb, ctx->start + ctx->cursor, &c, sizeof(c)) < 0) {
		ctx->failed = 1;
		return 1;
	}
	if (ctx->label_remaining == 0) {
		/* Compression and reserved label types are not valid in the sole
		 * first question that policy classification inspects.
		 */
		if ((c & 0xc0) != 0) {
			ctx->failed = 1;
			return 1;
		}
		ctx->parsed->key.domain[ctx->cursor] = c;
		if (c == 0) {
			ctx->parsed->qname_length = (__u16)ctx->cursor + 1;
			ctx->done = 1;
			return 1;
		}
		ctx->label_remaining = c;
		ctx->cursor++;
		return 0;
	}
	if (c == 0) {
		ctx->failed = 1;
		return 1;
	}
	if (c >= 'A' && c <= 'Z') {
		c += 'a' - 'A';
	}
	ctx->parsed->key.domain[ctx->cursor] = c;
	ctx->label_remaining--;
	ctx->cursor++;
	return 0;
}

static __always_inline int load_qname_key(struct __sk_buff *skb, __u32 start, __u32 packet_len, struct dns_parse_result *parsed)
{
	struct qname_load_context ctx = {
		.skb = skb,
		.parsed = parsed,
		.start = start,
	};
	__u32 available;

	if (packet_len <= start) {
		return -1;
	}
	available = packet_len - start;
	if (available > MAX_DOMAIN_LEN) {
		available = MAX_DOMAIN_LEN;
	}

	__builtin_memset(&parsed->key, 0, sizeof(parsed->key));
	parsed->qname_length = 0;
	if (bpf_loop(available, load_qname_byte, &ctx, 0) < 0 || ctx.failed || !ctx.done) {
		return -1;
	}
	return 0;
}

struct dns_emit_context {
	const struct domain_key *key;
	__u32 kind;
	__u32 decision;
	__u8 transport;
};

static __always_inline int emit_dns4_event(struct __sk_buff *skb, const struct dns_emit_context *ctx, __u32 addr)
{
	struct event *event = reserve_event(ctx->kind);
	__u8 protocol = ctx->transport == TRANSPORT_TCP ? SOCKET_PROTOCOL_TCP : SOCKET_PROTOCOL_UDP;
	(void)skb;

	if (!event) {
		return ctx->kind == EVENT_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, ctx->kind, ctx->transport, EVENT_SOURCE_CGROUP_SKB);
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
	event->socket_cookie = bpf_get_socket_cookie(skb);
#endif
	apply_socket_info(event, FAMILY_IPV4, protocol, DNS_PORT, &addr);
	set_event_peer(event, FAMILY_IPV4, DNS_PORT, &addr);
	event->rule_id = ctx->decision;
	__builtin_memcpy(event->domain, ctx->key->domain, sizeof(event->domain));
	bpf_ringbuf_submit(event, 0);
	return ctx->kind == EVENT_BLOCKED ? 0 : 1;
}

static __always_inline int emit_dns6_event(struct __sk_buff *skb, const struct dns_emit_context *ctx, const __u8 addr[16])
{
	struct event *event = reserve_event(ctx->kind);
	__u8 protocol = ctx->transport == TRANSPORT_TCP ? SOCKET_PROTOCOL_TCP : SOCKET_PROTOCOL_UDP;
	(void)skb;

	if (!event) {
		return ctx->kind == EVENT_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, ctx->kind, ctx->transport, EVENT_SOURCE_CGROUP_SKB);
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
	event->socket_cookie = bpf_get_socket_cookie(skb);
#endif
	apply_socket_info(event, FAMILY_IPV6, protocol, DNS_PORT, addr);
	set_event_peer(event, FAMILY_IPV6, DNS_PORT, addr);
	event->rule_id = ctx->decision;
	__builtin_memcpy(event->domain, ctx->key->domain, sizeof(event->domain));
	bpf_ringbuf_submit(event, 0);
	return ctx->kind == EVENT_BLOCKED ? 0 : 1;
}

static __always_inline __u32 dns_event_kind(const struct dns_parse_result *parsed, const struct policy_snapshot *policy, __u32 *decision)
{
	__u8 *present;

	*decision = POLICY_DECISION_NONE;
	present = bpf_map_lookup_elem(&allowlist, &parsed->key);
	if (policy_rule_active(present, policy->policy_mask)) {
		*decision = POLICY_DECISION_ALLOW;
		return EVENT_DNS;
	}
	if (parsed->allow_suffix_match) {
		*decision = POLICY_DECISION_ALLOW;
		return EVENT_DNS;
	}
	if (policy->block_all_domains) {
		*decision = POLICY_DECISION_BLOCK;
		return policy->block_enabled ? EVENT_BLOCKED : EVENT_DNS;
	}
	present = bpf_map_lookup_elem(&blocklist, &parsed->key);
	if (policy_rule_active(present, policy->policy_mask)) {
		*decision = POLICY_DECISION_BLOCK;
		return policy->block_enabled ? EVENT_BLOCKED : EVENT_DNS;
	}
	if (parsed->block_suffix_match) {
		*decision = POLICY_DECISION_BLOCK;
		return policy->block_enabled ? EVENT_BLOCKED : EVENT_DNS;
	}
	return EVENT_DNS;
}

struct suffix_hash_context {
	__u64 hash;
	__u16 length;
	__u8 cursor;
	__u8 failed;
};

static long hash_suffix_byte(__u64 index, void *data)
{
	struct suffix_hash_context *ctx = data;
	__u32 zero = 0;
	const struct dns_parse_result *source;
	__u8 c;

	(void)index;
	source = bpf_map_lookup_elem(&dns_scratch, &zero);
	if (!source) {
		ctx->failed = 1;
		return 1;
	}
	c = source->key.domain[ctx->cursor];
	ctx->hash ^= c;
	ctx->hash *= 1099511628211ULL;
	ctx->length++;
	ctx->cursor++;
	return 0;
}

struct suffix_match_context {
	__u8 offset;
	__u8 policy_slot;
	__u8 allow;
	__u8 matched;
	__u8 failed;
};

static long match_qname_suffix(__u64 index, void *data)
{
	struct suffix_match_context *ctx = data;
	struct suffix_hash_context hash = {
		.hash = 14695981039346656037ULL,
		.cursor = ctx->offset,
	};
	struct domain_suffix_key suffix;
	__u32 zero = 0;
	const struct dns_parse_result *parsed;
	__u8 *present;
	__u8 label_len;
	__u16 suffix_length;
	__u16 next_offset;

	(void)index;
	parsed = bpf_map_lookup_elem(&dns_scratch, &zero);
	if (!parsed) {
		ctx->failed = 1;
		return 1;
	}
	if (ctx->offset >= MAX_DOMAIN_LEN) {
		return 1;
	}
	label_len = parsed->key.domain[ctx->offset];
	if (label_len == 0) {
		return 1;
	}
	next_offset = (__u16)ctx->offset + 1 + (__u16)label_len;
	if (label_len > 63 || next_offset >= MAX_DOMAIN_LEN) {
		return 1;
	}
	if (parsed->qname_length <= ctx->offset) {
		return 1;
	}
	suffix_length = parsed->qname_length - ctx->offset;
	if (suffix_length > MAX_SUFFIX_WIRE_LEN) {
		ctx->offset = (__u8)next_offset;
		return 0;
	}
	if (bpf_loop(suffix_length, hash_suffix_byte, &hash, 0) < 0 || hash.failed) {
		ctx->failed = 1;
		return 1;
	}
	suffix = (struct domain_suffix_key){
		.hash = hash.hash,
		.length = hash.length,
		.policy_slot = ctx->policy_slot,
	};
	if (ctx->allow) {
		present = bpf_map_lookup_elem(&allow_suffixes, &suffix);
	} else {
		present = bpf_map_lookup_elem(&block_suffixes, &suffix);
	}
	if (present) {
		ctx->matched = 1;
		return 1;
	}
	ctx->offset = (__u8)next_offset;
	return 0;
}

static __noinline __u8 qname_matches_suffix(__u8 policy_slot, __u8 allow)
{
	struct suffix_match_context ctx = {
		.policy_slot = policy_slot,
		.allow = allow,
	};

	/* Keep the label walk behind bpf_loop. A bounded C loop over every
	 * possible DNS label makes the verifier explore too many states and can
	 * exceed its one-million-instruction processing limit.
	 */
	if (bpf_loop(MAX_SUFFIX_LABELS, match_qname_suffix, &ctx, 0) < 0 || ctx.failed) {
		return 0;
	}
	return ctx.matched;
}

static __always_inline int parse_dns_payload(struct __sk_buff *skb, __u32 payload_offset, __u32 packet_len, struct dns_parse_result *parsed, const struct policy_snapshot *policy)
{
	struct dns_header dns = {0};
	__u32 qname_offset;
	__u16 flags;
	__u16 qdcount;
	int parse_status;

	parsed->allow_suffix_match = 0;
	parsed->block_suffix_match = 0;
	if (payload_offset + sizeof(dns) > packet_len) {
		return -1;
	}
	if (bpf_skb_load_bytes(skb, payload_offset, &dns, sizeof(dns)) < 0) {
		return -1;
	}

	flags = bpf_ntohs(dns.flags);
	qdcount = bpf_ntohs(dns.qdcount);
	/* Policy classification parses one question. Reject multi-question
	 * requests instead of admitting uninspected names after the first one.
	 */
	if ((flags & 0x8000) != 0 || qdcount != 1) {
		return -1;
	}

	qname_offset = payload_offset + sizeof(dns);
	parse_status = load_qname_key(skb, qname_offset, packet_len, parsed);
	if (parse_status < 0) {
		return -1;
	}
	/* A complete DNS question includes QTYPE and QCLASS after QNAME. */
	if (parsed->qname_length > packet_len - qname_offset ||
		packet_len - qname_offset - parsed->qname_length < 4) {
		return -1;
	}
	if (policy->allow_suffix_rules_enabled) {
		parsed->allow_suffix_match = qname_matches_suffix(policy->policy_mask >> 1, 1);
	}
	if (policy->block_suffix_rules_enabled) {
		parsed->block_suffix_match = qname_matches_suffix(policy->policy_mask >> 1, 0);
	}

	return 0;
}

static __always_inline int parse_tcp_dns_payload(struct __sk_buff *skb, __u32 payload_offset, __u32 packet_len, struct dns_parse_result *parsed, const struct policy_snapshot *policy)
{
	__be16 dns_len_be;
	__u16 dns_len;
	__u32 dns_offset;
	__u32 dns_end;

	if (payload_offset >= packet_len) {
		return DNS_PARSE_PASS;
	}
	if (payload_offset + sizeof(dns_len_be) > packet_len) {
		return policy->block_enabled ? DNS_PARSE_DROP : DNS_PARSE_PASS;
	}
	if (bpf_skb_load_bytes(skb, payload_offset, &dns_len_be, sizeof(dns_len_be)) < 0) {
		return policy->block_enabled ? DNS_PARSE_DROP : DNS_PARSE_PASS;
	}

	dns_len = bpf_ntohs(dns_len_be);
	if (dns_len < sizeof(struct dns_header)) {
		return policy->block_enabled ? DNS_PARSE_DROP : DNS_PARSE_PASS;
	}

	dns_offset = payload_offset + sizeof(dns_len_be);
	dns_end = dns_offset + (__u32)dns_len;
	if (dns_end < dns_offset || dns_end > packet_len || dns_end != packet_len) {
		return policy->block_enabled ? DNS_PARSE_DROP : DNS_PARSE_PASS;
	}

	return parse_dns_payload(skb, dns_offset, dns_end, parsed, policy) == 0 ? DNS_PARSE_OK : policy->block_enabled ? DNS_PARSE_DROP : DNS_PARSE_PASS;
}

static __always_inline int emit_resolver_event(struct bpf_sock_addr *ctx, __u32 kind, __u8 transport, __u8 family, __u16 port, const void *addr, __u32 addr_len, __u8 hook, __u32 decision)
{
	struct event *event = reserve_event(kind);
	(void)ctx;
	(void)addr_len;

	if (!event) {
		return kind == EVENT_RESOLVER_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, transport, EVENT_SOURCE_CGROUP_SOCK_ADDR);
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
	event->socket_cookie = bpf_get_socket_cookie(ctx);
#endif
	set_event_socket_meta(event, family, SOCKET_PROTOCOL_TCP, hook, ATTRIBUTION_KERNEL_CONNECT);
	set_event_peer(event, family, port, addr);
	event->rule_id = decision;
	bpf_ringbuf_submit(event, 0);
	return kind == EVENT_RESOLVER_BLOCKED ? 0 : 1;
}

static __always_inline int parse_ipv6_transport(struct __sk_buff *skb, __u32 packet_len, __u8 *nexthdr, __u32 *transport_offset, __u8 *fragmented)
{
	*fragmented = 0;
#pragma clang loop unroll(disable)
	for (int i = 0; i < 6; i++) {
		if (*nexthdr == IPPROTO_HOPOPTS || *nexthdr == IPPROTO_ROUTING || *nexthdr == IPPROTO_DSTOPTS) {
			struct ipv6_ext_header ext = {0};
			__u32 header_len;

			if (*transport_offset + sizeof(ext) > packet_len) {
				return -1;
			}
			if (bpf_skb_load_bytes(skb, *transport_offset, &ext, sizeof(ext)) < 0) {
				return -1;
			}

			header_len = ((__u32)ext.hdrlen + 1) * 8;
			if (header_len < 8 || *transport_offset + header_len > packet_len) {
				return -1;
			}

			*nexthdr = ext.nexthdr;
			*transport_offset += header_len;
			continue;
		}
		if (*nexthdr == IPPROTO_AH) {
			struct ipv6_ext_header ext = {0};
			__u32 header_len;

			if (*transport_offset + sizeof(ext) > packet_len) {
				return -1;
			}
			if (bpf_skb_load_bytes(skb, *transport_offset, &ext, sizeof(ext)) < 0) {
				return -1;
			}

			header_len = ((__u32)ext.hdrlen + 2) * 4;
			if (header_len < 8 || *transport_offset + header_len > packet_len) {
				return -1;
			}

			*nexthdr = ext.nexthdr;
			*transport_offset += header_len;
			continue;
		}
		if (*nexthdr == IPPROTO_FRAGMENT) {
			struct ipv6_frag_header frag = {0};
			__u16 frag_off;

			if (*transport_offset + sizeof(frag) > packet_len) {
				return -1;
			}
			if (bpf_skb_load_bytes(skb, *transport_offset, &frag, sizeof(frag)) < 0) {
				return -1;
			}

			frag_off = bpf_ntohs(frag.frag_off);
			*nexthdr = frag.nexthdr;
			*transport_offset += sizeof(frag);
			if ((frag_off & 0xfff8) != 0 || (frag_off & 0x1) != 0) {
				*fragmented = 1;
				return 0;
			}
			continue;
		}
		return 0;
	}

	if (*nexthdr == IPPROTO_HOPOPTS || *nexthdr == IPPROTO_ROUTING || *nexthdr == IPPROTO_DSTOPTS || *nexthdr == IPPROTO_AH ||
		*nexthdr == IPPROTO_FRAGMENT) {
		return IPV6_EXT_HEADERS_EXHAUSTED;
	}
	return 0;
}

static __always_inline int block_fragmented_ipv6_dns(struct __sk_buff *skb, __u32 transport_offset, __u32 packet_len, __u8 nexthdr, __u8 block_enabled)
{
	if (!block_enabled) {
		return 1;
	}
	if (transport_offset >= packet_len) {
		/* Later fragments do not carry the transport header, so they cannot be
		 * classified safely without connection reassembly state. Pass them here
		 * rather than breaking unrelated fragmented IPv6 traffic.
		 */
		return 1;
	}

	if (nexthdr == IPPROTO_UDP) {
		struct udphdr udph = {0};

		if (transport_offset + sizeof(udph) > packet_len) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, transport_offset, &udph, sizeof(udph)) < 0) {
			return 1;
		}
		if (bpf_ntohs(udph.dest) == DNS_PORT) {
			return 0;
		}
		return 1;
	}
	if (nexthdr == IPPROTO_TCP) {
		struct tcphdr tcph = {0};

		if (transport_offset + sizeof(tcph) > packet_len) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, transport_offset, &tcph, sizeof(tcph)) < 0) {
			return 1;
		}
		if (bpf_ntohs(tcph.dest) == DNS_PORT) {
			return 0;
		}
	}
	return 1;
}

static __always_inline int classify_endpoint4(__u32 addr, __u16 port, const struct policy_snapshot *policy, __u8 *transport_out, __u8 *decision)
{
	struct endpoint4_key key = {
		.addr = addr,
		.port = port,
		.transport = TRANSPORT_DOH,
	};
	__u8 *present;

	*decision = POLICY_DECISION_NONE;
	if (port == DOT_PORT) {
		key.transport = TRANSPORT_DOT;
		present = bpf_map_lookup_elem(&endpoint4_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = lookup_endpoint4_cidr_allow_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint4_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*decision = POLICY_DECISION_BLOCK;
		}
		present = lookup_endpoint4_cidr_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present || policy->block_all_resolvers) {
			*decision = POLICY_DECISION_BLOCK;
		}
		*transport_out = TRANSPORT_DOT;
		return 1;
	}
	if (port == HTTPS_PORT) {
		present = bpf_map_lookup_elem(&endpoint4_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = lookup_endpoint4_cidr_allow_rule(addr, port, TRANSPORT_DOH, policy->policy_mask);
		if (present) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint4_rules, &key);
		if (!policy_rule_active(present, policy->policy_mask)) {
			present = lookup_endpoint4_cidr_rule(addr, port, TRANSPORT_DOH, policy->policy_mask);
		}
		/* DoH remains endpoint-based on 443; wildcard resolver mode must not classify arbitrary HTTPS traffic. */
		if (!policy_rule_active(present, policy->policy_mask)) {
			return 0;
		}
		*decision = POLICY_DECISION_BLOCK;
		*transport_out = TRANSPORT_DOH;
		return 1;
	}
	return 0;
}

static __always_inline int classify_endpoint6(const __u8 addr[16], __u16 port, const struct policy_snapshot *policy, __u8 *transport_out, __u8 *decision)
{
	struct endpoint6_key key = {0};
	__u8 *present;

	__builtin_memcpy(key.addr, addr, sizeof(key.addr));
	key.port = port;
	*decision = POLICY_DECISION_NONE;
	if (port == DOT_PORT) {
		key.transport = TRANSPORT_DOT;
		present = bpf_map_lookup_elem(&endpoint6_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = lookup_endpoint6_cidr_allow_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*decision = POLICY_DECISION_BLOCK;
		}
		present = lookup_endpoint6_cidr_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present || policy->block_all_resolvers) {
			*decision = POLICY_DECISION_BLOCK;
		}
		*transport_out = TRANSPORT_DOT;
		return 1;
	}
	if (port == HTTPS_PORT) {
		key.transport = TRANSPORT_DOH;
		present = bpf_map_lookup_elem(&endpoint6_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = lookup_endpoint6_cidr_allow_rule(addr, port, TRANSPORT_DOH, policy->policy_mask);
		if (present) {
			*decision = POLICY_DECISION_ALLOW;
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
		if (!policy_rule_active(present, policy->policy_mask)) {
			present = lookup_endpoint6_cidr_rule(addr, port, TRANSPORT_DOH, policy->policy_mask);
		}
		if (!policy_rule_active(present, policy->policy_mask)) {
			return 0;
		}
		*decision = POLICY_DECISION_BLOCK;
		*transport_out = TRANSPORT_DOH;
		return 1;
	}
	return 0;
}

static __always_inline int evaluate_resolver4(struct bpf_sock_addr *ctx, __u32 addr, __u16 port, __u8 hook)
{
	struct policy_guard guard = {0};
	struct policy_snapshot policy;
	__u8 transport;
	__u8 decision;
	int verdict = 1;

	if (!acquire_policy_guard(&guard)) {
		return 1;
	}
	policy = (struct policy_snapshot){
		.block_enabled = guard.cfg.block_enabled,
		.block_all_resolvers = guard.cfg.block_all_resolvers,
		.policy_mask = guard.cfg.active_policy_slot ? 2 : 1,
	};
	if (classify_endpoint4(addr, port, &policy, &transport, &decision)) {
		if (policy.block_enabled && decision == POLICY_DECISION_BLOCK) {
			verdict = emit_resolver_event(ctx, EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV4,
				port, &addr, sizeof(addr), hook, decision);
		} else {
			emit_resolver_event(ctx, EVENT_RESOLVER, transport, FAMILY_IPV4,
				port, &addr, sizeof(addr), hook, decision);
		}
	}
	release_policy_guard(&guard);
	return verdict;
}

static __always_inline int evaluate_resolver6(struct bpf_sock_addr *ctx, const __u8 addr[16], __u16 port, __u8 hook)
{
	struct policy_guard guard = {0};
	struct policy_snapshot policy;
	__u8 transport;
	__u8 decision;
	int verdict = 1;

	if (!acquire_policy_guard(&guard)) {
		return 1;
	}
	policy = (struct policy_snapshot){
		.block_enabled = guard.cfg.block_enabled,
		.block_all_resolvers = guard.cfg.block_all_resolvers,
		.policy_mask = guard.cfg.active_policy_slot ? 2 : 1,
	};
	if (classify_endpoint6(addr, port, &policy, &transport, &decision)) {
		if (policy.block_enabled && decision == POLICY_DECISION_BLOCK) {
			verdict = emit_resolver_event(ctx, EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV6,
				port, addr, 16, hook, decision);
		} else {
			emit_resolver_event(ctx, EVENT_RESOLVER, transport, FAMILY_IPV6,
				port, addr, 16, hook, decision);
		}
	}
	release_policy_guard(&guard);
	return verdict;
}

static __always_inline int ipv6_mapped_ipv4(const __u8 addr[16], __u32 *ipv4)
{
	if (addr[0] || addr[1] || addr[2] || addr[3] || addr[4] || addr[5] ||
	    addr[6] || addr[7] || addr[8] || addr[9] || addr[10] != 0xff || addr[11] != 0xff) {
		return 0;
	}
	__builtin_memcpy(ipv4, &addr[12], sizeof(*ipv4));
	return 1;
}

static __always_inline int trace_dns_with_policy(struct __sk_buff *skb, const struct settings *cfg)
{
	__u32 packet_len = skb->len;
	__u32 zero = 0;
	struct dns_parse_result *parsed = bpf_map_lookup_elem(&dns_scratch, &zero);
	struct policy_snapshot policy = {
		.block_enabled = cfg->block_enabled,
		.block_all_domains = cfg->block_all_domains,
		.block_all_resolvers = cfg->block_all_resolvers,
		.allow_suffix_rules_enabled = cfg->allow_suffixes_enabled,
		.block_suffix_rules_enabled = cfg->block_suffixes_enabled,
		.policy_mask = cfg->active_policy_slot ? 2 : 1,
	};
	__u8 version_ihl;
	__u8 version;

	if (!parsed) {
		return 1;
	}
	if (packet_len < 1) {
		return 1;
	}
	if (bpf_skb_load_bytes(skb, 0, &version_ihl, sizeof(version_ihl)) < 0) {
		return 1;
	}

	version = version_ihl >> 4;
	if (version == 4) {
		struct iphdr iph = {0};
		__u32 header_len;
		__u32 transport_offset;
		__u32 kind;
		__u32 decision;

		if (packet_len < sizeof(iph)) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0) {
			return 1;
		}

		header_len = (version_ihl & 0x0f) * 4;
		if (header_len < sizeof(iph) || header_len > packet_len) {
			return 1;
		}
		transport_offset = header_len;

		if (iph.protocol == IPPROTO_UDP) {
			struct udphdr udph = {0};
			__u32 payload_offset;

			if (transport_offset + sizeof(udph) > packet_len) {
				return 1;
			}
			if (bpf_skb_load_bytes(skb, transport_offset, &udph, sizeof(udph)) < 0) {
				return 1;
			}
			if (bpf_ntohs(udph.dest) != DNS_PORT) {
				return 1;
			}
			payload_offset = transport_offset + sizeof(udph);
			if (parse_dns_payload(skb, payload_offset, packet_len, parsed, &policy) < 0) {
				/* Fragmented or malformed UDP DNS cannot be matched against the
				 * policy map. Block mode fails closed; observe mode passes it.
				 */
				return policy.block_enabled ? 0 : 1;
			}
			kind = dns_event_kind(parsed, &policy, &decision);
			struct dns_emit_context emit = {
				.key = &parsed->key, .kind = kind, .decision = decision, .transport = TRANSPORT_UDP,
			};
			return emit_dns4_event(skb, &emit, iph.daddr);
		}
		if (iph.protocol == IPPROTO_TCP) {
			struct tcphdr tcph = {0};
			__u32 tcp_len;
			__u32 payload_offset;
			int dns_parse;

			if (transport_offset + sizeof(tcph) > packet_len) {
				return 1;
			}
			if (bpf_skb_load_bytes(skb, transport_offset, &tcph, sizeof(tcph)) < 0) {
				return 1;
			}
			if (bpf_ntohs(tcph.dest) != DNS_PORT) {
				return 1;
			}

			tcp_len = tcph.doff * 4;
			payload_offset = transport_offset + tcp_len;
			if (tcp_len < sizeof(tcph) || payload_offset > packet_len) {
				return 1;
			}
			dns_parse = parse_tcp_dns_payload(skb, payload_offset, packet_len, parsed, &policy);
			if (dns_parse != DNS_PARSE_OK) {
				/* Segmented or malformed TCP DNS cannot be matched against the
				 * policy map. Block mode fails closed; observe mode passes it.
				 */
				return dns_parse == DNS_PARSE_DROP ? 0 : 1;
			}
			kind = dns_event_kind(parsed, &policy, &decision);
			struct dns_emit_context emit = {
				.key = &parsed->key, .kind = kind, .decision = decision, .transport = TRANSPORT_TCP,
			};
			return emit_dns4_event(skb, &emit, iph.daddr);
		}
		return 1;
	}

	if (version == 6) {
		struct ipv6hdr ip6h = {0};
		__u32 transport_offset = sizeof(ip6h);
		__u8 nexthdr;
		__u8 fragmented;
		__u32 kind;
		__u32 decision;
		int ext_parse;

		if (packet_len < sizeof(ip6h)) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h)) < 0) {
			return 1;
		}
		nexthdr = ip6h.nexthdr;
		ext_parse = parse_ipv6_transport(skb, packet_len, &nexthdr, &transport_offset, &fragmented);
		if (ext_parse == IPV6_EXT_HEADERS_EXHAUSTED) {
			/* The transport is unknown, so a longer chain could hide DNS. */
			return policy.block_enabled ? 0 : 1;
		}
		if (ext_parse < 0) {
			return 1;
		}
		if (fragmented) {
			return block_fragmented_ipv6_dns(skb, transport_offset, packet_len, nexthdr, policy.block_enabled);
		}

		if (nexthdr == IPPROTO_UDP) {
			struct udphdr udph = {0};
			__u32 payload_offset;

			if (transport_offset + sizeof(udph) > packet_len) {
				return 1;
			}
			if (bpf_skb_load_bytes(skb, transport_offset, &udph, sizeof(udph)) < 0) {
				return 1;
			}
			if (bpf_ntohs(udph.dest) != DNS_PORT) {
				return 1;
			}
			payload_offset = transport_offset + sizeof(udph);
			if (parse_dns_payload(skb, payload_offset, packet_len, parsed, &policy) < 0) {
				return policy.block_enabled ? 0 : 1;
			}
			kind = dns_event_kind(parsed, &policy, &decision);
			struct dns_emit_context emit = {
				.key = &parsed->key, .kind = kind, .decision = decision, .transport = TRANSPORT_UDP,
			};
			return emit_dns6_event(skb, &emit, ip6h.daddr.s6_addr);
		}
		if (nexthdr == IPPROTO_TCP) {
			struct tcphdr tcph = {0};
			__u32 tcp_len;
			__u32 payload_offset;
			int dns_parse;

			if (transport_offset + sizeof(tcph) > packet_len) {
				return 1;
			}
			if (bpf_skb_load_bytes(skb, transport_offset, &tcph, sizeof(tcph)) < 0) {
				return 1;
			}
			if (bpf_ntohs(tcph.dest) != DNS_PORT) {
				return 1;
			}

			tcp_len = tcph.doff * 4;
			payload_offset = transport_offset + tcp_len;
			if (tcp_len < sizeof(tcph) || payload_offset > packet_len) {
				return 1;
			}
			dns_parse = parse_tcp_dns_payload(skb, payload_offset, packet_len, parsed, &policy);
			if (dns_parse != DNS_PARSE_OK) {
				return dns_parse == DNS_PARSE_DROP ? 0 : 1;
			}
			kind = dns_event_kind(parsed, &policy, &decision);
			struct dns_emit_context emit = {
				.key = &parsed->key, .kind = kind, .decision = decision, .transport = TRANSPORT_TCP,
			};
			return emit_dns6_event(skb, &emit, ip6h.daddr.s6_addr);
		}
	}

	return 1;
}

SEC("cgroup_skb/egress")
int trace_dns(struct __sk_buff *skb)
{
	struct policy_guard guard = {0};
	int verdict;

	if (!acquire_policy_guard(&guard)) {
		return 1;
	}
	verdict = trace_dns_with_policy(skb, &guard.cfg);
	release_policy_guard(&guard);
	return verdict;
}

SEC("cgroup_skb/ingress")
int trace_connection_ingress(struct __sk_buff *skb)
{
	__u32 packet_len = skb->len;
	__u8 version_ihl;
	__u8 version;

	if (packet_len < 1) {
		return 1;
	}
	if (bpf_skb_load_bytes(skb, 0, &version_ihl, sizeof(version_ihl)) < 0) {
		return 1;
	}

	version = version_ihl >> 4;
	if (version == 4) {
		struct iphdr iph = {0};
		struct connection_event_params params = {0};
		struct tcphdr tcph = {0};
		struct listener_info_value *listener;
		__u32 header_len;
		__u32 transport_offset;
		__u16 port;
		__u16 local_port;

		if (packet_len < sizeof(iph)) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0) {
			return 1;
		}
		if (iph.protocol != IPPROTO_TCP) {
			return 1;
		}

		header_len = (version_ihl & 0x0f) * 4;
		if (header_len < sizeof(iph) || header_len > packet_len) {
			return 1;
		}
		transport_offset = header_len;
		if (transport_offset + sizeof(tcph) > packet_len) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, transport_offset, &tcph, sizeof(tcph)) < 0) {
			return 1;
		}
		if (!tcph.syn || tcph.ack) {
			return 1;
		}

		port = bpf_ntohs(tcph.source);
		local_port = bpf_ntohs(tcph.dest);
		listener = lookup_listener_info(FAMILY_IPV4, SOCKET_PROTOCOL_TCP, local_port, &iph.daddr);
		params.direction = DIRECTION_INBOUND;
		params.family = FAMILY_IPV4;
		params.protocol = SOCKET_PROTOCOL_TCP;
		params.hook = SOCKET_HOOK_CGROUP_SKB_INGRESS;
		params.attribution = ATTRIBUTION_KERNEL_INGRESS;
		params.port = port;
		params.local_port = local_port;
		copy_socket_addr(params.addr, FAMILY_IPV4, &iph.saddr);
		copy_socket_addr(params.local_addr, FAMILY_IPV4, &iph.daddr);
		return emit_connection_event_identity(&params, listener, 0);
	}

	if (version == 6) {
		struct connection_event_params params = {0};
		struct ipv6hdr ip6h = {0};
		struct tcphdr tcph = {0};
		struct listener_info_value *listener;
		__u32 transport_offset = sizeof(ip6h);
		__u8 nexthdr;
		__u8 fragmented;
		__u16 port;
		__u16 local_port;

		if (packet_len < sizeof(ip6h)) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h)) < 0) {
			return 1;
		}
		nexthdr = ip6h.nexthdr;
		if (parse_ipv6_transport(skb, packet_len, &nexthdr, &transport_offset, &fragmented) < 0 || fragmented || nexthdr != IPPROTO_TCP) {
			return 1;
		}
		if (transport_offset + sizeof(tcph) > packet_len) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, transport_offset, &tcph, sizeof(tcph)) < 0) {
			return 1;
		}
		if (!tcph.syn || tcph.ack) {
			return 1;
		}

		port = bpf_ntohs(tcph.source);
		local_port = bpf_ntohs(tcph.dest);
		listener = lookup_listener_info(FAMILY_IPV6, SOCKET_PROTOCOL_TCP, local_port, ip6h.daddr.s6_addr);
		params.direction = DIRECTION_INBOUND;
		params.family = FAMILY_IPV6;
		params.protocol = SOCKET_PROTOCOL_TCP;
		params.hook = SOCKET_HOOK_CGROUP_SKB_INGRESS;
		params.attribution = ATTRIBUTION_KERNEL_INGRESS;
		params.port = port;
		params.local_port = local_port;
		copy_socket_addr(params.addr, FAMILY_IPV6, ip6h.saddr.s6_addr);
		copy_socket_addr(params.local_addr, FAMILY_IPV6, ip6h.daddr.s6_addr);
		return emit_connection_event_identity(&params, listener, 0);
	}

	return 1;
}

SEC("cgroup/sendmsg4")
int trace_sendmsg4(struct bpf_sock_addr *ctx)
{
	struct connection_event_params params = {0};
	struct bpf_sock *sk;
	__u32 local_addr = 0;
	__u32 user_ip4;
	__u32 protocol;
	__u32 user_port;
	__u16 port;
	__u16 local_port = 0;
	int have_local;

	protocol = ctx->protocol;
	user_port = ctx->user_port;
	user_ip4 = ctx->user_ip4;
	sk = ctx->sk;
	if (protocol != IPPROTO_UDP) {
		return 1;
	}

	port = bpf_ntohs((__u16)user_port);
	have_local = load_sock_local4(sk, &local_addr, &local_port);
	params.direction = DIRECTION_OUTBOUND;
	params.family = FAMILY_IPV4;
	params.protocol = SOCKET_PROTOCOL_UDP;
	params.hook = SOCKET_HOOK_CGROUP_SENDMSG4;
	params.attribution = ATTRIBUTION_KERNEL_SENDMSG;
	params.port = port;
	params.local_port = local_port;
	copy_socket_addr(params.addr, FAMILY_IPV4, &user_ip4);
	copy_socket_addr(params.local_addr, FAMILY_IPV4, have_local ? &local_addr : 0);
	if (!evaluate_egress4(ctx, &params, user_ip4)) {
		return 0;
	}
	emit_connection_event_current(&params, EVENT_SOURCE_CGROUP_SOCK_ADDR,
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
		bpf_get_socket_cookie(ctx)
#else
		0
#endif
	);
	if (port == DNS_PORT) {
		cache_socket_info(FAMILY_IPV4, SOCKET_PROTOCOL_UDP, port, &user_ip4, SOCKET_HOOK_CGROUP_SENDMSG4);
	}
	return 1;
}

SEC("cgroup/sendmsg6")
int trace_sendmsg6(struct bpf_sock_addr *ctx)
{
	struct connection_event_params params = {0};
	__u8 addr[16];
	__u8 local_addr[16] = {0};
	struct bpf_sock *sk;
	__u32 protocol;
	__u32 user_port;
	__u32 user_ip6_0;
	__u32 user_ip6_1;
	__u32 user_ip6_2;
	__u32 user_ip6_3;
	__u16 port;
	__u16 local_port = 0;
	int have_local;

	protocol = ctx->protocol;
	user_port = ctx->user_port;
	sk = ctx->sk;
	user_ip6_0 = ctx->user_ip6[0];
	user_ip6_1 = ctx->user_ip6[1];
	user_ip6_2 = ctx->user_ip6[2];
	user_ip6_3 = ctx->user_ip6[3];
	((__u32 *)addr)[0] = user_ip6_0;
	((__u32 *)addr)[1] = user_ip6_1;
	((__u32 *)addr)[2] = user_ip6_2;
	((__u32 *)addr)[3] = user_ip6_3;
	if (protocol != IPPROTO_UDP) {
		return 1;
	}

	port = bpf_ntohs((__u16)user_port);
	have_local = load_sock_local6(sk, local_addr, &local_port);
	params.direction = DIRECTION_OUTBOUND;
	params.family = FAMILY_IPV6;
	params.protocol = SOCKET_PROTOCOL_UDP;
	params.hook = SOCKET_HOOK_CGROUP_SENDMSG6;
	params.attribution = ATTRIBUTION_KERNEL_SENDMSG;
	params.port = port;
	params.local_port = local_port;
	copy_socket_addr(params.addr, FAMILY_IPV6, addr);
	copy_socket_addr(params.local_addr, FAMILY_IPV6, have_local ? local_addr : 0);
	if (!evaluate_egress6(ctx, &params, addr)) {
		return 0;
	}
	emit_connection_event_current(&params, EVENT_SOURCE_CGROUP_SOCK_ADDR,
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
		bpf_get_socket_cookie(ctx)
#else
		0
#endif
	);
	if (port == DNS_PORT) {
		cache_socket_info(FAMILY_IPV6, SOCKET_PROTOCOL_UDP, port, addr, SOCKET_HOOK_CGROUP_SENDMSG6);
	}
	return 1;
}

SEC("cgroup/connect4")
int trace_connect4(struct bpf_sock_addr *ctx)
{
	struct connection_event_params params = {0};
	struct bpf_sock *sk;
	__u32 local_addr = 0;
	__u32 user_ip4;
	__u32 protocol;
	__u32 user_port;
	__u16 port;
	__u16 local_port = 0;
	int have_local;

	protocol = ctx->protocol;
	user_port = ctx->user_port;
	user_ip4 = ctx->user_ip4;
	sk = ctx->sk;
	if (protocol != IPPROTO_TCP) {
		return 1;
	}

	port = bpf_ntohs((__u16)user_port);
	have_local = load_sock_local4(sk, &local_addr, &local_port);
	params.direction = DIRECTION_OUTBOUND;
	params.family = FAMILY_IPV4;
	params.protocol = SOCKET_PROTOCOL_TCP;
	params.hook = SOCKET_HOOK_CGROUP_CONNECT4;
	params.attribution = ATTRIBUTION_KERNEL_CONNECT;
	params.port = port;
	params.local_port = local_port;
	copy_socket_addr(params.addr, FAMILY_IPV4, &user_ip4);
	copy_socket_addr(params.local_addr, FAMILY_IPV4, have_local ? &local_addr : 0);
	if (!evaluate_egress4(ctx, &params, user_ip4)) {
		return 0;
	}
	emit_connection_event_current(&params, EVENT_SOURCE_CGROUP_SOCK_ADDR,
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
		bpf_get_socket_cookie(ctx)
#else
		0
#endif
	);
	if (port == DNS_PORT) {
		cache_socket_info(FAMILY_IPV4, SOCKET_PROTOCOL_TCP, port, &user_ip4, SOCKET_HOOK_CGROUP_CONNECT4);
	}
	return evaluate_resolver4(ctx, user_ip4, port, SOCKET_HOOK_CGROUP_CONNECT4);
}

SEC("cgroup/connect6")
int trace_connect6(struct bpf_sock_addr *ctx)
{
	struct connection_event_params params = {0};
	struct bpf_sock *sk;
	__u32 protocol;
	__u32 user_port;
	__u32 user_ip6_0;
	__u32 user_ip6_1;
	__u32 user_ip6_2;
	__u32 user_ip6_3;
	__u16 port;
	__u8 addr[16];
	__u8 local_addr[16] = {0};
	__u32 mapped_ipv4 = 0;
	__u16 local_port = 0;
	int have_local;

	protocol = ctx->protocol;
	user_port = ctx->user_port;
	sk = ctx->sk;
	user_ip6_0 = ctx->user_ip6[0];
	user_ip6_1 = ctx->user_ip6[1];
	user_ip6_2 = ctx->user_ip6[2];
	user_ip6_3 = ctx->user_ip6[3];
	((__u32 *)addr)[0] = user_ip6_0;
	((__u32 *)addr)[1] = user_ip6_1;
	((__u32 *)addr)[2] = user_ip6_2;
	((__u32 *)addr)[3] = user_ip6_3;
	if (protocol != IPPROTO_TCP) {
		return 1;
	}

	port = bpf_ntohs((__u16)user_port);
	have_local = load_sock_local6(sk, local_addr, &local_port);
	params.direction = DIRECTION_OUTBOUND;
	params.family = FAMILY_IPV6;
	params.protocol = SOCKET_PROTOCOL_TCP;
	params.hook = SOCKET_HOOK_CGROUP_CONNECT6;
	params.attribution = ATTRIBUTION_KERNEL_CONNECT;
	params.port = port;
	params.local_port = local_port;
	copy_socket_addr(params.addr, FAMILY_IPV6, addr);
	copy_socket_addr(params.local_addr, FAMILY_IPV6, have_local ? local_addr : 0);
	if (!evaluate_egress6(ctx, &params, addr)) {
		return 0;
	}
	emit_connection_event_current(&params, EVENT_SOURCE_CGROUP_SOCK_ADDR,
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
		bpf_get_socket_cookie(ctx)
#else
		0
#endif
	);
	if (port == DNS_PORT) {
		cache_socket_info(FAMILY_IPV6, SOCKET_PROTOCOL_TCP, port, addr, SOCKET_HOOK_CGROUP_CONNECT6);
	}
	if (ipv6_mapped_ipv4(addr, &mapped_ipv4)) {
		return evaluate_resolver4(ctx, mapped_ipv4, port, SOCKET_HOOK_CGROUP_CONNECT6);
	}
	return evaluate_resolver6(ctx, addr, port, SOCKET_HOOK_CGROUP_CONNECT6);
}

SEC("cgroup/recvmsg4")
int trace_recvmsg4(struct bpf_sock_addr *ctx)
{
#if TRACEGUARD_CONNECTION_NO_RECVMSG
	(void)ctx;
	return 1;
#else
	struct connection_event_params params = {0};
	struct bpf_sock *sk;
	__u32 local_addr = 0;
	__u32 msg_src_ip4;
	__u32 protocol;
	__u16 port = 0;
	__u16 local_port = 0;
	int have_local;

	protocol = ctx->protocol;
	msg_src_ip4 = ctx->msg_src_ip4;
	sk = ctx->sk;
	if (protocol != IPPROTO_UDP) {
		return 1;
	}

	have_local = load_sock_local4(sk, &local_addr, &local_port);
	if (sk) {
		port = bpf_ntohs(sk->dst_port);
	}
	params.direction = DIRECTION_INBOUND;
	params.family = FAMILY_IPV4;
	params.protocol = SOCKET_PROTOCOL_UDP;
	params.hook = SOCKET_HOOK_CGROUP_RECVMSG4;
	params.attribution = ATTRIBUTION_KERNEL_RECVMSG;
	params.port = port;
	params.local_port = local_port;
	copy_socket_addr(params.addr, FAMILY_IPV4, &msg_src_ip4);
	copy_socket_addr(params.local_addr, FAMILY_IPV4, have_local ? &local_addr : 0);
	emit_connection_event_current(&params, EVENT_SOURCE_CGROUP_SOCK_ADDR,
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
		bpf_get_socket_cookie(ctx)
#else
		0
#endif
	);
	return 1;
#endif
}

SEC("cgroup/recvmsg6")
int trace_recvmsg6(struct bpf_sock_addr *ctx)
{
#if TRACEGUARD_CONNECTION_NO_RECVMSG
	(void)ctx;
	return 1;
#else
	struct connection_event_params params = {0};
	__u8 addr[16] = {0};
	__u8 local_addr[16] = {0};
	struct bpf_sock *sk;
	__u32 protocol;
	__u32 msg_src_ip6_0;
	__u32 msg_src_ip6_1;
	__u32 msg_src_ip6_2;
	__u32 msg_src_ip6_3;
	__u16 port = 0;
	__u16 local_port = 0;
	int have_local;

	protocol = ctx->protocol;
	sk = ctx->sk;
	msg_src_ip6_0 = ctx->msg_src_ip6[0];
	msg_src_ip6_1 = ctx->msg_src_ip6[1];
	msg_src_ip6_2 = ctx->msg_src_ip6[2];
	msg_src_ip6_3 = ctx->msg_src_ip6[3];
	((__u32 *)addr)[0] = msg_src_ip6_0;
	((__u32 *)addr)[1] = msg_src_ip6_1;
	((__u32 *)addr)[2] = msg_src_ip6_2;
	((__u32 *)addr)[3] = msg_src_ip6_3;
	if (protocol != IPPROTO_UDP) {
		return 1;
	}

	have_local = load_sock_local6(sk, local_addr, &local_port);
	if (sk) {
		port = bpf_ntohs(sk->dst_port);
	}
	params.direction = DIRECTION_INBOUND;
	params.family = FAMILY_IPV6;
	params.protocol = SOCKET_PROTOCOL_UDP;
	params.hook = SOCKET_HOOK_CGROUP_RECVMSG6;
	params.attribution = ATTRIBUTION_KERNEL_RECVMSG;
	params.port = port;
	params.local_port = local_port;
	copy_socket_addr(params.addr, FAMILY_IPV6, addr);
	copy_socket_addr(params.local_addr, FAMILY_IPV6, have_local ? local_addr : 0);
	emit_connection_event_current(&params, EVENT_SOURCE_CGROUP_SOCK_ADDR,
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
		bpf_get_socket_cookie(ctx)
#else
		0
#endif
	);
	return 1;
#endif
}

SEC("cgroup/bind4")
int trace_bind4(struct bpf_sock_addr *ctx)
{
	__u8 protocol = socket_protocol_from_ipproto(ctx->protocol);

	if (protocol == 0) {
		return 1;
	}
	return evaluate_bind4(ctx, ctx->user_ip4, protocol, bpf_ntohs((__u16)ctx->user_port),
		SOCKET_HOOK_CGROUP_BIND4);
}

SEC("cgroup/bind6")
int trace_bind6(struct bpf_sock_addr *ctx)
{
	__u8 addr[16];
	__u8 protocol = socket_protocol_from_ipproto(ctx->protocol);

	if (protocol == 0) {
		return 1;
	}
	__builtin_memcpy(addr, ctx->user_ip6, sizeof(addr));
	/*
	 * A wildcard "::" bind on a dual-stack socket also accepts IPv4, so it
	 * must pass IPv4 wildcard policy too. The hook cannot see IPV6_V6ONLY,
	 * so v6-only wildcard binds are checked the same way (fail closed).
	 */
	if (!((__u32 *)addr)[0] && !((__u32 *)addr)[1] && !((__u32 *)addr)[2] && !((__u32 *)addr)[3] &&
	    !evaluate_bind4(ctx, 0, protocol, bpf_ntohs((__u16)ctx->user_port), SOCKET_HOOK_CGROUP_BIND6)) {
		return 0;
	}
	return evaluate_bind6(ctx, addr, protocol, bpf_ntohs((__u16)ctx->user_port));
}

SEC("cgroup/post_bind4")
int trace_post_bind4(struct bpf_sock *sk)
{
	__u8 protocol = socket_protocol_from_ipproto(sk->protocol);

	if (sk->family != AF_INET || protocol == 0 || sk->src_port == 0) {
		return 1;
	}

	cache_listener_info(FAMILY_IPV4, protocol, (__u16)sk->src_port, &sk->src_ip4);
	return 1;
}

SEC("cgroup/post_bind6")
int trace_post_bind6(struct bpf_sock *sk)
{
	__u8 addr[16];
	__u8 protocol = socket_protocol_from_ipproto(sk->protocol);

	if (sk->family != AF_INET6 || protocol == 0 || sk->src_port == 0) {
		return 1;
	}

	__builtin_memcpy(addr, sk->src_ip6, sizeof(addr));
	cache_listener_info(FAMILY_IPV6, protocol, (__u16)sk->src_port, addr);
	return 1;
}

/*
 * BPF LSM programs receive a single context pointer to the hook arguments,
 * followed by the return value of any earlier BPF LSM program. The programs
 * are not sleepable because the path policy maps are LPM tries, which the
 * verifier rejects in sleepable programs; bpf_d_path remains available because
 * both hooks are in the kernel's sleepable-hook allowlist.
 */
SEC("lsm/bprm_check_security")
int lsm_bprm_check_security(unsigned long long *ctx)
{
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[0];
	int ret = (int)ctx[1];
	struct policy_guard guard = {0};
	const struct settings *cfg;
	struct file *file;
	int verdict;

	if (ret != 0) {
		return ret;
	}
	if (!acquire_policy_guard(&guard)) {
		return 0;
	}
	cfg = &guard.cfg;
	if (!cfg->exec_enabled || daemon_is_exempt(cfg)) {
		release_policy_guard(&guard);
		return 0;
	}
	file = bprm ? bprm->file : 0;
	verdict = evaluate_lsm_path(file, cfg, PATH_DOMAIN_EXEC, FILE_ACCESS_ANY, 0);
	release_policy_guard(&guard);
	return verdict;
}

SEC("lsm/file_open")
int lsm_file_open(unsigned long long *ctx)
{
	struct file *file = (struct file *)ctx[0];
	int ret = (int)ctx[1];
	struct policy_guard guard = {0};
	const struct settings *cfg;
	__u32 flags;
	__u8 access;
	int verdict;

	if (ret != 0) {
		return ret;
	}
	if (!acquire_policy_guard(&guard)) {
		return 0;
	}
	cfg = &guard.cfg;
	if (!cfg->file_enabled || daemon_is_exempt(cfg) || !file) {
		release_policy_guard(&guard);
		return 0;
	}
	flags = file->f_flags;
	if ((flags & TRACEGUARD_O_ACCMODE) == TRACEGUARD_O_RDWR) {
		access = FILE_ACCESS_READ_WRITE;
	} else if ((flags & TRACEGUARD_O_ACCMODE) == TRACEGUARD_O_RDONLY &&
		(flags & (TRACEGUARD_O_CREAT | TRACEGUARD_O_TRUNC)) == 0) {
		access = FILE_ACCESS_READ;
	} else {
		access = FILE_ACCESS_WRITE;
	}
	verdict = evaluate_lsm_path(file, cfg, PATH_DOMAIN_FILE, access, flags);
	release_policy_guard(&guard);
	return verdict;
}

static __always_inline void copy_exec_argv(struct event *event, const char *const *argv)
{
	struct exec_argv_scratch *scratch;
	__u32 zero = 0;
	__u32 offset = 0;
	__u16 argc = 0;

	if (!argv) {
		return;
	}
	scratch = bpf_map_lookup_elem(&exec_argv_scratch, &zero);
	if (!scratch) {
		return;
	}
	for (__u32 index = 0; index < EXEC_ARGV_MAX; index++) {
		const char *arg = 0;
		long copied;

		if (bpf_probe_read_user(&arg, sizeof(arg), &argv[index]) != 0 || !arg) {
			break;
		}
		if (offset >= EXEC_ARGV_BYTES) {
			event->file_flags |= EXEC_ARGV_TRUNCATED;
			break;
		}
		copied = bpf_probe_read_user_str(&scratch->buf[offset & (EXEC_ARGV_BYTES - 1)], EXEC_ARGV_BYTES, arg);
		if (copied <= 0) {
			break;
		}
		if (copied == EXEC_ARGV_BYTES) {
			/* The read filled its limit, so the argument is either exactly
			 * EXEC_ARGV_BYTES - 1 bytes long or was cut at that length.
			 */
			char next = 0;

			if (bpf_probe_read_user(&next, sizeof(next), arg + EXEC_ARGV_BYTES - 1) != 0 || next) {
				event->file_flags |= EXEC_ARGV_TRUNCATED;
			}
		}
		offset += (__u32)copied;
		argc++;
		if (index == EXEC_ARGV_MAX - 1) {
			if (bpf_probe_read_user(&arg, sizeof(arg), &argv[index + 1]) == 0 && arg) {
				event->file_flags |= EXEC_ARGV_TRUNCATED;
			}
		}
	}
	if (offset > EXEC_ARGV_BYTES) {
		/* The last argument runs past the bytes the event carries. One that
		 * ends exactly at the limit fits with its terminator.
		 */
		event->file_flags |= EXEC_ARGV_TRUNCATED;
	}
	__builtin_memcpy(event->domain, scratch->buf, sizeof(event->domain));
	event->domain[sizeof(event->domain) - 1] = 0;
	event->port = argc;
}

static __always_inline int emit_exec_event(__u32 syscall, const char *filename, const char *const *argv, __u64 dirfd, __u64 flags)
{
	struct event *event = reserve_event(EVENT_EXEC);

	if (!event) {
		return 0;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, EVENT_EXEC, 0, EVENT_SOURCE_SYSCALL_TRACEPOINT);
	event->rule_id = syscall;
	event->file_mode = (__u32)dirfd;
	event->file_flags = (__u32)flags & ~EXEC_ARGV_TRUNCATED;
	if (filename) {
		bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
	}
	copy_exec_argv(event, argv);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int emit_file_access_event(const char *filename, __u64 flags, __u64 mode)
{
	struct event *event = reserve_event(EVENT_FILE_ACCESS);

	if (!event) {
		return 0;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, EVENT_FILE_ACCESS, 0, EVENT_SOURCE_SYSCALL_TRACEPOINT);
	event->file_flags = (__u32)flags;
	event->file_mode = (__u32)mode;
	if (filename) {
		bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline struct event *start_security_event(__u32 kind, __u32 operation)
{
	struct event *event = reserve_event(kind);

	if (!event) {
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, 0, EVENT_SOURCE_SYSCALL_TRACEPOINT);
	event->rule_id = operation;
	return event;
}

static __always_inline int emit_security_ids(__u32 kind, __u32 operation, __u64 flags, __u64 argument)
{
	struct event *event = start_security_event(kind, operation);

	if (!event) {
		return 0;
	}
	event->file_flags = (__u32)flags;
	event->file_mode = (__u32)argument;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
	struct event *event = start_security_event(EVENT_MEMFD_CREATE, 0);

	if (!event) {
		return 0;
	}
	event->file_flags = (__u32)ctx->args[1];
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const char *)ctx->args[0]);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* Only requests that attach to, or write into, another process are emitted;
 * tracers issue other requests at very high rates.
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	unsigned long request = ctx->args[0];

	switch (request) {
	case TRACEGUARD_PTRACE_TRACEME:
	case TRACEGUARD_PTRACE_POKETEXT:
	case TRACEGUARD_PTRACE_POKEDATA:
	case TRACEGUARD_PTRACE_POKEUSER:
	case TRACEGUARD_PTRACE_ATTACH:
	case TRACEGUARD_PTRACE_SEIZE:
		return emit_security_ids(EVENT_PTRACE, (__u32)request, 0, ctx->args[1]);
	default:
		return 0;
	}
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int trace_process_vm_readv(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PROCESS_VM, PROCESS_VM_READ, 0, ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int trace_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PROCESS_VM, PROCESS_VM_WRITE, 0, ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
	struct event *event = start_security_event(EVENT_MODULE_LOAD, MODULE_LOAD_INIT);

	if (!event) {
		return 0;
	}
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const char *)ctx->args[2]);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	struct event *event = start_security_event(EVENT_MODULE_LOAD, MODULE_LOAD_FINIT);

	if (!event) {
		return 0;
	}
	event->file_mode = (__u32)ctx->args[0];
	event->file_flags = (__u32)ctx->args[2];
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const char *)ctx->args[1]);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* Map and object operations are routine for BPF tooling; only program loads
 * are emitted.
 */
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
	__u32 prog_type = 0;

	if (ctx->args[0] != TRACEGUARD_BPF_PROG_LOAD) {
		return 0;
	}
	bpf_probe_read_user(&prog_type, sizeof(prog_type), (const void *)ctx->args[1]);
	return emit_security_ids(EVENT_BPF_PROG_LOAD, TRACEGUARD_BPF_PROG_LOAD, 0, prog_type);
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int trace_io_uring_setup(struct trace_event_raw_sys_enter *ctx)
{
	__u32 flags = 0;

	/* struct io_uring_params begins with sq_entries, cq_entries, flags. */
	bpf_probe_read_user(&flags, sizeof(flags), (const char *)ctx->args[1] + 2 * sizeof(__u32));
	return emit_security_ids(EVENT_IO_URING_SETUP, 0, flags, ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx)
{
	struct event *event = start_security_event(EVENT_MOUNT, 0);

	if (!event) {
		return 0;
	}
	event->file_flags = (__u32)ctx->args[3];
	bpf_probe_read_user_str(event->domain, MOUNT_SOURCE_LEN, (const char *)ctx->args[0]);
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const char *)ctx->args[1]);
	bpf_probe_read_user_str(event->domain + MOUNT_FSTYPE_OFFSET, sizeof(event->domain) - MOUNT_FSTYPE_OFFSET,
		(const char *)ctx->args[2]);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_NAMESPACE_CHANGE, NAMESPACE_SETNS, ctx->args[1], ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_NAMESPACE_CHANGE, NAMESPACE_UNSHARE, ctx->args[0], 0);
}

/* For the set*id family file_mode carries the requested effective ID, or
 * 0xffffffff when the call leaves it unchanged.
 */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PRIVILEGE_CHANGE, PRIVILEGE_SETUID, 0, ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PRIVILEGE_CHANGE, PRIVILEGE_SETGID, 0, ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PRIVILEGE_CHANGE, PRIVILEGE_SETREUID, 0, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_setregid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PRIVILEGE_CHANGE, PRIVILEGE_SETREGID, 0, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PRIVILEGE_CHANGE, PRIVILEGE_SETRESUID, 0, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_security_ids(EVENT_PRIVILEGE_CHANGE, PRIVILEGE_SETRESGID, 0, ctx->args[1]);
}

/* file_flags carries the low 32 bits of the requested effective set. */
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
	__u32 effective = 0;

	bpf_probe_read_user(&effective, sizeof(effective), (const void *)ctx->args[1]);
	return emit_security_ids(EVENT_PRIVILEGE_CHANGE, PRIVILEGE_CAPSET, effective, 0);
}

static __always_inline int emit_file_change(__u32 operation, __u64 dirfd, const char *path, __u64 flags, __u64 value)
{
	struct event *event = reserve_event(EVENT_FILE_CHANGE);

	if (!event) {
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, EVENT_FILE_CHANGE, 0, EVENT_SOURCE_SYSCALL_TRACEPOINT);
	event->rule_id = operation;
	event->file_mode = (__u32)dirfd;
	event->file_flags = (__u32)flags;
	event->socket_cookie = value;
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), path);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int emit_file_rename(__u64 old_dirfd, const char *old_path, __u64 new_dirfd, const char *new_path, __u64 flags)
{
	struct event *event = reserve_event(EVENT_FILE_CHANGE);

	if (!event) {
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, EVENT_FILE_CHANGE, 0, EVENT_SOURCE_SYSCALL_TRACEPOINT);
	event->rule_id = FILE_CHANGE_RENAME;
	event->file_mode = (__u32)old_dirfd;
	event->file_flags = (__u32)flags;
	event->socket_cookie = (__u32)new_dirfd;
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), old_path);
	bpf_probe_read_user_str(event->domain, sizeof(event->domain), new_path);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

#define AT_FDCWD_ARG ((__u64)(__s64)TRACEGUARD_AT_FDCWD)

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_UNLINK, AT_FDCWD_ARG, (const char *)ctx->args[0], 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_UNLINK, ctx->args[0], (const char *)ctx->args[1], ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_rmdir(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_UNLINK, AT_FDCWD_ARG, (const char *)ctx->args[0], TRACEGUARD_AT_REMOVEDIR, 0);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_rename(AT_FDCWD_ARG, (const char *)ctx->args[0], AT_FDCWD_ARG, (const char *)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_rename(ctx->args[0], (const char *)ctx->args[1], ctx->args[2], (const char *)ctx->args[3], 0);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_rename(ctx->args[0], (const char *)ctx->args[1], ctx->args[2], (const char *)ctx->args[3], ctx->args[4]);
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_CHMOD, AT_FDCWD_ARG, (const char *)ctx->args[0], 0, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_CHMOD, ctx->args[0], (const char *)ctx->args[1], 0, ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int trace_fchmodat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_CHMOD, ctx->args[0], (const char *)ctx->args[1], ctx->args[3], ctx->args[2]);
}

static __always_inline __u64 owner_value(__u64 uid, __u64 gid)
{
	return (uid & 0xffffffffULL) | ((gid & 0xffffffffULL) << 32);
}

SEC("tracepoint/syscalls/sys_enter_chown")
int trace_chown(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_CHOWN, AT_FDCWD_ARG, (const char *)ctx->args[0], 0, owner_value(ctx->args[1], ctx->args[2]));
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int trace_lchown(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_CHOWN, AT_FDCWD_ARG, (const char *)ctx->args[0], TRACEGUARD_AT_SYMLINK_NOFOLLOW,
		owner_value(ctx->args[1], ctx->args[2]));
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_fchownat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_CHOWN, ctx->args[0], (const char *)ctx->args[1], ctx->args[4],
		owner_value(ctx->args[2], ctx->args[3]));
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_change(FILE_CHANGE_TRUNCATE, AT_FDCWD_ARG, (const char *)ctx->args[0], 0, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	return emit_exec_event(EXEC_SYSCALL_EXECVE, (const char *)ctx->args[0], (const char *const *)ctx->args[1],
		(__u64)(__s64)TRACEGUARD_AT_FDCWD, 0);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_exec_event(EXEC_SYSCALL_EXECVEAT, (const char *)ctx->args[1], (const char *const *)ctx->args[2],
		ctx->args[0], ctx->args[4]);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_access_event((const char *)ctx->args[0], ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_access_event((const char *)ctx->args[1], ctx->args[2], ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
	struct traceguard_open_how how = {0};
	__u64 flags = FILE_ACCESS_FLAG_UNKNOWN;

	if (bpf_probe_read_user(&how, sizeof(how), (const void *)ctx->args[2]) == 0) {
		flags = how.flags;
	}
	return emit_file_access_event((const char *)ctx->args[1], flags, how.mode);
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_file_access_event((const char *)ctx->args[0], TRACEGUARD_CREAT_FLAGS, ctx->args[1]);
}
