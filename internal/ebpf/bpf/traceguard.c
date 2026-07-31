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
#define MAX_FILENAME_LEN 256
#define EVENT_DNS 1
#define EVENT_BLOCKED 2
#define EVENT_EXEC 3
#define EVENT_RESOLVER 4
#define EVENT_RESOLVER_BLOCKED 5
#define EVENT_CONNECTION 6
#define EVENT_FILE_ACCESS 7
#define EVENT_EGRESS_BLOCKED 8
#define EVENT_EGRESS_WOULD_BLOCK 9
#define TRANSPORT_UDP 1
#define TRANSPORT_TCP 2
#define TRANSPORT_DOT 3
#define TRANSPORT_DOH 4
#define FAMILY_IPV4 4
#define FAMILY_IPV6 6
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
#define EVENT_SOURCE_SYSCALL_TRACEPOINT 1
#define EVENT_SOURCE_CGROUP_SKB 2
#define EVENT_SOURCE_CGROUP_SOCK_ADDR 3
#define EVENT_SOURCE_CGROUP_SOCK 4
#define KERNEL_FEATURE_SET_LEGACY 1
#define KERNEL_FEATURE_SET_LINUX71 2
#define UID_SOURCE_NONE 0
#define UID_SOURCE_KERNEL 1
#define SOCKET_INFO_MAX_ENTRIES 16384
#define LISTENER_INFO_MAX_ENTRIES 16384
#define CONNECTION_DEDUPE_MAX_ENTRIES 32768
#define CONNECTION_DEDUPE_WINDOW_NS 60000000000ULL
#define EGRESS_IDENTITY_BYTES 17
#define EGRESS_IDENTITY_GLOBAL 0
#define EGRESS_IDENTITY_UID 1
#define EGRESS_IDENTITY_CGROUP 2
#define EGRESS_IDENTITY_UID_CGROUP 3
#define FILE_ACCESS_FLAG_UNKNOWN (1U << 31)
#define TRACEGUARD_O_WRONLY 01
#define TRACEGUARD_O_CREAT 0100
#define TRACEGUARD_O_TRUNC 01000
#define TRACEGUARD_CREAT_FLAGS (TRACEGUARD_O_WRONLY | TRACEGUARD_O_CREAT | TRACEGUARD_O_TRUNC)

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

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
	__u8 _pad[7];
};

struct policy_snapshot {
	__u8 block_enabled;
	__u8 block_all_domains;
	__u8 block_all_resolvers;
	__u8 allow_suffix_rules_enabled;
	__u8 block_suffix_rules_enabled;
	__u8 policy_mask;
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
	__u32 pid;
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
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct settings);
} settings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_parse_result);
} dns_scratch SEC(".maps");

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

static __always_inline __u32 active_kernel_feature_set(void)
{
#if TRACEGUARD_LINUX71_TELEMETRY
	return KERNEL_FEATURE_SET_LINUX71;
#else
	return KERNEL_FEATURE_SET_LEGACY;
#endif
}

static __always_inline void init_event_base(struct event *event, __u32 kind, __u8 transport, __u32 source)
{
	event->timestamp_ns = bpf_ktime_get_boot_ns();
	event->kind = kind;
	event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	event->transport = transport;
	event->event_source = source;
	event->kernel_feature_set = active_kernel_feature_set();
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
	event->kernel_uid = (__u32)bpf_get_current_uid_gid();
	event->uid_source = UID_SOURCE_KERNEL;
	event->cgroup_id = bpf_get_current_cgroup_id();
#endif
}

static __always_inline void init_event(struct event *event, __u32 kind, __u8 transport, __u32 source)
{
	init_event_base(event, kind, transport, source);
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
	if (value) {
		__builtin_memcpy(event->comm, value->comm, sizeof(event->comm));
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

	value.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
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
	__u64 now = bpf_ktime_get_ns();

	key.pid = pid;
	key.port = params->port;
	key.local_port = params->local_port;
	key.family = params->family;
	key.protocol = params->protocol;
	key.direction = params->direction;
	copy_socket_addr(key.addr, params->family, params->addr);
	copy_socket_addr(key.local_addr, params->family, params->local_addr);

	existing = bpf_map_lookup_elem(&connection_dedupe, &key);
	if (existing && now >= existing->last_seen_ns && now - existing->last_seen_ns < CONNECTION_DEDUPE_WINDOW_NS) {
		return 0;
	}

	value.last_seen_ns = now;
	bpf_map_update_elem(&connection_dedupe, &key, &value, BPF_ANY);
	return 1;
}

static __always_inline int emit_connection_event_identity(const struct connection_event_params *params, __u32 pid, const char *comm, __u64 socket_cookie)
{
	struct event *event;

	if (!should_emit_connection_event(params, pid)) {
		return 1;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, EVENT_CONNECTION, transport_for_socket_protocol(params->protocol), EVENT_SOURCE_CGROUP_SKB);
	event->pid = pid;
	event->socket_cookie = socket_cookie;
	if (comm) {
		__builtin_memcpy(event->comm, comm, sizeof(event->comm));
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
	char comm[16] = {0};
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

	if (!should_emit_connection_event(params, pid)) {
		return 1;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 1;
	}

	bpf_get_current_comm(comm, sizeof(comm));
	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, EVENT_CONNECTION, transport_for_socket_protocol(params->protocol), source);
	event->pid = pid;
	event->socket_cookie = socket_cookie;
	__builtin_memcpy(event->comm, comm, sizeof(event->comm));
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
	__u32 uid = kind == EGRESS_IDENTITY_UID || kind == EGRESS_IDENTITY_UID_CGROUP ? lookup->uid : 0;
	__u64 cgroup_id = kind == EGRESS_IDENTITY_CGROUP || kind == EGRESS_IDENTITY_UID_CGROUP ? lookup->cgroup_id : 0;

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
	__u32 uid = kind == EGRESS_IDENTITY_UID || kind == EGRESS_IDENTITY_UID_CGROUP ? lookup->uid : 0;
	__u64 cgroup_id = kind == EGRESS_IDENTITY_CGROUP || kind == EGRESS_IDENTITY_UID_CGROUP ? lookup->cgroup_id : 0;

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

static __always_inline __u32 lookup_egress4(__u8 allow, const struct egress_lookup *lookup)
{
	__u32 rule;

	rule = lookup_egress4_kind(allow, EGRESS_IDENTITY_UID_CGROUP, lookup);
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
	return lookup_egress4_kind(allow, EGRESS_IDENTITY_GLOBAL, lookup);
}

static __always_inline __u32 lookup_egress6(__u8 allow, const struct egress_lookup *lookup)
{
	__u32 rule;

	rule = lookup_egress6_kind(allow, EGRESS_IDENTITY_UID_CGROUP, lookup);
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
	return lookup_egress6_kind(allow, EGRESS_IDENTITY_GLOBAL, lookup);
}

static __always_inline int emit_egress_decision(struct bpf_sock_addr *ctx, const struct connection_event_params *params, const struct settings *cfg, __u32 rule_id, const struct egress_lookup *lookup)
{
	__u32 kind = cfg->egress_enforce ? EVENT_EGRESS_BLOCKED : EVENT_EGRESS_WOULD_BLOCK;
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

	if (!event) {
		return cfg->egress_enforce ? 0 : 1;
	}
	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, transport_for_socket_protocol(params->protocol), EVENT_SOURCE_CGROUP_SOCK_ADDR);
	event->kernel_uid = lookup->uid;
	event->uid_source = UID_SOURCE_KERNEL;
	event->cgroup_id = lookup->cgroup_id;
	event->rule_id = rule_id;
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
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);
	struct egress_lookup lookup = {0};
	__u32 rule;

	if (!cfg || !cfg->egress_enabled) {
		return 1;
	}
	lookup.uid = (__u32)bpf_get_current_uid_gid();
	lookup.cgroup_id = bpf_get_current_cgroup_id();
	lookup.policy_slot = cfg->active_policy_slot;
	lookup.protocol = params->protocol;
	lookup.port = params->port;
	__builtin_memcpy(lookup.addr, &addr, sizeof(addr));
	if (lookup_egress4(1, &lookup)) {
		return 1;
	}
	rule = lookup_egress4(0, &lookup);
	if (!rule && !cfg->egress_default_block) {
		return 1;
	}
	return emit_egress_decision(ctx, params, cfg, rule, &lookup);
}

static __always_inline int evaluate_egress6(struct bpf_sock_addr *ctx, const struct connection_event_params *params, const __u8 addr[16])
{
	__u32 zero = 0;
	__u32 mapped_ipv4 = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);
	struct egress_lookup lookup = {0};
	__u32 rule;

	if (!cfg || !cfg->egress_enabled) {
		return 1;
	}
	if (!addr[0] && !addr[1] && !addr[2] && !addr[3] && !addr[4] && !addr[5] &&
	    !addr[6] && !addr[7] && !addr[8] && !addr[9] && addr[10] == 0xff && addr[11] == 0xff) {
		__builtin_memcpy(&mapped_ipv4, &addr[12], sizeof(mapped_ipv4));
		return evaluate_egress4(ctx, params, mapped_ipv4);
	}
	lookup.uid = (__u32)bpf_get_current_uid_gid();
	lookup.cgroup_id = bpf_get_current_cgroup_id();
	lookup.policy_slot = cfg->active_policy_slot;
	lookup.protocol = params->protocol;
	lookup.port = params->port;
	__builtin_memcpy(lookup.addr, addr, sizeof(lookup.addr));
	if (lookup_egress6(1, &lookup)) {
		return 1;
	}
	rule = lookup_egress6(0, &lookup);
	if (!rule && !cfg->egress_default_block) {
		return 1;
	}
	return emit_egress_decision(ctx, params, cfg, rule, &lookup);
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
	if (c >= 'A' && c <= 'Z') {
		c += 'a' - 'A';
	}

	ctx->parsed->key.domain[ctx->cursor] = c;
	if (c == 0) {
		ctx->parsed->qname_length = (__u16)ctx->cursor + 1;
		ctx->done = 1;
		return 1;
	}
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

static __always_inline int emit_dns4_event(struct __sk_buff *skb, const struct domain_key *key, __u32 kind, __u8 transport, __u32 addr)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	__u8 protocol = transport == TRANSPORT_TCP ? SOCKET_PROTOCOL_TCP : SOCKET_PROTOCOL_UDP;
	(void)skb;

	if (!event) {
		return kind == EVENT_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, kind, transport, EVENT_SOURCE_CGROUP_SKB);
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
	event->socket_cookie = bpf_get_socket_cookie(skb);
#endif
	apply_socket_info(event, FAMILY_IPV4, protocol, DNS_PORT, &addr);
	set_event_peer(event, FAMILY_IPV4, DNS_PORT, &addr);
	__builtin_memcpy(event->domain, key->domain, sizeof(event->domain));
	bpf_ringbuf_submit(event, 0);
	return kind == EVENT_BLOCKED ? 0 : 1;
}

static __always_inline int emit_dns6_event(struct __sk_buff *skb, const struct domain_key *key, __u32 kind, __u8 transport, const __u8 addr[16])
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	__u8 protocol = transport == TRANSPORT_TCP ? SOCKET_PROTOCOL_TCP : SOCKET_PROTOCOL_UDP;
	(void)skb;

	if (!event) {
		return kind == EVENT_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, kind, transport, EVENT_SOURCE_CGROUP_SKB);
#if TRACEGUARD_KERNEL_HELPER_TELEMETRY
	event->socket_cookie = bpf_get_socket_cookie(skb);
#endif
	apply_socket_info(event, FAMILY_IPV6, protocol, DNS_PORT, addr);
	set_event_peer(event, FAMILY_IPV6, DNS_PORT, addr);
	__builtin_memcpy(event->domain, key->domain, sizeof(event->domain));
	bpf_ringbuf_submit(event, 0);
	return kind == EVENT_BLOCKED ? 0 : 1;
}

static __always_inline __u32 dns_event_kind(const struct dns_parse_result *parsed, const struct policy_snapshot *policy)
{
	__u8 *present;

	present = bpf_map_lookup_elem(&allowlist, &parsed->key);
	if (policy_rule_active(present, policy->policy_mask)) {
		return EVENT_DNS;
	}
	if (parsed->allow_suffix_match) {
		return EVENT_DNS;
	}
	if (policy->block_enabled && policy->block_all_domains) {
		return EVENT_BLOCKED;
	}
	present = bpf_map_lookup_elem(&blocklist, &parsed->key);
	if (policy_rule_active(present, policy->policy_mask) && policy->block_enabled) {
		return EVENT_BLOCKED;
	}
	if (parsed->block_suffix_match && policy->block_enabled) {
		return EVENT_BLOCKED;
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
	if ((flags & 0x8000) != 0 || qdcount == 0) {
		return -1;
	}

	qname_offset = payload_offset + sizeof(dns);
	parse_status = load_qname_key(skb, qname_offset, packet_len, parsed);
	if (parse_status < 0) {
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
	if (dns_end < dns_offset || dns_end > packet_len) {
		return policy->block_enabled ? DNS_PARSE_DROP : DNS_PARSE_PASS;
	}

	return parse_dns_payload(skb, dns_offset, dns_end, parsed, policy) == 0 ? DNS_PARSE_OK : policy->block_enabled ? DNS_PARSE_DROP : DNS_PARSE_PASS;
}

static __always_inline int emit_resolver_event(struct bpf_sock_addr *ctx, __u32 kind, __u8 transport, __u8 family, __u16 port, const void *addr, __u32 addr_len, __u8 hook)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
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

	return -1;
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

static __always_inline int classify_endpoint4(__u32 addr, __u16 port, const struct policy_snapshot *policy, __u8 *transport_out, __u8 *matched_rule)
{
	struct endpoint4_key key = {
		.addr = addr,
		.port = port,
		.transport = TRANSPORT_DOH,
	};
	__u8 *present;

	*matched_rule = 0;
	if (port == DOT_PORT) {
		key.transport = TRANSPORT_DOT;
		present = bpf_map_lookup_elem(&endpoint4_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = lookup_endpoint4_cidr_allow_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint4_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*matched_rule = 1;
		}
		present = lookup_endpoint4_cidr_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present || policy->block_all_resolvers) {
			*matched_rule = 1;
		}
		*transport_out = TRANSPORT_DOT;
		return 1;
	}
	if (port == HTTPS_PORT) {
		present = bpf_map_lookup_elem(&endpoint4_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = lookup_endpoint4_cidr_allow_rule(addr, port, TRANSPORT_DOH, policy->policy_mask);
		if (present) {
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
		*matched_rule = 1;
		*transport_out = TRANSPORT_DOH;
		return 1;
	}
	return 0;
}

static __always_inline int classify_endpoint6(const __u8 addr[16], __u16 port, const struct policy_snapshot *policy, __u8 *transport_out, __u8 *matched_rule)
{
	struct endpoint6_key key = {0};
	__u8 *present;

	__builtin_memcpy(key.addr, addr, sizeof(key.addr));
	key.port = port;
	*matched_rule = 0;
	if (port == DOT_PORT) {
		key.transport = TRANSPORT_DOT;
		present = bpf_map_lookup_elem(&endpoint6_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = lookup_endpoint6_cidr_allow_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*matched_rule = 1;
		}
		present = lookup_endpoint6_cidr_rule(addr, port, TRANSPORT_DOT, policy->policy_mask);
		if (present || policy->block_all_resolvers) {
			*matched_rule = 1;
		}
		*transport_out = TRANSPORT_DOT;
		return 1;
	}
	if (port == HTTPS_PORT) {
		key.transport = TRANSPORT_DOH;
		present = bpf_map_lookup_elem(&endpoint6_allow_rules, &key);
		if (policy_rule_active(present, policy->policy_mask)) {
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = lookup_endpoint6_cidr_allow_rule(addr, port, TRANSPORT_DOH, policy->policy_mask);
		if (present) {
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
		if (!policy_rule_active(present, policy->policy_mask)) {
			present = lookup_endpoint6_cidr_rule(addr, port, TRANSPORT_DOH, policy->policy_mask);
		}
		/* DoH remains endpoint-based on 443; wildcard resolver mode must not classify arbitrary HTTPS traffic. */
		if (!policy_rule_active(present, policy->policy_mask)) {
			return 0;
		}
		*matched_rule = 1;
		*transport_out = TRANSPORT_DOH;
		return 1;
	}
	return 0;
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

SEC("cgroup_skb/egress")
int trace_dns(struct __sk_buff *skb)
{
	__u32 packet_len = skb->len;
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);
	struct dns_parse_result *parsed = bpf_map_lookup_elem(&dns_scratch, &zero);
	struct policy_snapshot policy = {
		.block_enabled = cfg && cfg->block_enabled,
		.block_all_domains = cfg && cfg->block_all_domains,
		.block_all_resolvers = cfg && cfg->block_all_resolvers,
		.allow_suffix_rules_enabled = cfg && cfg->allow_suffixes_enabled,
		.block_suffix_rules_enabled = cfg && cfg->block_suffixes_enabled,
		.policy_mask = cfg && cfg->active_policy_slot ? 2 : 1,
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
			kind = dns_event_kind(parsed, &policy);
			return emit_dns4_event(skb, &parsed->key, kind, TRANSPORT_UDP, iph.daddr);
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
			kind = dns_event_kind(parsed, &policy);
			return emit_dns4_event(skb, &parsed->key, kind, TRANSPORT_TCP, iph.daddr);
		}
		return 1;
	}

	if (version == 6) {
		struct ipv6hdr ip6h = {0};
		__u32 transport_offset = sizeof(ip6h);
		__u8 nexthdr;
		__u8 fragmented;
		__u32 kind;

		if (packet_len < sizeof(ip6h)) {
			return 1;
		}
		if (bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h)) < 0) {
			return 1;
		}
		nexthdr = ip6h.nexthdr;
		if (parse_ipv6_transport(skb, packet_len, &nexthdr, &transport_offset, &fragmented) < 0) {
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
				/* Fragmented or malformed UDP DNS cannot be matched against the
				 * policy map. Block mode fails closed; observe mode passes it.
				 */
				return policy.block_enabled ? 0 : 1;
			}
			kind = dns_event_kind(parsed, &policy);
			return emit_dns6_event(skb, &parsed->key, kind, TRANSPORT_UDP, ip6h.daddr.s6_addr);
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
				/* Segmented or malformed TCP DNS cannot be matched against the
				 * policy map. Block mode fails closed; observe mode passes it.
				 */
				return dns_parse == DNS_PARSE_DROP ? 0 : 1;
			}
			kind = dns_event_kind(parsed, &policy);
			return emit_dns6_event(skb, &parsed->key, kind, TRANSPORT_TCP, ip6h.daddr.s6_addr);
		}
	}

	return 1;
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
		return emit_connection_event_identity(&params, listener ? listener->pid : 0, listener ? listener->comm : 0, 0);
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
		return emit_connection_event_identity(&params, listener ? listener->pid : 0, listener ? listener->comm : 0, 0);
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
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);
	struct bpf_sock *sk;
	__u32 local_addr = 0;
	__u32 user_ip4;
	__u32 protocol;
	__u32 user_port;
	__u16 port;
	__u16 local_port = 0;
	__u8 transport;
	__u8 matched_rule;
	struct policy_snapshot policy = {
		.block_enabled = cfg && cfg->block_enabled,
		.block_all_resolvers = cfg && cfg->block_all_resolvers,
		.policy_mask = cfg && cfg->active_policy_slot ? 2 : 1,
	};
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
	if (!classify_endpoint4(user_ip4, port, &policy, &transport, &matched_rule)) {
		return 1;
	}

	if (policy.block_enabled && matched_rule) {
		return emit_resolver_event(ctx, EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV4, port, &user_ip4, sizeof(user_ip4), SOCKET_HOOK_CGROUP_CONNECT4);
	}

	emit_resolver_event(ctx, EVENT_RESOLVER, transport, FAMILY_IPV4, port, &user_ip4, sizeof(user_ip4), SOCKET_HOOK_CGROUP_CONNECT4);
	return 1;
}

SEC("cgroup/connect6")
int trace_connect6(struct bpf_sock_addr *ctx)
{
	struct connection_event_params params = {0};
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);
	struct bpf_sock *sk;
	__u32 protocol;
	__u32 user_port;
	__u32 user_ip6_0;
	__u32 user_ip6_1;
	__u32 user_ip6_2;
	__u32 user_ip6_3;
	__u16 port;
	__u8 transport;
	__u8 matched_rule;
	__u8 addr[16];
	__u8 local_addr[16] = {0};
	__u32 mapped_ipv4 = 0;
	struct policy_snapshot policy = {
		.block_enabled = cfg && cfg->block_enabled,
		.block_all_resolvers = cfg && cfg->block_all_resolvers,
		.policy_mask = cfg && cfg->active_policy_slot ? 2 : 1,
	};
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
		if (!classify_endpoint4(mapped_ipv4, port, &policy, &transport, &matched_rule)) {
			return 1;
		}
		if (policy.block_enabled && matched_rule) {
			return emit_resolver_event(ctx, EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV4, port, &mapped_ipv4, sizeof(mapped_ipv4), SOCKET_HOOK_CGROUP_CONNECT6);
		}
		emit_resolver_event(ctx, EVENT_RESOLVER, transport, FAMILY_IPV4, port, &mapped_ipv4, sizeof(mapped_ipv4), SOCKET_HOOK_CGROUP_CONNECT6);
		return 1;
	}
	if (!classify_endpoint6(addr, port, &policy, &transport, &matched_rule)) {
		return 1;
	}

	if (policy.block_enabled && matched_rule) {
		return emit_resolver_event(ctx, EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV6, port, addr, sizeof(addr), SOCKET_HOOK_CGROUP_CONNECT6);
	}

	emit_resolver_event(ctx, EVENT_RESOLVER, transport, FAMILY_IPV6, port, addr, sizeof(addr), SOCKET_HOOK_CGROUP_CONNECT6);
	return 1;
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

static __always_inline int emit_exec_event(const char *filename)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

	if (!event) {
		return 0;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, EVENT_EXEC, 0, EVENT_SOURCE_SYSCALL_TRACEPOINT);
	if (filename) {
		bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int emit_file_access_event(const char *filename, __u64 flags, __u64 mode)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

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

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	return emit_exec_event((const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_exec_event((const char *)ctx->args[1]);
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
