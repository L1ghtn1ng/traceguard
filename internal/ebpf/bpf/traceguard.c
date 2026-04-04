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
#define MAX_DOMAIN_LEN 255
#define DOMAIN_KEY_SIZE (MAX_DOMAIN_LEN + 1)
#define MAX_FILENAME_LEN 256
#define EVENT_DNS 1
#define EVENT_BLOCKED 2
#define EVENT_EXEC 3
#define EVENT_RESOLVER 4
#define EVENT_RESOLVER_BLOCKED 5
#define EVENT_CONNECTION 6
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
#define SOCKET_INFO_MAX_ENTRIES 16384
#define LISTENER_INFO_MAX_ENTRIES 16384
#define CONNECTION_DEDUPE_MAX_ENTRIES 32768
#define CONNECTION_DEDUPE_WINDOW_NS 60000000000ULL

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

struct domain_key {
	__u8 domain[DOMAIN_KEY_SIZE];
};

struct settings {
	__u8 block_enabled;
	__u8 block_all_domains;
	__u8 block_all_resolvers;
	__u8 _pad[5];
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
	__u16 _pad0;
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
	__uint(max_entries, 8192);
	__type(key, struct domain_key);
	__type(value, __u8);
} blocklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct domain_key);
	__type(value, __u8);
} allowlist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct settings);
} settings SEC(".maps");

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
	__uint(max_entries, 8192);
	__type(key, struct endpoint4_key);
	__type(value, __u8);
} endpoint4_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct endpoint4_key);
	__type(value, __u8);
} endpoint4_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 8192);
	__type(key, struct endpoint4_cidr_key);
	__type(value, __u8);
} endpoint4_cidr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 8192);
	__type(key, struct endpoint4_cidr_key);
	__type(value, __u8);
} endpoint4_cidr_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct endpoint6_key);
	__type(value, __u8);
} endpoint6_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct endpoint6_key);
	__type(value, __u8);
} endpoint6_allow_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 8192);
	__type(key, struct endpoint6_cidr_key);
	__type(value, __u8);
} endpoint6_cidr_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 8192);
	__type(key, struct endpoint6_cidr_key);
	__type(value, __u8);
} endpoint6_cidr_allow_rules SEC(".maps");

static __always_inline void init_event_base(struct event *event, __u32 kind, __u8 transport)
{
	event->timestamp_ns = bpf_ktime_get_ns();
	event->kind = kind;
	event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	event->transport = transport;
}

static __always_inline void init_event(struct event *event, __u32 kind, __u8 transport)
{
	init_event_base(event, kind, transport);
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

static __always_inline int emit_connection_event_identity(const struct connection_event_params *params, __u32 pid, const char *comm)
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
	init_event_base(event, EVENT_CONNECTION, transport_for_socket_protocol(params->protocol));
	event->pid = pid;
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

static __always_inline int emit_connection_event_current(const struct connection_event_params *params)
{
	char comm[16] = {0};
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

	bpf_get_current_comm(comm, sizeof(comm));
	return emit_connection_event_identity(params, pid, comm);
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

static __always_inline int is_block_enabled(void)
{
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);

	return cfg && cfg->block_enabled;
}

static __always_inline int block_all_domains_enabled(void)
{
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);

	return cfg && cfg->block_all_domains;
}

static __always_inline void init_endpoint4_cidr_key(struct endpoint4_cidr_key *key, __u32 addr, __u16 port, __u8 transport)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->prefixlen = 24 + 32;
	key->data[0] = transport;
	key->data[1] = (__u8)(port >> 8);
	key->data[2] = (__u8)(port & 0xff);
	key->data[3] = (__u8)(addr & 0xff);
	key->data[4] = (__u8)((addr >> 8) & 0xff);
	key->data[5] = (__u8)((addr >> 16) & 0xff);
	key->data[6] = (__u8)((addr >> 24) & 0xff);
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

static __always_inline __u8 *lookup_endpoint4_cidr_rule(__u32 addr, __u16 port, __u8 transport)
{
	struct endpoint4_cidr_key key = {0};

	init_endpoint4_cidr_key(&key, addr, port, transport);
	return bpf_map_lookup_elem(&endpoint4_cidr_rules, &key);
}

static __always_inline __u8 *lookup_endpoint4_cidr_allow_rule(__u32 addr, __u16 port, __u8 transport)
{
	struct endpoint4_cidr_key key = {0};

	init_endpoint4_cidr_key(&key, addr, port, transport);
	return bpf_map_lookup_elem(&endpoint4_cidr_allow_rules, &key);
}

static __always_inline __u8 *lookup_endpoint6_cidr_rule(const __u8 addr[16], __u16 port, __u8 transport)
{
	struct endpoint6_cidr_key key = {0};

	init_endpoint6_cidr_key(&key, addr, port, transport);
	return bpf_map_lookup_elem(&endpoint6_cidr_rules, &key);
}

static __always_inline __u8 *lookup_endpoint6_cidr_allow_rule(const __u8 addr[16], __u16 port, __u8 transport)
{
	struct endpoint6_cidr_key key = {0};

	init_endpoint6_cidr_key(&key, addr, port, transport);
	return bpf_map_lookup_elem(&endpoint6_cidr_allow_rules, &key);
}

static __always_inline int load_qname_key(struct __sk_buff *skb, __u32 start, __u32 packet_len, struct domain_key *key)
{
	if (packet_len <= start) {
		return -1;
	}

	__builtin_memset(key, 0, sizeof(*key));
#pragma clang loop unroll(disable)
	for (int i = 0; i < DOMAIN_KEY_SIZE; i++) {
		__u8 c;

		if (start + (__u32)i >= packet_len) {
			return -1;
		}
		if (bpf_skb_load_bytes(skb, start + (__u32)i, &c, sizeof(c)) < 0) {
			return -1;
		}
		if (c >= 'A' && c <= 'Z') {
			c += 'a' - 'A';
		}

		key->domain[i] = c;
		if (c == 0) {
			return 0;
		}
	}

	return -1;
}

static __always_inline int emit_dns4_event(const struct domain_key *key, __u32 kind, __u8 transport, __u8 protocol, __u32 addr)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

	if (!event) {
		return kind == EVENT_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, kind, transport);
	apply_socket_info(event, FAMILY_IPV4, protocol, DNS_PORT, &addr);
	set_event_peer(event, FAMILY_IPV4, DNS_PORT, &addr);
	__builtin_memcpy(event->domain, key->domain, sizeof(event->domain));
	bpf_ringbuf_submit(event, 0);
	return kind == EVENT_BLOCKED ? 0 : 1;
}

static __always_inline int emit_dns6_event(const struct domain_key *key, __u32 kind, __u8 transport, __u8 protocol, const __u8 addr[16])
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

	if (!event) {
		return kind == EVENT_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event_base(event, kind, transport);
	apply_socket_info(event, FAMILY_IPV6, protocol, DNS_PORT, addr);
	set_event_peer(event, FAMILY_IPV6, DNS_PORT, addr);
	__builtin_memcpy(event->domain, key->domain, sizeof(event->domain));
	bpf_ringbuf_submit(event, 0);
	return kind == EVENT_BLOCKED ? 0 : 1;
}

static __always_inline __u32 dns_event_kind(const struct domain_key *key)
{
	__u8 *present;

	present = bpf_map_lookup_elem(&allowlist, key);
	if (present) {
		return EVENT_DNS;
	}
	if (is_block_enabled() && block_all_domains_enabled()) {
		return EVENT_BLOCKED;
	}
	present = bpf_map_lookup_elem(&blocklist, key);
	if (present && is_block_enabled()) {
		return EVENT_BLOCKED;
	}
	return EVENT_DNS;
}

static __always_inline int parse_dns_payload(struct __sk_buff *skb, __u32 payload_offset, __u32 packet_len, struct domain_key *key)
{
	struct dns_header dns = {0};
	__u16 flags;
	__u16 qdcount;
	int parsed;

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

	parsed = load_qname_key(skb, payload_offset + sizeof(dns), packet_len, key);
	if (parsed < 0) {
		return -1;
	}

	return 0;
}

static __always_inline int parse_tcp_dns_payload(struct __sk_buff *skb, __u32 payload_offset, __u32 packet_len, struct domain_key *key)
{
	__be16 dns_len_be;
	__u16 dns_len;
	__u32 dns_offset;
	__u32 dns_end;

	if (payload_offset >= packet_len) {
		return 1;
	}
	if (payload_offset + sizeof(dns_len_be) > packet_len) {
		return is_block_enabled() ? 0 : 1;
	}
	if (bpf_skb_load_bytes(skb, payload_offset, &dns_len_be, sizeof(dns_len_be)) < 0) {
		return is_block_enabled() ? 0 : 1;
	}

	dns_len = bpf_ntohs(dns_len_be);
	if (dns_len < sizeof(struct dns_header)) {
		return is_block_enabled() ? 0 : 1;
	}

	dns_offset = payload_offset + sizeof(dns_len_be);
	dns_end = dns_offset + (__u32)dns_len;
	if (dns_end < dns_offset || dns_end > packet_len) {
		return is_block_enabled() ? 0 : 1;
	}

	return parse_dns_payload(skb, dns_offset, dns_end, key);
}

static __always_inline int emit_resolver_event(__u32 kind, __u8 transport, __u8 family, __u16 port, const void *addr, __u32 addr_len, __u8 hook)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	(void)addr_len;

	if (!event) {
		return kind == EVENT_RESOLVER_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, transport);
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

static __always_inline int block_fragmented_ipv6_dns(struct __sk_buff *skb, __u32 transport_offset, __u32 packet_len, __u8 nexthdr)
{
	if (!is_block_enabled()) {
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

static __always_inline int classify_endpoint4(__u32 addr, __u16 port, __u8 block_all, __u8 *transport_out, __u8 *matched_rule)
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
		if (present) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = lookup_endpoint4_cidr_allow_rule(addr, port, TRANSPORT_DOT);
		if (present) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint4_rules, &key);
		if (present) {
			*matched_rule = 1;
		}
		present = lookup_endpoint4_cidr_rule(addr, port, TRANSPORT_DOT);
		if (present || block_all) {
			*matched_rule = 1;
		}
		*transport_out = TRANSPORT_DOT;
		return 1;
	}
	if (port == HTTPS_PORT) {
		present = bpf_map_lookup_elem(&endpoint4_allow_rules, &key);
		if (present) {
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = lookup_endpoint4_cidr_allow_rule(addr, port, TRANSPORT_DOH);
		if (present) {
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint4_rules, &key);
		if (!present) {
			present = lookup_endpoint4_cidr_rule(addr, port, TRANSPORT_DOH);
		}
		/* DoH remains endpoint-based on 443; wildcard resolver mode must not classify arbitrary HTTPS traffic. */
		if (!present) {
			return 0;
		}
		*matched_rule = 1;
		*transport_out = TRANSPORT_DOH;
		return 1;
	}
	return 0;
}

static __always_inline int classify_endpoint6(const __u8 addr[16], __u16 port, __u8 block_all, __u8 *transport_out, __u8 *matched_rule)
{
	struct endpoint6_key key = {0};
	__u8 *present;

	__builtin_memcpy(key.addr, addr, sizeof(key.addr));
	key.port = port;
	*matched_rule = 0;
	if (port == DOT_PORT) {
		key.transport = TRANSPORT_DOT;
		present = bpf_map_lookup_elem(&endpoint6_allow_rules, &key);
		if (present) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = lookup_endpoint6_cidr_allow_rule(addr, port, TRANSPORT_DOT);
		if (present) {
			*transport_out = TRANSPORT_DOT;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
		if (present) {
			*matched_rule = 1;
		}
		present = lookup_endpoint6_cidr_rule(addr, port, TRANSPORT_DOT);
		if (present || block_all) {
			*matched_rule = 1;
		}
		*transport_out = TRANSPORT_DOT;
		return 1;
	}
	if (port == HTTPS_PORT) {
		key.transport = TRANSPORT_DOH;
		present = bpf_map_lookup_elem(&endpoint6_allow_rules, &key);
		if (present) {
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = lookup_endpoint6_cidr_allow_rule(addr, port, TRANSPORT_DOH);
		if (present) {
			*transport_out = TRANSPORT_DOH;
			return 1;
		}
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
		if (!present) {
			present = lookup_endpoint6_cidr_rule(addr, port, TRANSPORT_DOH);
		}
		/* DoH remains endpoint-based on 443; wildcard resolver mode must not classify arbitrary HTTPS traffic. */
		if (!present) {
			return 0;
		}
		*matched_rule = 1;
		*transport_out = TRANSPORT_DOH;
		return 1;
	}
	return 0;
}

SEC("cgroup_skb/egress")
int trace_dns(struct __sk_buff *skb)
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
		__u32 header_len;
		__u32 transport_offset;
		struct domain_key key = {0};
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
			if (parse_dns_payload(skb, payload_offset, packet_len, &key) < 0) {
				return 1;
			}
			kind = dns_event_kind(&key);
			return emit_dns4_event(&key, kind, TRANSPORT_UDP, SOCKET_PROTOCOL_UDP, iph.daddr);
		}
		if (iph.protocol == IPPROTO_TCP) {
			struct tcphdr tcph = {0};
			__u32 tcp_len;
			__u32 payload_offset;

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
			if (parse_tcp_dns_payload(skb, payload_offset, packet_len, &key) < 0) {
				return is_block_enabled() ? 0 : 1;
			}
			kind = dns_event_kind(&key);
			return emit_dns4_event(&key, kind, TRANSPORT_TCP, SOCKET_PROTOCOL_TCP, iph.daddr);
		}
		return 1;
	}

	if (version == 6) {
		struct ipv6hdr ip6h = {0};
		__u32 transport_offset = sizeof(ip6h);
		__u8 nexthdr;
		__u8 fragmented;
		struct domain_key key = {0};
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
			return block_fragmented_ipv6_dns(skb, transport_offset, packet_len, nexthdr);
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
			if (parse_dns_payload(skb, payload_offset, packet_len, &key) < 0) {
				return 1;
			}
			kind = dns_event_kind(&key);
			return emit_dns6_event(&key, kind, TRANSPORT_UDP, SOCKET_PROTOCOL_UDP, ip6h.daddr.s6_addr);
		}
		if (nexthdr == IPPROTO_TCP) {
			struct tcphdr tcph = {0};
			__u32 tcp_len;
			__u32 payload_offset;

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
			if (parse_tcp_dns_payload(skb, payload_offset, packet_len, &key) < 0) {
				return is_block_enabled() ? 0 : 1;
			}
			kind = dns_event_kind(&key);
			return emit_dns6_event(&key, kind, TRANSPORT_TCP, SOCKET_PROTOCOL_TCP, ip6h.daddr.s6_addr);
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
		return emit_connection_event_identity(&params, listener ? listener->pid : 0, listener ? listener->comm : 0);
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
		return emit_connection_event_identity(&params, listener ? listener->pid : 0, listener ? listener->comm : 0);
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
	emit_connection_event_current(&params);
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
	emit_connection_event_current(&params);
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
	__u8 block_all = cfg && cfg->block_all_resolvers;
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
	emit_connection_event_current(&params);
	if (port == DNS_PORT) {
		cache_socket_info(FAMILY_IPV4, SOCKET_PROTOCOL_TCP, port, &user_ip4, SOCKET_HOOK_CGROUP_CONNECT4);
	}
	if (!classify_endpoint4(user_ip4, port, block_all, &transport, &matched_rule)) {
		return 1;
	}

	if (cfg && cfg->block_enabled && matched_rule) {
		return emit_resolver_event(EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV4, port, &user_ip4, sizeof(user_ip4), SOCKET_HOOK_CGROUP_CONNECT4);
	}

	emit_resolver_event(EVENT_RESOLVER, transport, FAMILY_IPV4, port, &user_ip4, sizeof(user_ip4), SOCKET_HOOK_CGROUP_CONNECT4);
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
	__u8 block_all = cfg && cfg->block_all_resolvers;
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
	emit_connection_event_current(&params);
	if (port == DNS_PORT) {
		cache_socket_info(FAMILY_IPV6, SOCKET_PROTOCOL_TCP, port, addr, SOCKET_HOOK_CGROUP_CONNECT6);
	}
	if (!classify_endpoint6(addr, port, block_all, &transport, &matched_rule)) {
		return 1;
	}

	if (cfg && cfg->block_enabled && matched_rule) {
		return emit_resolver_event(EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV6, port, addr, sizeof(addr), SOCKET_HOOK_CGROUP_CONNECT6);
	}

	emit_resolver_event(EVENT_RESOLVER, transport, FAMILY_IPV6, port, addr, sizeof(addr), SOCKET_HOOK_CGROUP_CONNECT6);
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
	emit_connection_event_current(&params);
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
	emit_connection_event_current(&params);
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
	init_event(event, EVENT_EXEC, 0);
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
