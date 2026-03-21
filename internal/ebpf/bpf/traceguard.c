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
#define TRANSPORT_UDP 1
#define TRANSPORT_TCP 2
#define TRANSPORT_DOT 3
#define TRANSPORT_DOH 4
#define FAMILY_IPV4 4
#define FAMILY_IPV6 6

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

struct domain_key {
	char domain[DOMAIN_KEY_SIZE];
};

struct settings {
	__u8 block_enabled;
	__u8 _pad[7];
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
	__u16 port;
	__u8 _pad[3];
	__u8 addr[16];
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

static __always_inline void init_event(struct event *event, __u32 kind, __u8 transport)
{
	event->timestamp_ns = bpf_ktime_get_ns();
	event->kind = kind;
	event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	event->transport = transport;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline int is_block_enabled(void)
{
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);

	return cfg && cfg->block_enabled;
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

static __always_inline int emit_dns_event(const struct domain_key *key, __u32 kind, __u8 transport)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

	if (!event) {
		return kind == EVENT_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, transport);
	__builtin_memcpy(event->domain, key->domain, sizeof(event->domain));
	bpf_ringbuf_submit(event, 0);
	return kind == EVENT_BLOCKED ? 0 : 1;
}

static __always_inline int handle_dns_payload(struct __sk_buff *skb, __u32 payload_offset, __u32 packet_len, __u8 transport)
{
	struct dns_header dns = {};
	struct domain_key key = {};
	__u16 flags;
	__u16 qdcount;
	int parsed;
	__u8 *present;

	if (payload_offset + sizeof(dns) > packet_len) {
		return 1;
	}
	if (bpf_skb_load_bytes(skb, payload_offset, &dns, sizeof(dns)) < 0) {
		return 1;
	}

	flags = bpf_ntohs(dns.flags);
	qdcount = bpf_ntohs(dns.qdcount);
	if ((flags & 0x8000) != 0 || qdcount == 0) {
		return 1;
	}

	parsed = load_qname_key(skb, payload_offset + sizeof(dns), packet_len, &key);
	if (parsed < 0) {
		return 1;
	}

	present = bpf_map_lookup_elem(&allowlist, &key);
	if (present) {
		return emit_dns_event(&key, EVENT_DNS, transport);
	}
	present = bpf_map_lookup_elem(&blocklist, &key);
	if (present && is_block_enabled()) {
		return emit_dns_event(&key, EVENT_BLOCKED, transport);
	}

	return emit_dns_event(&key, EVENT_DNS, transport);
}

static __always_inline int handle_tcp_dns_payload(struct __sk_buff *skb, __u32 payload_offset, __u32 packet_len)
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

	return handle_dns_payload(skb, dns_offset, dns_end, TRANSPORT_TCP);
}

static __always_inline int emit_resolver_event(__u32 kind, __u8 transport, __u8 family, __u16 port, const void *addr, __u32 addr_len)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

	if (!event) {
		return kind == EVENT_RESOLVER_BLOCKED ? 0 : 1;
	}

	__builtin_memset(event, 0, sizeof(*event));
	init_event(event, kind, transport);
	event->family = family;
	event->port = port;
	if (addr && addr_len <= sizeof(event->addr)) {
		__builtin_memcpy(event->addr, addr, addr_len);
	}
	bpf_ringbuf_submit(event, 0);
	return kind == EVENT_RESOLVER_BLOCKED ? 0 : 1;
}

static __always_inline int parse_ipv6_transport(struct __sk_buff *skb, __u32 packet_len, __u8 *nexthdr, __u32 *transport_offset, __u8 *fragmented)
{
	*fragmented = 0;
#pragma clang loop unroll(disable)
	for (int i = 0; i < 6; i++) {
		if (*nexthdr == IPPROTO_HOPOPTS || *nexthdr == IPPROTO_ROUTING || *nexthdr == IPPROTO_DSTOPTS) {
			struct ipv6_ext_header ext = {};
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
			struct ipv6_ext_header ext = {};
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
			struct ipv6_frag_header frag = {};
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
		struct udphdr udph = {};

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
		struct tcphdr tcph = {};

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

static __always_inline int classify_endpoint4(__u32 addr, __u16 port, __u8 *transport_out, __u8 *matched_rule)
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
		present = bpf_map_lookup_elem(&endpoint4_rules, &key);
		if (present) {
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
		present = bpf_map_lookup_elem(&endpoint4_rules, &key);
		if (!present) {
			return 0;
		}
		*matched_rule = 1;
		*transport_out = TRANSPORT_DOH;
		return 1;
	}
	return 0;
}

static __always_inline int classify_endpoint6(const __u8 addr[16], __u16 port, __u8 *transport_out, __u8 *matched_rule)
{
	struct endpoint6_key key = {};
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
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
		if (present) {
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
		present = bpf_map_lookup_elem(&endpoint6_rules, &key);
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
		struct iphdr iph = {};
		__u32 header_len;
		__u32 transport_offset;

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
			struct udphdr udph = {};
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
			return handle_dns_payload(skb, payload_offset, packet_len, TRANSPORT_UDP);
		}
		if (iph.protocol == IPPROTO_TCP) {
			struct tcphdr tcph = {};
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
			return handle_tcp_dns_payload(skb, payload_offset, packet_len);
		}
		return 1;
	}

	if (version == 6) {
		struct ipv6hdr ip6h = {};
		__u32 transport_offset = sizeof(ip6h);
		__u8 nexthdr;
		__u8 fragmented;

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
			struct udphdr udph = {};
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
			return handle_dns_payload(skb, payload_offset, packet_len, TRANSPORT_UDP);
		}
		if (nexthdr == IPPROTO_TCP) {
			struct tcphdr tcph = {};
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
			return handle_tcp_dns_payload(skb, payload_offset, packet_len);
		}
	}

	return 1;
}

SEC("cgroup/connect4")
int trace_connect4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);
	__u16 port;
	__u8 transport;
	__u8 matched_rule;

	if (ctx->protocol != IPPROTO_TCP) {
		return 1;
	}

	port = bpf_ntohs((__u16)ctx->user_port);
	if (!classify_endpoint4(ctx->user_ip4, port, &transport, &matched_rule)) {
		return 1;
	}

	if (cfg && cfg->block_enabled && matched_rule) {
		return emit_resolver_event(EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV4, port, &ctx->user_ip4, sizeof(ctx->user_ip4));
	}

	emit_resolver_event(EVENT_RESOLVER, transport, FAMILY_IPV4, port, &ctx->user_ip4, sizeof(ctx->user_ip4));
	return 1;
}

SEC("cgroup/connect6")
int trace_connect6(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct settings *cfg = bpf_map_lookup_elem(&settings, &zero);
	__u16 port;
	__u8 transport;
	__u8 matched_rule;
	__u8 addr[16];

	if (ctx->protocol != IPPROTO_TCP) {
		return 1;
	}

	port = bpf_ntohs((__u16)ctx->user_port);
	__builtin_memcpy(addr, ctx->user_ip6, sizeof(addr));
	if (!classify_endpoint6(addr, port, &transport, &matched_rule)) {
		return 1;
	}

	if (cfg && cfg->block_enabled && matched_rule) {
		return emit_resolver_event(EVENT_RESOLVER_BLOCKED, transport, FAMILY_IPV6, port, addr, sizeof(addr));
	}

	emit_resolver_event(EVENT_RESOLVER, transport, FAMILY_IPV6, port, addr, sizeof(addr));
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
