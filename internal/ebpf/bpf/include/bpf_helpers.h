#ifndef __TRACEGUARD_BPF_HELPERS_H
#define __TRACEGUARD_BPF_HELPERS_H

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __array(name, val) val *name[]
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static void *(*const bpf_map_lookup_elem)(const void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*const bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)BPF_FUNC_get_current_comm;
static __u64 (*const bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*const bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*const bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*const bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static long (*const bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_user_str;
static long (*const bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#endif
