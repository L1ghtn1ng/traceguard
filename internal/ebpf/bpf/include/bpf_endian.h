#ifndef __TRACEGUARD_BPF_ENDIAN_H
#define __TRACEGUARD_BPF_ENDIAN_H

#define __bpf_constant_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define __bpf_constant_ntohl(x) ((__u32)__builtin_bswap32((__u32)(x)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __bpf_constant_ntohs(x)
#define bpf_htons(x) __bpf_constant_ntohs(x)
#define bpf_ntohl(x) __bpf_constant_ntohl(x)
#define bpf_htonl(x) __bpf_constant_ntohl(x)
#else
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#define bpf_ntohl(x) (x)
#define bpf_htonl(x) (x)
#endif

#endif
