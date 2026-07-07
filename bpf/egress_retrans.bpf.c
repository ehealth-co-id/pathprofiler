// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* Authoritative retransmit signal. sock_ops RETRANS_CB is a secondary/best-effort
 * signal (see egress_sockops.bpf.c); this raw tracepoint is the one we trust for
 * the retransmit_rate term in the path-cost formula, because it fires precisely
 * once per actual retransmitted segment with the skb available for inspection.
 *
 * Using raw_tp (tp_btf) instead of tracepoint/ because the trace_event_raw_tcp_retransmit_skb
 * struct from vmlinux.h is kernel-version-specific and its daddr/saddr field layout
 * varies, causing CO-RE relocation failures (0xbad2310) on some kernels. Raw tracepoints
 * receive the raw args via BTF-resolved structs; we extract daddr from struct sock
 * via BPF_CORE_READ, which survives kernel version drift. Note: sk_daddr
 * is a C macro (#define sk_daddr __sk_common.skc_daddr) that doesn't exist
 * in BTF, so we use the actual BTF member path __sk_common.skc_daddr. */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct path_key);
	__type(value, struct egress_stats);
} egress_map SEC(".maps"); /* same map as egress_sockops.bpf.c -- both programs
			      must be loaded against the same pinned map, see
			      Makefile/loader for pinning under /sys/fs/bpf */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);   /* dest IPv4, host byte order */
	__type(value, __u32); /* resolved next-hop, populated by userspace from
				  a periodic `ip route get` sweep */
} dst_to_nexthop SEC(".maps"); /* shared with egress_sockops.bpf.c -- both
				  programs look up dest->nh, loaded against
				  the same pinned map via MapReplacements */

SEC("raw_tp/tcp_retransmit_skb")
int on_tcp_retransmit(struct bpf_raw_tracepoint_args *ctx)
{
	/* raw_tp programs receive `struct bpf_raw_tracepoint_args` and the first
	 * argument for tcp_retransmit_skb is a `struct sk_buff *`.
	 *
	 * Important: do NOT cast ctx to a locally-declared wrapper struct and
	 * CO-RE read a field from it. That emits a CO-RE relocation against a type
	 * that doesn't exist in the running kernel's BTF and can fail at load time
	 * with libbpf's 0x0BAD2310 relocation sentinel.
	 */
	struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
	if (!skb)
		return 0;

	struct sock *sk = NULL;
	BPF_CORE_READ_INTO(&sk, skb, sk);
	if (!sk)
		return 0;

	__u32 daddr;
	/* sk_daddr is a C macro (#define sk_daddr __sk_common.skc_daddr)
	 * that doesn't exist in BTF. Use BPF_CORE_READ with dot-notation
	 * to chain through the embedded __sk_common struct. */
	daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	daddr = bpf_ntohl(daddr);

	__u32 *nh = bpf_map_lookup_elem(&dst_to_nexthop, &daddr);
	if (!nh)
		return 0; /* unresolved dest; userspace hasn't populated this route yet */

	struct path_key pk = { .next_hop_ip = *nh, .dst_subnet = daddr & 0xffffff00 };
	struct egress_stats *st = bpf_map_lookup_elem(&egress_map, &pk);
	struct egress_stats zero = {};
	if (!st) {
		bpf_map_update_elem(&egress_map, &pk, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&egress_map, &pk);
		if (!st)
			return 0;
	}
	__sync_fetch_and_add(&st->retransmits, 1);
	st->last_update_ns = bpf_ktime_get_ns();
	return 0;
}

char _license[] SEC("license") = "GPL";
