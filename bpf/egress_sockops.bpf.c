// SPDX-License-Identifier: GPL-2.0
/* vmlinux.h doesn't export AF_INET (it lives in UAPI <linux/socket.h>);
 * define it before including vmlinux.h. IPPROTO_TCP is already defined in
 * vmlinux.h's enum. */
#define AF_INET 2
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* CORRECTION vs original plan: there is no BPF_SOCK_OPS_RTT_CB op.
 * srtt_us is a field on bpf_sock_ops available in whichever op actually
 * fires. We sample it opportunistically on:
 *   - BPF_SOCK_OPS_STATE_CB          (any TCP state transition)
 *   - BPF_SOCK_OPS_RTO_CB            (retransmit timeout fired -> also a loss signal)
 *   - BPF_SOCK_OPS_RETRANS_CB        (explicit retransmit -> increments retransmits here too,
 *                                      complements the tracepoint in egress_retrans.bpf.c so we
 *                                      don't depend on only one signal path)
 * We do NOT try to sample every ACK; that requires BPF_SOCK_OPS_ACK cb, which is far higher
 * frequency and not necessary for path scoring at ~second granularity.
 */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct path_key);
	__type(value, struct egress_stats);
} egress_map SEC(".maps");

/* Destination -> next-hop, populated by userspace via `ip route get` sweep.
 * Shared with egress_retrans.bpf.c (loaded against the same pinned map).
 * Replaces bpf_fib_lookup, which the kernel does not allow from sock_ops
 * (BPF__PROG_TYPE_sock_ops__HELPER_bpf_fib_lookup == 0). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);   /* dest IPv4, host byte order */
	__type(value, __u32); /* resolved next-hop, host byte order */
} dst_to_nexthop SEC(".maps");

/* Configured mask for dst_subnet grouping, e.g. /24 = 0xffffff00. Set from userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} subnet_mask_map SEC(".maps");

static __always_inline __u32 get_subnet_mask(void)
{
	__u32 zero = 0;
	__u32 *m = bpf_map_lookup_elem(&subnet_mask_map, &zero);
	return m ? *m : 0xffffff00; /* default /24 */
}

/* Resolve the next-hop for this socket's remote address by looking up the
 * dst_to_nexthop map, which is populated by the daemon via `ip route get`
 * sweeps. This replaces bpf_fib_lookup, which the kernel does not allow
 * from sock_ops programs. */
static __always_inline int resolve_next_hop(struct bpf_sock_ops *skops,
					     struct path_key *out)
{
	__u32 daddr = bpf_ntohl(skops->remote_ip4);
	__u32 *nh = bpf_map_lookup_elem(&dst_to_nexthop, &daddr);
	if (!nh)
		return -1; /* userspace hasn't populated this route yet */

	out->next_hop_ip = *nh;
	out->dst_subnet = daddr & get_subnet_mask();
	return 0;
}

static __always_inline void bump_egress(struct path_key *pk, __u64 srtt_us,
					 __u64 retrans_delta, __u64 bytes_delta)
{
	struct egress_stats *st = bpf_map_lookup_elem(&egress_map, pk);
	struct egress_stats zero = {};
	if (!st) {
		bpf_map_update_elem(&egress_map, pk, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&egress_map, pk);
		if (!st)
			return;
	}
	if (srtt_us) {
		__sync_fetch_and_add(&st->srtt_us_sum, srtt_us);
		__sync_fetch_and_add(&st->srtt_samples, 1);
	}
	if (retrans_delta)
		__sync_fetch_and_add(&st->retransmits, retrans_delta);
	if (bytes_delta)
		__sync_fetch_and_add(&st->bytes_acked, bytes_delta);
	st->last_update_ns = bpf_ktime_get_ns();
}

SEC("sockops")
int track_egress(struct bpf_sock_ops *skops)
{
	if (skops->family != AF_INET)
		return 0;

	struct path_key pk;
	if (resolve_next_hop(skops, &pk) != 0)
		return 0; /* dest not in dst_to_nexthop yet; skip sample */

	switch (skops->op) {
	case BPF_SOCK_OPS_STATE_CB:
	case BPF_SOCK_OPS_RTO_CB:
		bump_egress(&pk, skops->srtt_us, 0, 0);
		break;
	case BPF_SOCK_OPS_RETRANS_CB:
		/* skops->args[0] = bytes retransmitted context on some kernels; treat
		 * conservatively as a single retransmit event, and let the
		 * tcp_retransmit_skb tracepoint (egress_retrans.bpf.c) be the
		 * authoritative counter -- this path is a secondary/redundant signal
		 * in case the tracepoint program isn't loaded. */
		bump_egress(&pk, skops->srtt_us, 1, 0);
		break;
	default:
		break;
	}

	/* Request the callbacks we actually use; without this the kernel won't
	 * fire STATE_CB/RTO_CB/RETRANS_CB for this socket. */
	bpf_sock_ops_cb_flags_set(skops,
		BPF_SOCK_OPS_STATE_CB_FLAG |
		BPF_SOCK_OPS_RTO_CB_FLAG |
		BPF_SOCK_OPS_RETRANS_CB_FLAG);

	return 0;
}

char _license[] SEC("license") = "GPL";
