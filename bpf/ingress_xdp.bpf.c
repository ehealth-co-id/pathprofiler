// SPDX-License-Identifier: GPL-2.0
/* vmlinux.h (from BTF) doesn't export #define constants like AF_INET or
 * ETH_P_IP; define them before including vmlinux.h. IPPROTO_TCP is already
 * defined in vmlinux.h's enum. */
#define AF_INET 2
#define ETH_P_IP 0x0800
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* One of these programs is attached per physical/logical gateway-facing
 * interface. gateway_ip identifies which candidate path this interface
 * corresponds to -- set via the ARRAY map below at load time, NOT inferred
 * from packet headers (source IP inspection is unreliable when NAT or a
 * shared uplink is involved; interface identity is ground truth). */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32); /* this interface's gateway_ip, set by loader per attach */
} iface_gateway_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 64); /* small: keyed by gateway_ip, not by flow */
	__type(key, __u32);
	__type(value, struct ingress_stats);
} ingress_map SEC(".maps");

static __always_inline __u32 get_gateway_ip(void)
{
	__u32 zero = 0;
	__u32 *g = bpf_map_lookup_elem(&iface_gateway_map, &zero);
	return g ? *g : 0;
}

SEC("xdp")
int track_ingress(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	__u32 gw = get_gateway_ip();
	__u64 now = bpf_ktime_get_ns();

	struct ingress_stats *st = bpf_map_lookup_elem(&ingress_map, &gw);
	struct ingress_stats zero = {};
	if (!st) {
		bpf_map_update_elem(&ingress_map, &gw, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&ingress_map, &gw);
		if (!st)
			return XDP_PASS;
	}

	if (st->last_arrival_ns) {
		__u64 iat = now - st->last_arrival_ns;
		st->iat_sum_ns += iat;
		st->iat_sq_sum_ns += iat * iat; /* variance computed in userspace: E[x^2]-E[x]^2 */
		st->iat_samples += 1;
	}
	st->last_arrival_ns = now;
	st->packets += 1;

	/* Coarse sequence-gap proxy only for TCP; skip for UDP/ICMP. This is
	 * explicitly a PROXY, not a loss counter -- see residual uncertainty
	 * in the plan: it cannot distinguish reordering from actual drops,
	 * and out-of-window/retransmitted-and-recovered segments will
	 * register as false gaps. Treat as a coarse "something's off" signal
	 * that userspace should corroborate against egress retransmit deltas
	 * before actuating on ingress data alone. */
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
		if ((void *)(tcph + 1) <= data_end) {
			__u32 seq = bpf_ntohl(tcph->seq);
			if (st->last_seq_seen && seq < (__u32)st->last_seq_seen &&
			    (st->last_seq_seen - seq) > 1000000) {
				/* large backward jump heuristic, not a real gap detector */
				st->seq_gaps += 1;
			}
			st->last_seq_seen = seq;
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
