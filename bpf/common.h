#ifndef PATHPROFILER_COMMON_H
#define PATHPROFILER_COMMON_H

/* LPM trie key for dst_to_nexthop lookups. prefixlen=32 means
 * exact-match a /32 destination; the daemon populates entries at
 * the prefix granularity (e.g. /24) so one entry covers the whole
 * subnet. */
struct lpm_key {
	__u32 prefixlen;
	__u32 daddr;   /* host byte order */
};

/* Keyed by resolved next-hop, not by full flow — one entry per candidate
 * gateway path. next_hop_ip is the resolved gateway (populated by the
 * daemon via ip route get sweeps into dst_to_nexthop).
 */
struct path_key {
	__u32 next_hop_ip;   /* IPv4 next-hop, host byte order */
	__u32 dst_subnet;    /* /24 or configured mask of the destination, for per-subnet granularity */
};

/* Egress-side (forward path) stats, updated from sock_ops + retransmit tracepoint. */
struct egress_stats {
	__u64 srtt_us_sum;     /* running sum of sampled srtt_us, for averaging in userspace */
	__u64 srtt_samples;
	__u64 retransmits;
	__u64 bytes_acked;     /* denominator to normalize retransmit rate */
	__u64 last_update_ns;
};

/* Ingress-side (return path) stats, updated from XDP. */
struct ingress_stats {
	__u64 iat_sum_ns;      /* sum of inter-arrival times, for averaging */
	__u64 iat_samples;
	__u64 iat_sq_sum_ns;   /* sum of squares, for jitter/variance in userspace */
	__u64 last_arrival_ns;
	__u64 packets;
	__u64 last_seq_seen;   /* only meaningful for TCP flows we're tracking */
	__u64 seq_gaps;        /* coarse proxy for ingress loss; NOT a substitute for real loss accounting */
};

/* Transit-side (forwarded traffic) stats, updated from TC egress hook.
 * Keyed by path_key like egress_stats, but sourced from forwarded packets,
 * not locally-terminated TCP sockets. */
struct transit_stats {
	__u64 segments;       /* TCP segments forwarded through this path */
	__u64 retransmits;    /* retransmits detected via Bloom seq filter */
	__u64 last_update_ns;
};

#endif
