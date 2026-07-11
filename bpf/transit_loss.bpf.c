//go:build ignore

/* Ported from ebpf-packet-loss-exporter/bpf/packet_loss.bpf.c.
 * Core Bloom filter logic (hash, epoch roll, test-and-set) copied verbatim.
 * Replacements: zone LPM → dst_to_nexthop, ringbuf → transit_loss_map PERCPU_HASH. */
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define BLOOM_WORDS      32768
#define BLOOM_BITS       (BLOOM_WORDS * 64)
#define BLOOM_BITMASK    (BLOOM_BITS - 1)
#define BLOOM_HASHES     3
#define BLOOM_EPOCH_NS   1500000000ULL /* 1.5 seconds */

struct bloom_word {
	__u64 gen;
	__u64 bits;
};

struct bloom_epoch_state {
	__u64 gen;
	__u64 start_ns;
};

/* Owned by this collection (no longer shared from egress). */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dst_to_nexthop SEC(".maps");

/* Owned by this collection (no longer shared from egress_sockops). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} subnet_mask_map SEC(".maps");

/* Per-path forwarded TCP segment and retransmit counters.
 * PERCPU_HASH for lock-free per-CPU writes; userspace sums across CPUs. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 64);
	__type(key, struct path_key);
	__type(value, struct transit_stats);
} transit_loss_map SEC(".maps");

/* Double-buffered Bloom filter. Half for even generations, half for odd. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2 * BLOOM_WORDS);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bloom_word));
} transit_bloom_bits SEC(".maps");

/* Singleton: current Bloom epoch generation and start timestamp. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bloom_epoch_state));
} transit_bloom_epoch SEC(".maps");

/* Debug counter: packets dropped because dst_to_nexthop lookup failed. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
} transit_debug_dropped SEC(".maps");

static __always_inline void debug_inc(void *map)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(map, &k);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline __u32 get_subnet_mask(void)
{
	__u32 zero = 0;
	__u32 *m = bpf_map_lookup_elem(&subnet_mask_map, &zero);
	return m ? *m : 0xffffff00;
}

/* Copied verbatim from ebpf-packet-loss-exporter. */
static __always_inline int parse_ipv4(struct __sk_buff *skb, void *data, void *data_end,
				      struct iphdr **iph)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP)) {
		*iph = (void *)(eth + 1);
		if ((void *)(*iph + 1) > data_end)
			return -1;
		return 0;
	}

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		*iph = data;
		if ((void *)(*iph + 1) > data_end)
			return -1;
		return 0;
	}

	return -1;
}

/* Copied verbatim from ebpf-packet-loss-exporter. */
static __always_inline __u32 bloom_hash(__u32 saddr, __u32 daddr, __u16 sport,
					__u16 dport, __u32 seq, __u32 seed)
{
	__u32 h = seed;

	h ^= saddr;
	h ^= daddr + 0x9e3779b9 + (h << 6) + (h >> 2);
	h ^= ((__u32)sport << 16) | dport;
	h ^= seq + 0x9e3779b9 + (h << 6) + (h >> 2);
	return h;
}

/* Copied verbatim from ebpf-packet-loss-exporter. */
static __always_inline __u32 bloom_bit_index(__u32 saddr, __u32 daddr, __u16 sport,
					     __u16 dport, __u32 seq, __u32 seed)
{
	return bloom_hash(saddr, daddr, sport, dport, seq, seed) & BLOOM_BITMASK;
}

/* Copied verbatim from ebpf-packet-loss-exporter, maps renamed to transit_bloom_bits. */
static __always_inline int bloom_test_bit_gen(__u32 bit, __u64 gen)
{
	__u32 word = bit >> 6;
	__u64 mask = 1ULL << (bit & 63);
	__u32 idx = (gen & 1) * BLOOM_WORDS + word;
	struct bloom_word *w = bpf_map_lookup_elem(&transit_bloom_bits, &idx);

	if (!w || w->gen != gen)
		return 0;
	return (w->bits & mask) != 0;
}

/* Copied verbatim from ebpf-packet-loss-exporter, maps renamed to transit_bloom_bits. */
static __always_inline void bloom_set_bit_gen(__u32 bit, __u64 gen)
{
	__u32 word = bit >> 6;
	__u64 mask = 1ULL << (bit & 63);
	__u32 idx = (gen & 1) * BLOOM_WORDS + word;
	struct bloom_word *w = bpf_map_lookup_elem(&transit_bloom_bits, &idx);

	if (!w)
		return;

	if (w->gen != gen) {
		__u64 old = __sync_val_compare_and_swap(&w->gen, w->gen, gen);

		if (old != gen)
			w->bits = 0;
	}
	__sync_fetch_and_or(&w->bits, mask);
}

/* Copied verbatim from ebpf-packet-loss-exporter, map renamed to transit_bloom_epoch. */
static __always_inline void bloom_maybe_roll_epoch(__u64 now)
{
	__u32 k = 0;
	struct bloom_epoch_state *epoch = bpf_map_lookup_elem(&transit_bloom_epoch, &k);

	if (!epoch) {
		struct bloom_epoch_state init = {
			.gen = 0,
			.start_ns = now,
		};

		bpf_map_update_elem(&transit_bloom_epoch, &k, &init, BPF_ANY);
		return;
	}

	if (now > epoch->start_ns && now - epoch->start_ns > BLOOM_EPOCH_NS) {
		if (__sync_bool_compare_and_swap(&epoch->start_ns, epoch->start_ns, now))
			__sync_fetch_and_add(&epoch->gen, 1);
	}
}

/* Copied verbatim from ebpf-packet-loss-exporter, maps renamed. */
static __always_inline int bloom_test_and_set(__u32 saddr, __u32 daddr, __u16 sport,
					      __u16 dport, __u32 seq)
{
	__u32 k = 0;
	struct bloom_epoch_state *epoch = bpf_map_lookup_elem(&transit_bloom_epoch, &k);
	__u64 cur_gen;
	__u64 prev_gen;
	__u32 bit0, bit1, bit2;
	int seen0, seen1, seen2;

	if (!epoch)
		return 0;

	cur_gen = epoch->gen;
	prev_gen = cur_gen - 1;

	bit0 = bloom_bit_index(saddr, daddr, sport, dport, seq, 0x12345678);
	bit1 = bloom_bit_index(saddr, daddr, sport, dport, seq, 0x9e3779b9);
	bit2 = bloom_bit_index(saddr, daddr, sport, dport, seq, 0xdeadbeef);

	seen0 = bloom_test_bit_gen(bit0, cur_gen) || bloom_test_bit_gen(bit0, prev_gen);
	seen1 = bloom_test_bit_gen(bit1, cur_gen) || bloom_test_bit_gen(bit1, prev_gen);
	seen2 = bloom_test_bit_gen(bit2, cur_gen) || bloom_test_bit_gen(bit2, prev_gen);

	bloom_set_bit_gen(bit0, cur_gen);
	bloom_set_bit_gen(bit1, cur_gen);
	bloom_set_bit_gen(bit2, cur_gen);

	return seen0 && seen1 && seen2;
}

SEC("tc")
int transit_egress(struct __sk_buff *skb)
{
	void *data;
	void *data_end;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u64 now;
	__u32 seq;
	__u32 seq_key;
	__u8 fin;
	__u8 syn;
	__u8 rst;
	__u32 payload_len;
	__u8 is_retrans;

	if (bpf_skb_pull_data(skb, 0) < 0)
		return TC_ACT_UNSPEC;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	if (parse_ipv4(skb, data, data_end, &iph) < 0)
		return TC_ACT_UNSPEC;

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	tcph = (void *)iph + (iph->ihl * 4);
	if ((void *)(tcph + 1) > data_end)
		return TC_ACT_UNSPEC;

	__u16 tcp_hdr_len = tcph->doff * 4;

	if (tcp_hdr_len < sizeof(*tcph))
		return TC_ACT_UNSPEC;

	__u16 ip_total = bpf_ntohs(iph->tot_len);
	__u32 ip_hdr_len = iph->ihl * 4;

	if (ip_total < ip_hdr_len + tcp_hdr_len)
		return TC_ACT_UNSPEC;

	payload_len = ip_total - ip_hdr_len - tcp_hdr_len;

	fin = tcph->fin;
	syn = tcph->syn;
	rst = tcph->rst;

	/* Skip pure ACKs — no payload, no SYN/FIN/RST. */
	if (payload_len == 0 && !syn && !fin && !rst)
		return TC_ACT_UNSPEC;

	/* Lookup destination in dst_to_nexthop LPM trie.
	 * iph->daddr is raw wire bytes; on x86 this is already the same LE layout
	 * that the Go daemon writes into the map (no ntohl needed). */
	struct lpm_key lpm = { .prefixlen = 32, .daddr = iph->daddr };
	__u32 *nh = bpf_map_lookup_elem(&dst_to_nexthop, &lpm);
	if (!nh) {
		debug_inc(&transit_debug_dropped);
		return TC_ACT_UNSPEC; /* unresolved dest; userspace hasn't populated this route yet */
	}

	__u32 mask = get_subnet_mask();
	struct path_key pk = { .next_hop_ip = *nh, .dst_subnet = bpf_ntohl(iph->daddr) & mask };

	/* Lookup-or-create transit_loss_map entry. PERCPU_HASH — may race with another CPU
	 * on the first packet for a new key. Handle EEXIST by re-lookup. */
	struct transit_stats *st = bpf_map_lookup_elem(&transit_loss_map, &pk);
	if (!st) {
		struct transit_stats zero = {};
		int err = bpf_map_update_elem(&transit_loss_map, &pk, &zero, BPF_NOEXIST);
		if (err == 0) {
			st = bpf_map_lookup_elem(&transit_loss_map, &pk);
			if (!st)
				return TC_ACT_UNSPEC;
		} else {
			/* EEXIST — another CPU won the race. Re-lookup. */
			st = bpf_map_lookup_elem(&transit_loss_map, &pk);
			if (!st)
				return TC_ACT_UNSPEC;
		}
	}

	/* PERCPU_HASH: this CPU's own value, no atomic needed. */
	st->segments++;

	now = bpf_ktime_get_ns();
	bloom_maybe_roll_epoch(now);

	seq = bpf_ntohl(tcph->seq);
	is_retrans = 0;

	if (payload_len > 0) {
		seq_key = seq >> 4;
		is_retrans = bloom_test_and_set(iph->saddr, iph->daddr, tcph->source,
						tcph->dest, seq_key);
	} else if (syn && !tcph->ack) {
		is_retrans = bloom_test_and_set(iph->saddr, iph->daddr, tcph->source,
						tcph->dest, seq);
	}

	if (is_retrans)
		st->retransmits++;

	st->last_update_ns = now;

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";