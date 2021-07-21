// +build ignore

#include <linux/types.h>
#include <linux/byteorder.h>

#include <stddef.h>

// #include <linux/if_packet.h>

#include <linux/in.h>		// proto type
#include <linux/if_ether.h> // l2
#include <linux/ip.h>		// l3
#include <linux/tcp.h>		// l4 struct tcphdr
#include <linux/udp.h>		// l4 struct udphdr

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// -----------------------

#include <bpf/ctx/skb.h>

#define XDPACL_DEBUG

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif

// cacheline alignment
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES 64
#endif

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

// likely optimization
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

// FIXED value
#define ETH_HDR_SIZE 14
#define IP_HDR_SIZE 20
#define TCP_HDR_SIZE 20
#define UDP_HDR_SIZE 8

// struct
// {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, __u32);
// 	__type(value, __u64);
// 	__uint(max_entries, 1);
// } packets SEC(".maps");

// SEC("socket")
// int count_packets(struct __sk_buff *skb)
// {
// 	if (skb->pkt_type != PACKET_OUTGOING)
// 		return 0;

// 	__u32 index = 0;
// 	__u64 *value = bpf_map_lookup_elem(&packets, &index);
// 	if (value)
// 		__sync_fetch_and_add(value, 1);

// 	return 0;
// }

/* ---------------------- */
struct hdr_cursor
{
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
										struct ethhdr **ethhdr_l2)
{
	*ethhdr_l2 = nh->pos;

#ifdef XDPACL_DEBUG
	char msg1[] = "sizeof(struct ethhdr): %u; ETH_HDR_SIZE: %u; isequal: %u\n";
	bpf_trace_printk(msg1, sizeof(msg1), sizeof(struct ethhdr), ETH_HDR_SIZE, sizeof(struct ethhdr) == ETH_HDR_SIZE ? 1 : 0);

	char msg2[] = "differ: %u;\n";
	bpf_trace_printk(msg2, sizeof(msg2), ((void *)(*ethhdr_l2 + 1) - (void *)(*ethhdr_l2)));
#endif

	//  Byte-count bounds check; check if current pointer + size of header is after data_end.
	if ((void *)((*ethhdr_l2) + 1) > data_end)
	{
		return -1;
	}

	nh->pos += ETH_HDR_SIZE;

	return (*ethhdr_l2)->h_proto; // network-byte-order
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
									   void *data_end,
									   struct iphdr **iphdr_l3)
{
	*iphdr_l3 = nh->pos;

#ifdef XDPACL_DEBUG
	char msg1[] = "sizeof(struct iphdr): %u; IP_HDR_SIZE: %u; isequal: %u\n";
	bpf_trace_printk(msg1, sizeof(msg1), sizeof(struct iphdr), IP_HDR_SIZE, sizeof(struct iphdr) == IP_HDR_SIZE ? 1 : 0);

	char msg2[] = "differ: %u;\n";
	bpf_trace_printk(msg2, sizeof(msg2), ((void *)((*iphdr_l3) + 1) - (void *)(*iphdr_l3)));
#endif

	if ((void *)((*iphdr_l3) + 1) > data_end)
	{
		return -1;
	}

	int hdrsize = ((*iphdr_l3)->ihl) << 2; // * 4

	// Sanity check packet field is valid
	if (hdrsize < IP_HDR_SIZE)
	{
		return -1;
	}

	// Variable-length IPv4 header, need to use byte-based arithmetic
	nh->pos += hdrsize;
	if (nh->pos > data_end)
	{
		return -1;
	}

	return (*iphdr_l3)->protocol;
}

// parse the udp header and return the length of the udp payload
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
										void *data_end,
										struct udphdr **udphdr_l4)
{
	*udphdr_l4 = nh->pos;

#ifdef XDPACL_DEBUG
	char msg1[] = "sizeof(struct udphdr): %u; UDP_HDR_SIZE: %u; isequal: %u\n";
	bpf_trace_printk(msg1, sizeof(msg1), sizeof(struct udphdr), UDP_HDR_SIZE, sizeof(struct udphdr) == UDP_HDR_SIZE ? 1 : 0);

	char msg2[] = "differ: %u;\n";
	bpf_trace_printk(msg2, sizeof(msg2), ((void *)((*udphdr_l4) + 1) - (void *)(*udphdr_l4)));
#endif

	if ((void *)((*udphdr_l4) + 1) > data_end)
	{
		return -1;
	}

	nh->pos += UDP_HDR_SIZE;

	int len = bpf_ntohs((*udphdr_l4)->len) - UDP_HDR_SIZE;
	if (len < 0)
	{
		return -1;
	}

	return len;
}

struct bpf_map_def SEC("maps") frame_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 32,
};

SEC("xdp_acl")
int xdp_acl_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh = {.pos = data};
	int proto_type;
	struct ethhdr *ethhdr_l2;

	proto_type = parse_ethhdr(&nh, data_end, &ethhdr_l2);
	if (bpf_htons(ETH_P_IP) == proto_type)
	{
		struct iphdr *iphdr_l3;
		proto_type = parse_iphdr(&nh, data_end, &iphdr_l3);
		if (likely(IPPROTO_UDP == proto_type))
		{
#ifdef XDPACL_DEBUG
			char msg1[] = "receive UDP pkt\n";
			bpf_trace_printk(msg1, sizeof(msg1));
#endif

			struct udphdr *udphdr_l4;
			if (parse_udphdr(&nh, data_end, &udphdr_l4) < 0)
			{
				return XDP_DROP;
			}

			if (bpf_ntohs(udphdr_l4->dest) == 9898)
			{
#ifdef XDPACL_DEBUG
				char msg1[] = "receive target UDP pkt\n";
				bpf_trace_printk(msg1, sizeof(msg1));
#endif
			}

			return XDP_PASS;
		}
	}
	else
	{
		return XDP_PASS;
	}

	return XDP_PASS;
}


SEC("classifier_tc_say")
int tc_say(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	//   if (is_TCP(data, data_end))
	//     return TC_ACT_SHOT;

#ifdef XDPACL_DEBUG
	char msg1[] = "I`m TC\n";
	bpf_trace_printk(msg1, sizeof(msg1));
#endif

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

// SEC("xdp_stats1")
// int  xdp_stats1_func(struct xdp_md *ctx)
// {
// 	// void *data_end = (void *)(long)ctx->data_end;
// 	// void *data     = (void *)(long)ctx->data;
// 	struct datarec *rec;
// 	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

// 	/* Lookup in kernel BPF-side return pointer to actual data record */
// 	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
// 	/* BPF kernel-side verifier will reject program if the NULL pointer
// 	 * check isn't performed here. Even-though this is a static array where
// 	 * we know key lookup XDP_PASS always will succeed.
// 	 */
// 	if (!rec)
// 		return XDP_ABORTED;

// 	/* Multiple CPUs can access data record. Thus, the accounting needs to
// 	 * use an atomic operation.
// 	 */
// 	lock_xadd(&rec->rx_packets, 1);
//         /* Assignment#1: Add byte counters
//          * - Hint look at struct xdp_md *ctx (copied below)
//          *
//          * Assignment#3: Avoid the atomic operation
//          * - Hint there is a map type named BPF_MAP_TYPE_PERCPU_ARRAY
//          */

// 	return XDP_PASS;
// }

/* ---------------- */

// int index = ctx->rx_queue_index;

// // char msg1[] = "nic queue idx: %d is not in xsks_map;\n";
// // bpf_trace_printk(msg1, sizeof(msg1), index);

// __u64 key = 1;
// __u64 *value = bpf_map_lookup_elem(&frame_count, &key);

// if (value)
// {
// 	__sync_fetch_and_add(value, 1);

// 	char msg1[] = "receive %d frame\n";
// 	bpf_trace_printk(msg1, sizeof(msg1), (int)*value);
// }

// return XDP_DROP;
// // return XDP_PASS;