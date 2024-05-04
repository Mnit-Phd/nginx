#include <linux/string.h>
#include <linux/udp.h>
#include <linux/bpf.h>
// #include <linux/if_ether.h>
#include <linux/ip.h>
#include <bcc/proto.h>
#include <bpf/bpf_helpers.h>
// #include <bcc/compat/linux/bpf.h>


#if !defined(SEC)
#define SEC(NAME)  __attribute__((section(NAME), used))
#endif


#if defined(LICENSE_GPL)

//GET /block.html -> allow
//PUT, POST, DELETE -> disallow -> 403 forbidden

/*
 * To see debug:
 *
 *  echo 1 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 *  cat /sys/kernel/debug/tracing/trace_pipe
 *  echo 0 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 */

#define debugmsg(fmt, ...)                                                    \
do {                                                                          \
    char __buf[] = fmt;                                                       \
    bpf_trace_printk(__buf, sizeof(__buf), ##__VA_ARGS__);                    \
} while (0)

#else

#define debugmsg(fmt, ...)

#endif

#define IP_TCP 	6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define cursor_advance(_cursor, _len) \
        ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

struct Key {
	__u32 src_ip;               //source ip
	__u32 dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct Leaf {
	int timestamp;            //timestamp in ns
};

#define bpf_memcpy __builtin_memcpy
#define ARRAYSIZE 512 // size of 403 response

char buf[ARRAYSIZE];
// BPF_ARRAY(lookupTable, char, ARRAYSIZE);

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
// BPF_HASH(sessions, struct Key, struct Leaf, 1024);

char _license[] SEC("license") = LICENSE;

/*****************************************************************************/


// #define advance_data(nbytes)                                                  \
//     offset += nbytes;                                                         \
//     if (start + offset > end) {                                               \
//         debugmsg("cannot read %ld bytes at offset %ld", nbytes, offset);      \
//         goto failed;                                                          \
//     }                                                                         \
//     data = start + offset - 1;

// /*
//  * actual map object is created by the "bpf" system call,
//  * all pointers to this variable are replaced by the bpf loader
//  */
// struct bpf_map_def SEC("maps") ngx_quic_sockmap;

void swap_mac(struct __sk_buff *skb, struct ethhdr *eth)
{
	/* Let's grab the MAC address.
	 * We need to copy them out, as they are 48 bits long */
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
	bpf_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

	/* Swap the MAC addresses */
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);
}

void swap_ip(struct iphdr *ip, struct __sk_buff *skb)
{
	/* Let's grab the IP addresses.
	 * They are 32-bit, so it is easy to access */
	__u32 src_ip = ip->saddr;
	__u32 dst_ip = ip->daddr;

	/* Swap the IP addresses.
	 * IP contains a checksum, but just swapping bytes does not change it.
	 * so no need to recalculate */
	bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
	bpf_skb_store_bytes(skb, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);

}

SEC(PROGNAME)
int filter_http_packets(struct __sk_buff *skb)
{
    __u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}

	// int ifindex = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
// | eth-header | ip-header | tcp-header | tcp-payload |
//										 | http-header | http payload|

// 10k, 5k, 5k(block)[2.5k->GET block ->success, 403(2.5k)]
	__u32  tcp_header_length = 0;
	__u32  ip_header_length = 0;
	__u32  payload_offset = 0;
	__u32  payload_length = 0;
	struct Key 	key;
	struct Leaf zero = {0};

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

	//check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) {
			goto DROP;
	}

	//shift cursor forward for dynamic ip header size
	void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	//retrieve ip src/dest and port src/dest of current packet
	//and save it into struct Key
	key.dst_ip = ip->dst;
	key.src_ip = ip->src;
	key.dst_port = tcp->dst_port;
	key.src_port = tcp->src_port;

	//calculate tcp header length
	//value to multiply *4
	//e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	//calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

	//minimum length of http request is always geater than 7 bytes
	//avoid invalid access memory
	//include empty payload
	if(payload_length < 7) {
		goto DROP;
	}

	//load first 10 byte of payload into p (payload_array)
	//direct access to skb not allowed
	char p[10];
	int i = 0;
    debugmsg("Packet --->")
	// for (i = 0; i < 10; i++) {
	// 	p[i] = load_byte(skb, payload_offset + i);
    //     debugmsg("0x%llx", p[i])
	// }

	bpf_skb_load_bytes(skb, payload_offset, p, 10);

	//GET /block*
	if (bpf_strncmp(p, 10, "GET /block"))
	{
		goto KEEP;
	}
	else
	{
		goto DROP;
	}

	// //no HTTP match
	// //check if packet belong to an HTTP session
	// struct Leaf * lookup_leaf = sessions.lookup(&key);
	// if(lookup_leaf) {
	// 	//send packet to userspace
	// 	goto KEEP;
	// }
	// goto DROP;

	//keep the packet and send it to userspace returning -1
	// HTTP_MATCH:
		//if not already present, insert into map <Key, Leaf>
		// sessions.lookup_or_try_init(&key, &zero);

	//send packet to userspace returning -1
	KEEP:
		return -1;

	//drop the packet returning 0
	// Generate 403 forbidden here and send back the response
	DROP:
		// __u32 key = 0;
		// struct response_403 *response = bpf_map_lookup_elem(&lookupTable, &key);
		if (buf != NULL)
		{
			// swap mac
			swap_mac(skb, ethernet);
			// swap IP
			swap_ip(ip, skb);
			//swap ports

			// update response
			// long bpf_skb_change_tail(struct sk_buff *skb, u32 len, u64 flags)
			bpf_skb_store_bytes(skb, payload_offset, buf, sizeof(buf), BPF_F_RECOMPUTE_CSUM);
			bpf_redirect(skb->ifindex, 0); 
			// vs bpf_clone_redirect(skb, skb->ifindex, 0)
		}
		return 0;
}
