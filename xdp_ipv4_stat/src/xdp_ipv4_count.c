#define KBUILD_MODNAME "MINA"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>


BPF_TABLE("percpu_array", uint32_t, long, ip4cnt, 256);
BPF_TABLE("percpu_array", uint32_t, long, icmpcnt, 256);
BPF_TABLE("percpu_array", uint32_t, long, tcportcnt, 65536);
BPF_TABLE("percpu_array", uint32_t, long, udportcnt, 65536);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

static __always_inline int get_port(void *data, void *data_end, u64 nh_off)
{
    struct tcphdr *th;
    struct udphdr *uh;
    struct icmphdr *ih;
    struct iphdr *iph = data + nh_off;
    u8 protocol = iph->protocol;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)(iph +1);
            if (th + 1 > data_end)
                return -1;
            //bpf_trace_printk("prot %d %d : %d\n",protocol,ntohs(th->source),ntohs(th->dest));
            return ntohs(th->source);
        case IPPROTO_UDP:
            uh = (struct udphdr *)(iph+1);
            if (uh + 1 > data_end)
                return -1;
            return ntohs(uh->dest);
        case IPPROTO_ICMP:
            ih = (struct icmphdr *)(iph +1);
            if (ih + 1 > data_end)
                return -1;
            return ih->type;
        default:
            return 0;
    }
}

int ipv4_count(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    u32 *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;
    int32_t port;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP)) {
        index = parse_ipv4(data, nh_off, data_end);
    }
#if 0
    else if (h_proto == htons(ETH_P_IPV6))
        index = parse_ipv6(data, nh_off, data_end);
#endif
    else
        index = 0;


    if (0 != index) {
        value = ip4cnt.lookup(&index);
        if (value) {
            *value += 1;
        }
        port = get_port(data,data_end,nh_off);
        if ( -1 != port) {
            switch (index) {
                case IPPROTO_TCP:
                    value = tcportcnt.lookup(&port);
                    break;
                case IPPROTO_UDP:
                    value = udportcnt.lookup(&port);
                    break;
                case IPPROTO_ICMP:
                    value = icmpcnt.lookup(&port);
                    break;
                default:
                    return XDP_PASS;
            }
            if (value) {
                *value += 1;
            }
        }
    }

    return XDP_PASS;
}
