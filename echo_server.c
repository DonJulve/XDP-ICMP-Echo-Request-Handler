#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Definir una estructura ICMPv6 sin entrar en conflicto con las macros del sistema
struct custom_icmpv6hdr {
    __u8 icmp6_type;      // ICMPv6 type
    __u8 icmp6_code;      // ICMPv6 code
    __u16 icmp6_cksum;    // ICMPv6 checksum
    union {
        __u32 icmp6_custom_identifier;
        __u32 icmp6_custom_reserved;
    };
    __u32 icmp6_custom_sequence;
};

SEC("xdp")
int xdp_icmp_echo(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // Intercambio de direcciones MAC (origen <-> destino)
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Procesar IP (IPv4)
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Si es un paquete ICMP sobre IPv4
    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
        if ((void *)(icmp + 1) > data_end) return XDP_PASS;

        // Verifica que sea un Echo Request
        if (icmp->type == ICMP_ECHO) {
            // Intercambiar direcciones IP (origen <-> destino)
            __u32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            // Cambiar tipo de ICMP: ICMP_ECHOREPLY
            __u16 old_type = icmp->type;
            icmp->type = ICMP_ECHOREPLY;

            // Actualizar checksum (RFC 1624)
            __u32 csum_diff = bpf_csum_diff((__be32 *)&old_type, sizeof(old_type), (__be32 *)&icmp->type, sizeof(icmp->type), 0);
            icmp->checksum = ~((~icmp->checksum) + csum_diff);

            return XDP_TX;
        }
    }

    // Procesar ICMPv6
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end) return XDP_PASS;

    if (ipv6->nexthdr == IPPROTO_ICMPV6) {
        struct custom_icmpv6hdr *icmpv6 = (struct custom_icmpv6hdr *)(ipv6 + 1);
        if ((void *)(icmpv6 + 1) > data_end) return XDP_PASS;

        // Verifica que sea un Echo Request (ICMPv6)
        if (icmpv6->icmp6_type == ICMPV6_ECHO_REQUEST) {
            // Intercambiar direcciones IPv6 (origen <-> destino)
            __u8 tmp_ip6[16];
            __builtin_memcpy(tmp_ip6, &ipv6->saddr, 16);
            __builtin_memcpy(&ipv6->saddr, &ipv6->daddr, 16);
            __builtin_memcpy(&ipv6->daddr, tmp_ip6, 16);

            // Cambiar tipo de ICMPv6: ICMPV6_ECHO_REPLY
            __u16 old_type_v6 = icmpv6->icmp6_type;
            icmpv6->icmp6_type = ICMPV6_ECHO_REPLY;

            // Actualizar checksum para ICMPv6 (RFC 1624)
            __u32 csum_diff_v6 = bpf_csum_diff((__be32 *)&old_type_v6, sizeof(old_type_v6), (__be32 *)&icmpv6->icmp6_type, sizeof(icmpv6->icmp6_type), 0);
            icmpv6->icmp6_cksum = ~((~icmpv6->icmp6_cksum) + csum_diff_v6);

            return XDP_TX;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
