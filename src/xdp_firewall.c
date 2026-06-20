// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_firewall.c - XDP-based firewall running at NIC driver level
 *
 * This program attaches to the XDP hook and filters packets before
 * they enter the kernel network stack — zero overhead for dropped packets.
 *
 * Supports:
 *   - IP blocklist (IPv4 + IPv6)
 *   - Port blocklist (TCP/UDP)
 *   - Rate limiting per source IP
 *   - Protocol filtering
 *   - Geo-IP blocking (via userspace map updates)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/xdp_firewall.h"

/* ──────────────────────────── BPF Maps ──────────────────────────── */

/* Blocklisted IPv4 addresses */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __u32);
    __type(value, struct rule_meta);
} ipv4_blocklist SEC(".maps");

/* Blocklisted IPv6 addresses */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, struct in6_addr);
    __type(value, struct rule_meta);
} ipv6_blocklist SEC(".maps");

/* Blocklisted destination ports */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_PORTS);
    __type(key, __u16);
    __type(value, struct rule_meta);
} port_blocklist SEC(".maps");

/* Per-IP rate limiting: tracks packet count per second */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_IPS);
    __type(key, __u32);
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

/* Global firewall config (single entry, key=0) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fw_config);
} fw_config_map SEC(".maps");

/* Per-CPU statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/* Allowed source IP whitelist (overrides blocklist) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELISTED_IPS);
    __type(key, __u32);
    __type(value, __u8);
} ipv4_whitelist SEC(".maps");

/* ──────────────────────────── Helpers ──────────────────────────── */

static __always_inline void stats_inc(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int check_rate_limit(__u32 src_ip, __u32 pps_limit)
{
    struct rate_limit_entry *entry;
    struct rate_limit_entry new_entry = {};
    __u64 now = bpf_ktime_get_ns();

    entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (!entry) {
        new_entry.last_reset = now;
        new_entry.packet_count = 1;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY);
        return XDP_PASS;
    }

    /* Reset counter every second */
    if (now - entry->last_reset > NS_PER_SEC) {
        entry->last_reset = now;
        entry->packet_count = 1;
        return XDP_PASS;
    }

    entry->packet_count++;
    if (entry->packet_count > pps_limit) {
        stats_inc(STATS_RATE_LIMITED);
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int parse_ipv4(struct xdp_md *ctx,
                                       void *data, void *data_end,
                                       struct fw_config *cfg)
{
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_ABORTED;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u8  proto  = iph->protocol;

    /* Whitelist check — always allow */
    if (bpf_map_lookup_elem(&ipv4_whitelist, &src_ip)) {
        stats_inc(STATS_WHITELISTED);
        return XDP_PASS;
    }

    /* IP blocklist check */
    if (bpf_map_lookup_elem(&ipv4_blocklist, &src_ip)) {
        stats_inc(STATS_BLOCKED_IP);
        return XDP_DROP;
    }

    /* Protocol filter */
    if (cfg->block_icmp && proto == IPPROTO_ICMP) {
        stats_inc(STATS_BLOCKED_PROTO);
        return XDP_DROP;
    }

    /* Rate limiting */
    if (cfg->enable_rate_limit) {
        int rc = check_rate_limit(src_ip, cfg->pps_limit);
        if (rc == XDP_DROP)
            return XDP_DROP;
    }

    /* TCP/UDP port filtering */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return XDP_ABORTED;

        __u16 dst_port = bpf_ntohs(tcph->dest);
        if (bpf_map_lookup_elem(&port_blocklist, &dst_port)) {
            stats_inc(STATS_BLOCKED_PORT);
            return XDP_DROP;
        }

        /* SYN flood protection */
        if (cfg->syn_flood_protect && tcph->syn && !tcph->ack) {
            int rc = check_rate_limit(src_ip, cfg->syn_limit);
            if (rc == XDP_DROP) {
                stats_inc(STATS_SYN_FLOOD);
                return XDP_DROP;
            }
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return XDP_ABORTED;

        __u16 dst_port = bpf_ntohs(udph->dest);
        if (bpf_map_lookup_elem(&port_blocklist, &dst_port)) {
            stats_inc(STATS_BLOCKED_PORT);
            return XDP_DROP;
        }
    }

    stats_inc(STATS_PASSED);
    return XDP_PASS;
}

static __always_inline int parse_ipv6(struct xdp_md *ctx,
                                       void *data, void *data_end,
                                       struct fw_config *cfg)
{
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_ABORTED;

    if (bpf_map_lookup_elem(&ipv6_blocklist, &ip6h->saddr)) {
        stats_inc(STATS_BLOCKED_IP);
        return XDP_DROP;
    }

    __u8 proto = ip6h->nexthdr;
    if (cfg->block_icmp && (proto == IPPROTO_ICMPV6)) {
        stats_inc(STATS_BLOCKED_PROTO);
        return XDP_DROP;
    }

    stats_inc(STATS_PASSED);
    return XDP_PASS;
}

/* ──────────────────────────── Main XDP Hook ──────────────────────────── */

SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    stats_inc(STATS_TOTAL);

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    /* Load global config */
    __u32 cfg_key = 0;
    struct fw_config *cfg = bpf_map_lookup_elem(&fw_config_map, &cfg_key);
    if (!cfg)
        return XDP_PASS; /* no config = passthrough */

    /* Firewall kill switch */
    if (!cfg->enabled)
        return XDP_PASS;

    __u16 eth_type = bpf_ntohs(eth->h_proto);

    if (eth_type == ETH_P_IP)
        return parse_ipv4(ctx, data, data_end, cfg);

    if (eth_type == ETH_P_IPV6)
        return parse_ipv6(ctx, data, data_end, cfg);

    /* Pass non-IP traffic (ARP, etc.) */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
