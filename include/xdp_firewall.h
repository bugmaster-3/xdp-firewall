#ifndef __XDP_FIREWALL_H
#define __XDP_FIREWALL_H

#include <linux/types.h>

/* ──────────────────────────── Limits ──────────────────────────── */

#define MAX_BLOCKED_IPS      65536
#define MAX_BLOCKED_PORTS    1024
#define MAX_TRACKED_IPS      131072
#define MAX_WHITELISTED_IPS  4096
#define NS_PER_SEC           1000000000ULL

/* ──────────────────────────── Stats Keys ──────────────────────── */

enum stats_key {
    STATS_TOTAL        = 0,
    STATS_PASSED       = 1,
    STATS_BLOCKED_IP   = 2,
    STATS_BLOCKED_PORT = 3,
    STATS_BLOCKED_PROTO= 4,
    STATS_RATE_LIMITED = 5,
    STATS_SYN_FLOOD    = 6,
    STATS_WHITELISTED  = 7,
    STATS_MAX          = 8,
};

/* ──────────────────────────── Structs ──────────────────────────── */

/* Metadata attached to each block rule */
struct rule_meta {
    __u64 added_at;      /* epoch timestamp when rule was added */
    __u64 hit_count;     /* number of times this rule matched */
    __u32 expire_at;     /* 0 = permanent, else epoch seconds */
    char  comment[64];   /* human-readable label */
};

/* Per-IP rate limit tracking */
struct rate_limit_entry {
    __u64 last_reset;    /* nanosecond timestamp of last window reset */
    __u32 packet_count;  /* packets seen in current window */
    __u32 _pad;
};

/* Global firewall configuration (loaded into fw_config_map) */
struct fw_config {
    __u8  enabled;           /* master on/off switch */
    __u8  block_icmp;        /* drop all ICMP/ICMPv6 */
    __u8  enable_rate_limit; /* enable per-IP rate limiting */
    __u8  syn_flood_protect; /* enable SYN flood protection */
    __u32 pps_limit;         /* max packets/sec per source IP */
    __u32 syn_limit;         /* max SYN packets/sec per source IP */
    __u8  default_deny;      /* 1 = deny everything not whitelisted */
    __u8  _pad[3];
};

/* Userspace event passed via perf/ring buffer (future use) */
struct fw_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  action;    /* XDP_DROP=1, XDP_PASS=2 */
    __u8  reason;    /* which rule triggered */
    __u8  _pad;
    __u64 timestamp;
};

/* Actions (mirrors XDP actions for userspace) */
#define FW_ACTION_PASS  0
#define FW_ACTION_DROP  1

/* Block reasons */
#define REASON_IP_BLOCKLIST   0
#define REASON_PORT_BLOCKLIST 1
#define REASON_RATE_LIMIT     2
#define REASON_SYN_FLOOD      3
#define REASON_PROTO_FILTER   4
#define REASON_DEFAULT_DENY   5

#endif /* __XDP_FIREWALL_H */
