/*
 * xdp_firewall_user.c - Userspace control daemon for xdp-firewall
 *
 * Responsibilities:
 *   - Load and attach the XDP BPF program to a network interface
 *   - Manage blocklist/whitelist map entries
 *   - Display real-time statistics
 *   - Load rules from config file
 *   - Graceful detach on exit (SIGINT/SIGTERM)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../include/xdp_firewall.h"

/* ──────────────────────────── Globals ──────────────────────────── */

static volatile int running = 1;
static int ifindex = -1;
static struct bpf_object *obj = NULL;
static int prog_fd = -1;

/* Map FDs */
static int ipv4_blocklist_fd = -1;
static int ipv4_whitelist_fd = -1;
static int port_blocklist_fd = -1;
static int fw_config_fd      = -1;
static int stats_fd          = -1;
static int rate_limit_fd     = -1;

/* ──────────────────────────── Signal Handler ──────────────────────────── */

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* ──────────────────────────── Map Helpers ──────────────────────────── */

static int block_ipv4(const char *ip_str, const char *comment)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IPv4: %s\n", ip_str);
        return -1;
    }

    struct rule_meta meta = {
        .added_at  = (uint64_t)time(NULL),
        .hit_count = 0,
        .expire_at = 0,
    };
    strncpy(meta.comment, comment ? comment : "", sizeof(meta.comment) - 1);

    __u32 key = addr.s_addr;
    if (bpf_map_update_elem(ipv4_blocklist_fd, &key, &meta, BPF_ANY)) {
        perror("bpf_map_update_elem (ipv4_blocklist)");
        return -1;
    }

    printf("[+] Blocked IPv4: %s (%s)\n", ip_str, comment ? comment : "no comment");
    return 0;
}

static int unblock_ipv4(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IPv4: %s\n", ip_str);
        return -1;
    }

    __u32 key = addr.s_addr;
    if (bpf_map_delete_elem(ipv4_blocklist_fd, &key)) {
        perror("bpf_map_delete_elem");
        return -1;
    }

    printf("[-] Unblocked IPv4: %s\n", ip_str);
    return 0;
}

static int whitelist_ipv4(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IPv4: %s\n", ip_str);
        return -1;
    }

    __u8 val = 1;
    __u32 key = addr.s_addr;
    if (bpf_map_update_elem(ipv4_whitelist_fd, &key, &val, BPF_ANY)) {
        perror("bpf_map_update_elem (ipv4_whitelist)");
        return -1;
    }

    printf("[+] Whitelisted IPv4: %s\n", ip_str);
    return 0;
}

static int block_port(__u16 port, const char *comment)
{
    struct rule_meta meta = {
        .added_at  = (uint64_t)time(NULL),
        .hit_count = 0,
        .expire_at = 0,
    };
    strncpy(meta.comment, comment ? comment : "", sizeof(meta.comment) - 1);

    __u16 key = port;
    if (bpf_map_update_elem(port_blocklist_fd, &key, &meta, BPF_ANY)) {
        perror("bpf_map_update_elem (port_blocklist)");
        return -1;
    }

    printf("[+] Blocked port: %u (%s)\n", port, comment ? comment : "no comment");
    return 0;
}

static int set_fw_config(struct fw_config *cfg)
{
    __u32 key = 0;
    if (bpf_map_update_elem(fw_config_fd, &key, cfg, BPF_ANY)) {
        perror("bpf_map_update_elem (fw_config)");
        return -1;
    }
    return 0;
}

/* ──────────────────────────── Stats Display ──────────────────────────── */

static const char *stat_names[] = {
    [STATS_TOTAL]        = "Total packets",
    [STATS_PASSED]       = "Passed",
    [STATS_BLOCKED_IP]   = "Blocked (IP)",
    [STATS_BLOCKED_PORT] = "Blocked (Port)",
    [STATS_BLOCKED_PROTO]= "Blocked (Proto)",
    [STATS_RATE_LIMITED] = "Rate limited",
    [STATS_SYN_FLOOD]    = "SYN flood drops",
    [STATS_WHITELISTED]  = "Whitelisted",
};

static void print_stats(void)
{
    int ncpus = libbpf_num_possible_cpus();
    __u64 values[ncpus];

    printf("\n┌─────────────────────────────────────────┐\n");
    printf("│          XDP Firewall Statistics        │\n");
    printf("├─────────────────────────────────────────┤\n");

    for (int i = 0; i < STATS_MAX; i++) {
        __u32 key = i;
        __u64 total = 0;

        if (bpf_map_lookup_elem(stats_fd, &key, values) == 0) {
            for (int c = 0; c < ncpus; c++)
                total += values[c];
        }

        printf("│ %-28s %10llu │\n", stat_names[i], total);
    }

    printf("└─────────────────────────────────────────┘\n");
}

/* ──────────────────────────── Config File Parser ──────────────────────────── */

/*
 * Simple config format:
 *   block_ip   1.2.3.4       # comment
 *   block_port 22            # SSH
 *   whitelist  10.0.0.1
 *   rate_limit 1000          # pps per IP
 */
static int load_config_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen config");
        return -1;
    }

    char line[256];
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* Strip comments */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';

        char cmd[32], arg[128];
        if (sscanf(line, "%31s %127s", cmd, arg) != 2)
            continue;

        if (strcmp(cmd, "block_ip") == 0) {
            block_ipv4(arg, NULL);
        } else if (strcmp(cmd, "block_port") == 0) {
            block_port((uint16_t)atoi(arg), NULL);
        } else if (strcmp(cmd, "whitelist") == 0) {
            whitelist_ipv4(arg);
        } else {
            fprintf(stderr, "Unknown directive '%s' at line %d\n", cmd, lineno);
        }
    }

    fclose(f);
    return 0;
}

/* ──────────────────────────── Attach / Detach ──────────────────────────── */

static int attach_xdp(int ifindex, int prog_fd, __u32 flags)
{
    int err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP to ifindex %d: %s\n",
                ifindex, strerror(-err));
        return err;
    }
    return 0;
}

static void detach_xdp(int ifindex, __u32 flags)
{
    bpf_xdp_detach(ifindex, flags, NULL);
    printf("\n[*] XDP program detached from interface.\n");
}

/* ──────────────────────────── Usage ──────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -i <iface>      Network interface to attach to (required)\n"
        "  -c <config>     Path to rules config file\n"
        "  -b <ip>         Block an IPv4 address\n"
        "  -u <ip>         Unblock an IPv4 address\n"
        "  -w <ip>         Whitelist an IPv4 address\n"
        "  -p <port>       Block a destination port\n"
        "  -r <pps>        Enable rate limiting (packets per second)\n"
        "  -s              Show stats and exit\n"
        "  -n              Use native XDP mode (default: generic)\n"
        "  -o <file>       Path to XDP BPF object file\n"
        "  -h              Show this help\n"
        "\n"
        "Examples:\n"
        "  %s -i eth0 -b 1.2.3.4 -p 22\n"
        "  %s -i eth0 -c /etc/xdp-firewall/rules.conf -r 1000\n"
        "  %s -i eth0 -s\n",
        prog, prog, prog, prog);
}

/* ──────────────────────────── Main ──────────────────────────── */

int main(int argc, char **argv)
{
    const char *iface      = NULL;
    const char *config_file = NULL;
    const char *obj_path   = "xdp_firewall.o";
    const char *block_ip   = NULL;
    const char *unblock_ip = NULL;
    const char *wl_ip      = NULL;
    int         block_port_num = -1;
    int         pps_limit  = 0;
    int         show_stats = 0;
    __u32       xdp_flags  = XDP_FLAGS_SKB_MODE; /* generic mode default */

    int opt;
    while ((opt = getopt(argc, argv, "i:c:b:u:w:p:r:sno:h")) != -1) {
        switch (opt) {
        case 'i': iface       = optarg; break;
        case 'c': config_file = optarg; break;
        case 'b': block_ip    = optarg; break;
        case 'u': unblock_ip  = optarg; break;
        case 'w': wl_ip       = optarg; break;
        case 'p': block_port_num = atoi(optarg); break;
        case 'r': pps_limit   = atoi(optarg); break;
        case 's': show_stats  = 1; break;
        case 'n': xdp_flags   = XDP_FLAGS_DRV_MODE; break;
        case 'o': obj_path    = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (!iface) {
        fprintf(stderr, "Error: interface (-i) is required\n");
        usage(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Interface not found: %s\n", iface);
        return 1;
    }

    /* Load BPF object */
    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    /* Get program FD */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_firewall_prog");
    if (!prog) {
        fprintf(stderr, "BPF program 'xdp_firewall_prog' not found\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    /* Get map FDs */
#define GET_MAP(name, fd) do { \
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name); \
    if (!m) { fprintf(stderr, "Map not found: %s\n", name); return 1; } \
    fd = bpf_map__fd(m); \
} while (0)

    GET_MAP("ipv4_blocklist", ipv4_blocklist_fd);
    GET_MAP("ipv4_whitelist", ipv4_whitelist_fd);
    GET_MAP("port_blocklist", port_blocklist_fd);
    GET_MAP("fw_config_map",  fw_config_fd);
    GET_MAP("stats_map",      stats_fd);
    GET_MAP("rate_limit_map", rate_limit_fd);

    /* Attach XDP program */
    if (attach_xdp(ifindex, prog_fd, xdp_flags))
        return 1;

    printf("[*] XDP firewall attached to %s (ifindex=%d)\n", iface, ifindex);

    /* Register signal handlers */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Apply initial config */
    struct fw_config cfg = {
        .enabled           = 1,
        .block_icmp        = 0,
        .enable_rate_limit = pps_limit > 0,
        .syn_flood_protect = 1,
        .pps_limit         = pps_limit > 0 ? pps_limit : 10000,
        .syn_limit         = 100,
        .default_deny      = 0,
    };
    set_fw_config(&cfg);

    /* Apply CLI rules */
    if (config_file)     load_config_file(config_file);
    if (block_ip)        block_ipv4(block_ip, "cli");
    if (unblock_ip)      unblock_ipv4(unblock_ip);
    if (wl_ip)           whitelist_ipv4(wl_ip);
    if (block_port_num > 0) block_port((__u16)block_port_num, "cli");

    if (show_stats) {
        print_stats();
        detach_xdp(ifindex, xdp_flags);
        bpf_object__close(obj);
        return 0;
    }

    /* Main loop — print stats every 2s */
    printf("[*] Running. Press Ctrl+C to stop.\n\n");
    while (running) {
        sleep(2);
        print_stats();
    }

    detach_xdp(ifindex, xdp_flags);
    bpf_object__close(obj);
    return 0;
}
