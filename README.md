# xdp-firewall

**Ultra-fast packet filtering at the NIC driver level using eBPF/XDP.**

Packets are dropped *before* they enter the Linux network stack — meaning zero kernel overhead for blocked traffic. No conntrack, no iptables traversal, no skb allocation for dropped packets.

```
NIC → [XDP hook] → DROP (blocked) or PASS → kernel network stack → iptables → userspace
         ↑
    We live here
```

## Features

- **IPv4 + IPv6 blocklisting** — drop by source IP
- **Port blocklisting** — TCP/UDP destination port filtering
- **Per-IP rate limiting** — packets-per-second cap per source
- **SYN flood protection** — rate-limit SYN packets independently
- **IP whitelist** — always-allow list that overrides blocklist
- **ICMP filtering** — optionally block all ICMP/ICMPv6
- **Per-CPU statistics** — real-time counters with zero lock contention
- **Live rule updates** — add/remove rules at runtime via BPF maps
- **Config file support** — load rules from `/etc/xdp-firewall/rules.conf`
- **Systemd integration** — run as a hardened system service

## Performance

XDP operates at the earliest possible point in the receive path. On a modern NIC with native XDP driver support, this means:

| Mode          | Throughput (Mpps) | Notes                        |
|---------------|------------------|------------------------------|
| Native (DRV)  | 20–60+           | Requires driver support      |
| Offloaded     | Line rate        | Requires SmartNIC            |
| Generic (SKB) | 2–5              | Works on any interface       |

> Benchmarked on Intel E810 with native XDP. Your numbers will vary.

## Requirements

- Linux kernel ≥ 5.15 (6.1+ recommended for sched_ext compatibility)
- libbpf ≥ 1.0
- clang ≥ 12
- Kernel headers for your running kernel
- Root or `CAP_NET_ADMIN` + `CAP_BPF`

### Install dependencies

```bash
# Debian/Ubuntu
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) \
                 libelf-dev gcc make

# Fedora/RHEL
sudo dnf install clang llvm libbpf-devel kernel-devel elfutils-libelf-devel gcc make

# Arch
sudo pacman -S clang llvm libbpf linux-headers
```

## Build

```bash
git clone https://github.com/yourusername/xdp-firewall
cd xdp-firewall
make
```

Outputs:
- `build/xdp_firewall.o` — BPF kernel program
- `build/xdp_firewall` — userspace control binary

## Quick Start

```bash
# Attach to eth0, block an IP and a port
sudo ./build/xdp_firewall -i eth0 -b 1.2.3.4 -p 22

# Use a rules file
sudo ./build/xdp_firewall -i eth0 -c scripts/rules.conf.example

# Native XDP mode (faster, requires driver support)
sudo ./build/xdp_firewall -i eth0 -n -c /etc/xdp-firewall/rules.conf

# Show live stats
sudo ./build/xdp_firewall -i eth0 -s
```

## CLI Reference

```
Usage: xdp_firewall [OPTIONS]

Options:
  -i <iface>      Network interface to attach to (required)
  -c <config>     Path to rules config file
  -b <ip>         Block an IPv4 address
  -u <ip>         Unblock an IPv4 address
  -w <ip>         Whitelist an IPv4 address
  -p <port>       Block a destination port
  -r <pps>        Enable rate limiting (packets per second per IP)
  -s              Show stats and exit
  -n              Use native XDP mode (default: generic)
  -o <file>       Path to XDP BPF object file
  -h              Show help
```

## Config File Format

```
# /etc/xdp-firewall/rules.conf

whitelist  10.0.0.1        # internal gateway
whitelist  127.0.0.1       # loopback

block_ip   198.51.100.1    # known scanner
block_ip   203.0.113.45    # abuse report

block_port 23              # Telnet
block_port 445             # SMB
block_port 3389            # RDP
```

## Statistics

```
┌─────────────────────────────────────────┐
│          XDP Firewall Statistics        │
├─────────────────────────────────────────┤
│ Total packets               1000000     │
│ Passed                       998432     │
│ Blocked (IP)                   1234     │
│ Blocked (Port)                  200     │
│ Blocked (Proto)                   0     │
│ Rate limited                    100     │
│ SYN flood drops                  34     │
│ Whitelisted                       0     │
└─────────────────────────────────────────┘
```

## Systemd

```bash
sudo make install
sudo systemctl enable --now xdp-firewall@eth0
sudo systemctl status xdp-firewall@eth0
```

## Testing

```bash
# Spin up a network namespace and run automated tests
sudo bash scripts/test_netns.sh

# Packet-level tests with scapy (requires scapy + root)
pip install scapy
sudo python3 tests/test_firewall.py --iface veth_host --target 192.168.99.1
```

## Architecture

```
xdp-firewall/
├── src/
│   ├── xdp_firewall.c        # BPF kernel program (runs in kernel)
│   └── xdp_firewall_user.c   # Userspace loader and map manager
├── include/
│   └── xdp_firewall.h        # Shared structs (kernel + userspace)
├── maps/                     # BPF map pinning directory (runtime)
├── scripts/
│   ├── rules.conf.example    # Example config
│   ├── test_netns.sh         # Network namespace test harness
│   └── xdp-firewall.service  # Systemd unit
├── tests/
│   └── test_firewall.py      # Scapy packet-level tests
└── Makefile
```

## BPF Maps

| Map               | Type          | Key          | Value             | Purpose                    |
|-------------------|---------------|--------------|-------------------|----------------------------|
| `ipv4_blocklist`  | HASH          | u32 (IP)     | rule_meta         | Blocked IPv4 sources       |
| `ipv6_blocklist`  | HASH          | in6_addr     | rule_meta         | Blocked IPv6 sources       |
| `port_blocklist`  | HASH          | u16 (port)   | rule_meta         | Blocked dst ports          |
| `ipv4_whitelist`  | HASH          | u32 (IP)     | u8                | Always-allowed sources     |
| `rate_limit_map`  | LRU_HASH      | u32 (IP)     | rate_limit_entry  | Per-IP rate tracking       |
| `fw_config_map`   | ARRAY         | u32 (0)      | fw_config         | Global firewall config     |
| `stats_map`       | PERCPU_ARRAY  | u32          | u64               | Per-CPU packet counters    |

## Contributing

PRs welcome. Areas of interest:
- IPv6 port filtering
- Ring buffer event streaming to userspace
- bpftool skeleton-based loading
- eBPF CO-RE (Compile Once, Run Everywhere) support
- Geo-IP blocking via userspace map population
- Dynamic TTL-based rule expiry

## License

GPL-2.0 — same as the Linux kernel.
