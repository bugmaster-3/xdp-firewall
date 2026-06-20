# xdp-firewall Makefile
#
# Builds:
#   xdp_firewall.o       — BPF kernel program (loaded into the kernel via libbpf)
#   xdp_firewall_user    — Userspace control binary

# ─── Toolchain ───────────────────────────────────────────────────────────────

CLANG      ?= clang
LLC        ?= llc
CC         ?= gcc
BPFTOOL    ?= bpftool

# ─── Paths ───────────────────────────────────────────────────────────────────

SRC_DIR    := src
INC_DIR    := include
BUILD_DIR  := build
SCRIPTS_DIR:= scripts

BPF_SRC    := $(SRC_DIR)/xdp_firewall.c
USER_SRC   := $(SRC_DIR)/xdp_firewall_user.c

BPF_OBJ    := $(BUILD_DIR)/xdp_firewall.o
USER_BIN   := $(BUILD_DIR)/xdp_firewall

# ─── Kernel Headers ──────────────────────────────────────────────────────────
# Adjust KERNEL_HEADERS if your headers are in a non-default location.

KERNEL_HEADERS ?= /usr/include
ARCH           ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# ─── Flags ───────────────────────────────────────────────────────────────────

BPF_CFLAGS := \
    -O2 \
    -g \
    -Wall \
    -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I$(INC_DIR) \
    -I$(KERNEL_HEADERS) \
    -I/usr/include/bpf

USER_CFLAGS := \
    -O2 \
    -g \
    -Wall \
    -Wextra \
    -I$(INC_DIR) \
    -I$(KERNEL_HEADERS)

USER_LDFLAGS := -lbpf -lelf -lz

# ─── Targets ─────────────────────────────────────────────────────────────────

.PHONY: all clean install uninstall fmt lint help

all: $(BUILD_DIR) $(BPF_OBJ) $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile BPF kernel program
$(BPF_OBJ): $(BPF_SRC) $(INC_DIR)/xdp_firewall.h
	@echo "  CLANG  $< -> $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile userspace control binary
$(USER_BIN): $(USER_SRC) $(INC_DIR)/xdp_firewall.h
	@echo "  CC     $< -> $@"
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

# ─── Skeleton (optional, for skeleton-based loading) ─────────────────────────

skeleton: $(BPF_OBJ)
	@echo "  BPFTOOL generating skeleton..."
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(INC_DIR)/xdp_firewall.skel.h
	@echo "  Skeleton written to $(INC_DIR)/xdp_firewall.skel.h"

# ─── Formatting ──────────────────────────────────────────────────────────────

fmt:
	clang-format -i $(SRC_DIR)/*.c $(INC_DIR)/*.h

# ─── Lint ────────────────────────────────────────────────────────────────────

lint:
	clang-tidy $(USER_SRC) -- $(USER_CFLAGS)

# ─── Verify BPF bytecode ─────────────────────────────────────────────────────

verify: $(BPF_OBJ)
	$(BPFTOOL) prog load $(BPF_OBJ) /sys/fs/bpf/xdp_fw_test 2>&1 || true
	rm -f /sys/fs/bpf/xdp_fw_test

# ─── Install ─────────────────────────────────────────────────────────────────

INSTALL_BIN  := /usr/local/bin
INSTALL_LIB  := /usr/local/lib/xdp-firewall
INSTALL_CONF := /etc/xdp-firewall

install: all
	install -d $(INSTALL_LIB) $(INSTALL_CONF)
	install -m 755 $(USER_BIN) $(INSTALL_BIN)/xdp-firewall
	install -m 644 $(BPF_OBJ) $(INSTALL_LIB)/xdp_firewall.o
	@if [ ! -f $(INSTALL_CONF)/rules.conf ]; then \
	    install -m 644 $(SCRIPTS_DIR)/rules.conf.example $(INSTALL_CONF)/rules.conf; \
	fi
	@echo "Installed. Run: xdp-firewall -i <iface>"

uninstall:
	rm -f $(INSTALL_BIN)/xdp-firewall
	rm -rf $(INSTALL_LIB)
	@echo "Uninstalled. Config preserved at $(INSTALL_CONF)"

# ─── Clean ───────────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(INC_DIR)/xdp_firewall.skel.h

# ─── Help ────────────────────────────────────────────────────────────────────

help:
	@echo "xdp-firewall build targets:"
	@echo "  all       Build BPF object + userspace binary (default)"
	@echo "  skeleton  Generate BPF skeleton header via bpftool"
	@echo "  verify    Verify BPF program loads cleanly"
	@echo "  install   Install to /usr/local"
	@echo "  uninstall Remove installed files"
	@echo "  fmt       Auto-format source with clang-format"
	@echo "  lint      Run clang-tidy on userspace code"
	@echo "  clean     Remove build artifacts"
