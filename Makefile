# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

SHELL := /bin/bash
.ONESHELL:
.SUFFIXES:

CC      ?= clang
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS?=
LDFLAGS ?=

ZASM_ROOT ?= ..
BUILD     ?= build
BIN       ?= bin
PLATFORM  ?= $(shell ./scripts/platform.sh)
BIN_PLATFORM ?= $(BIN)/$(PLATFORM)
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
INCLUDEDIR?= $(PREFIX)/include

OBJDIR      := $(BUILD)/obj
CLOAK_OBJDIR:= $(BUILD)/cloak

override CPPFLAGS += -Isrc -Isrc/jsonl -Inormative -Iinclude -I.

ZCC_OBJ := \
	$(OBJDIR)/main.o \
	$(OBJDIR)/emit_c.o \
	$(OBJDIR)/jsonl.o

.PHONY: all zcc clean dirs install cloak-stdio cloak-cuda test test-cuda-cloak examples

all: zcc

examples: $(BUILD)/ctl_probe_cuda

zcc: $(ZCC_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZCC_OBJ) -o $(BIN_PLATFORM)/zcc $(LDFLAGS)

$(OBJDIR)/%.o: src/%.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/jsonl.o: src/jsonl/jsonl.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

cloak-stdio: | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Iinclude -c cloak/stdio_cloak.c -o $(CLOAK_OBJDIR)/stdio_cloak.o

cloak-cuda: | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -DZCC_ENABLE_CUDA_RUNTIME -Iinclude -c cloak/cloak_cuda.c -o $(CLOAK_OBJDIR)/cloak_cuda.o

install: zcc
	@mkdir -p $(DESTDIR)$(BINDIR)
	@install -m 0755 $(BIN_PLATFORM)/zcc $(DESTDIR)$(BINDIR)/zcc
	@mkdir -p $(DESTDIR)$(INCLUDEDIR)
	@install -m 0644 include/zprog_rt.h $(DESTDIR)$(INCLUDEDIR)/zprog_rt.h

clean:
	rm -rf $(BUILD)

# Ensure build directories exist before compiling

dirs:
	mkdir -p $(BIN_PLATFORM) $(OBJDIR) $(CLOAK_OBJDIR) out

test: zcc
	set -e
	./bin/zcc --version | grep -q "zcc 1.0.0"
	echo "" | ./bin/zcc > /dev/null
	./bin/zcc --output $(BUILD)/mnemonic_smoke.c < examples/mnemonic_smoke.jsonl
	$(CC) -Iinclude -Inormative -c $(BUILD)/mnemonic_smoke.c -o $(BUILD)/mnemonic_smoke.o
	$(CC) -Iinclude -Inormative -c examples/mnemonic_smoke_host.c -o $(BUILD)/mnemonic_smoke_host.o
	$(CC) $(BUILD)/mnemonic_smoke.o $(BUILD)/mnemonic_smoke_host.o -o $(BUILD)/mnemonic_smoke
	./$(BUILD)/mnemonic_smoke > /dev/null
	./scripts/error_tests.sh
	@echo "All tests passed"

test-cuda-cloak: $(BUILD)/ctl_probe_cuda
	@echo "Running CUDA cloak test..."
	./$(BUILD)/ctl_probe_cuda | grep -q "Caps list ok"
	@echo "CUDA cloak test passed"

$(BUILD)/ctl_probe.c: examples/ctl_probe.jsonl zcc | dirs
	./bin/zcc --output $@ < $<

$(BUILD)/ctl_probe_cuda: $(BUILD)/ctl_probe.c cloak/cloak_cuda.c normative/zing_zctl1_kernel_backplane_pack_v1/c/zctl1.c | dirs cloak-cuda
	$(CC) -Iinclude -Inormative $(BUILD)/ctl_probe.c cloak/cloak_cuda.c normative/zing_zctl1_kernel_backplane_pack_v1/c/zctl1.c -o $@ -L/usr/lib/x86_64-linux-gnu -lcuda -ldl -lpthread

perf-bench: zcc | dirs cloak-cuda
	$(CC) -DZCC_ENABLE_CUDA_RUNTIME -Iinclude -Inormative examples/perf_bench.c examples/bench_stub.c cloak/cloak_bench.c normative/zing_zctl1_kernel_backplane_pack_v1/c/zctl1.c -o $(BUILD)/perf_bench -L/usr/lib/x86_64-linux-gnu -lcuda -ldl -lpthread
	@echo ""
	@echo "Running benchmark..."
	@$(BUILD)/perf_bench
