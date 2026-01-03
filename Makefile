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
PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
INCLUDEDIR?= $(PREFIX)/include

OBJDIR      := $(BUILD)/obj
CLOAK_OBJDIR:= $(BUILD)/cloak

override CPPFLAGS += -Isrc -Isrc/jsonl -Iinclude

ZCC_OBJ := \
	$(OBJDIR)/main.o \
	$(OBJDIR)/emit_c.o \
	$(OBJDIR)/jsonl.o

.PHONY: all zcc clean dirs install cloak-stdio test

all: zcc

zcc: $(ZCC_OBJ) | dirs
	$(CC) $(CFLAGS) $(ZCC_OBJ) -o $(BIN)/zcc $(LDFLAGS)

$(OBJDIR)/%.o: src/%.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/jsonl.o: src/jsonl/jsonl.c | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

cloak-stdio: | dirs
	$(CC) $(CPPFLAGS) $(CFLAGS) -Iinclude -c cloak/stdio_cloak.c -o $(CLOAK_OBJDIR)/stdio_cloak.o

install: zcc
	@mkdir -p $(DESTDIR)$(BINDIR)
	@install -m 0755 $(BIN)/zcc $(DESTDIR)$(BINDIR)/zcc
	@mkdir -p $(DESTDIR)$(INCLUDEDIR)
	@install -m 0644 include/zprog_rt.h $(DESTDIR)$(INCLUDEDIR)/zprog_rt.h

clean:
	rm -rf $(BUILD)

# Ensure build directories exist before compiling

dirs:
	mkdir -p $(BIN) $(OBJDIR) $(CLOAK_OBJDIR)

test: zcc
	./bin/zcc --version | grep -q "zcc 1.0.0"
	echo "" | ./bin/zcc > /dev/null
	@echo "All tests passed"
