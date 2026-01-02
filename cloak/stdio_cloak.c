/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zprog_rt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct host_ctx {
  FILE* in;
  FILE* out;
  FILE* log;
};

struct heap_ctx {
  int32_t head;
};

static int32_t cloak_alloc(void* ctx, uint8_t* mem, size_t mem_cap, int32_t size) {
  (void)mem;
  struct heap_ctx* heap = (struct heap_ctx*)ctx;
  if (!heap || size <= 0) return -1;
  if ((int64_t)heap->head + size > (int64_t)mem_cap) return -1;
  int32_t ptr = heap->head;
  heap->head += size;
  return ptr;
}

static void cloak_free(void* ctx, uint8_t* mem, size_t mem_cap, int32_t ptr) {
  (void)ctx;
  (void)mem;
  (void)mem_cap;
  (void)ptr;
}

static int32_t cloak_in(void* ctx,
                        int32_t req_handle,
                        uint8_t* mem,
                        size_t mem_cap,
                        int32_t ptr,
                        int32_t cap) {
  (void)req_handle;
  if (!ctx || !mem || cap < 0) return -1;
  struct host_ctx* host = (struct host_ctx*)ctx;
  size_t want = (size_t)cap;
  if ((size_t)ptr + want > mem_cap) return -1;
  size_t got = fread(mem + ptr, 1, want, host->in);
  if (ferror(host->in)) return -1;
  return (int32_t)got;
}

static int32_t cloak_out(void* ctx,
                         int32_t res_handle,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t ptr,
                         int32_t len) {
  (void)res_handle;
  if (!ctx || !mem || len < 0) return -1;
  struct host_ctx* host = (struct host_ctx*)ctx;
  size_t want = (size_t)len;
  if ((size_t)ptr + want > mem_cap) return -1;
  size_t wrote = fwrite(mem + ptr, 1, want, host->out);
  if (wrote != want) return -1;
  fflush(host->out);
  return (int32_t)wrote;
}

static void cloak_log(void* ctx,
                      uint8_t* mem,
                      size_t mem_cap,
                      int32_t topic_ptr,
                      int32_t topic_len,
                      int32_t msg_ptr,
                      int32_t msg_len) {
  if (!ctx || !mem) return;
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (topic_ptr < 0 || msg_ptr < 0 || topic_len < 0 || msg_len < 0) return;
  if ((size_t)topic_ptr + (size_t)topic_len > mem_cap) return;
  if ((size_t)msg_ptr + (size_t)msg_len > mem_cap) return;
  fprintf(host->log, "[log] %.*s: %.*s\n",
          topic_len, (const char*)(mem + topic_ptr),
          msg_len, (const char*)(mem + msg_ptr));
}

extern int lembeh_handle(int32_t req_handle,
                         int32_t res_handle,
                         zprog_in_fn in_fn,
                         zprog_out_fn out_fn,
                         zprog_log_fn log_fn,
                         void* host_ctx,
                         const struct zprog_sys* sys);
int main(void) {
  struct host_ctx host = { stdin, stdout, stderr };
  struct heap_ctx heap = { (int32_t)zprog_heap_base_value() };
  struct zprog_sys sys = {
    .ctx = &heap,
    .alloc_fn = cloak_alloc,
    .free_fn = cloak_free
  };
  return lembeh_handle(0, 0, cloak_in, cloak_out, cloak_log, &host, &sys);
}
