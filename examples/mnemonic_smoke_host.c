/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zprog_rt.h"
#include <stdint.h>
#include <string.h>

struct heap_ctx {
  int32_t head;
};

struct host_ctx {
  int ok;
  int saw_out;
};

static const char k_expected_out[] = "mnemonic smoke";

static int32_t host_alloc(void* ctx, uint8_t* mem, size_t mem_cap, int32_t size) {
  (void)mem;
  struct heap_ctx* heap = (struct heap_ctx*)ctx;
  if (!heap || size <= 0) return -1;
  if ((int64_t)heap->head + size > (int64_t)mem_cap) return -1;
  int32_t ptr = heap->head;
  heap->head += size;
  return ptr;
}

static void host_free(void* ctx, uint8_t* mem, size_t mem_cap, int32_t ptr) {
  (void)ctx;
  (void)mem;
  (void)mem_cap;
  (void)ptr;
}

static int32_t host_in(void* ctx,
                       int32_t req_handle,
                       uint8_t* mem,
                       size_t mem_cap,
                       int32_t ptr,
                       int32_t cap) {
  (void)ctx;
  (void)req_handle;
  (void)mem;
  (void)mem_cap;
  (void)ptr;
  (void)cap;
  return 0;
}

static int32_t host_out(void* ctx,
                        int32_t res_handle,
                        uint8_t* mem,
                        size_t mem_cap,
                        int32_t ptr,
                        int32_t len) {
  (void)res_handle;
  (void)mem;
  (void)mem_cap;
  (void)ptr;
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (!host || !mem || ptr < 0 || len < 0) return -1;
  size_t want = (size_t)len;
  size_t expected = sizeof(k_expected_out) - 1;
  if ((size_t)ptr + want > mem_cap) return -1;
  host->saw_out = 1;
  if (want != expected || memcmp(mem + ptr, k_expected_out, expected) != 0) {
    host->ok = 0;
    return -1;
  }
  return len;
}

static void host_end(void* ctx, int32_t res_handle) {
  (void)ctx;
  (void)res_handle;
}

static void host_log(void* ctx,
                     uint8_t* mem,
                     size_t mem_cap,
                     int32_t topic_ptr,
                     int32_t topic_len,
                     int32_t msg_ptr,
                     int32_t msg_len) {
  (void)ctx;
  (void)mem;
  (void)mem_cap;
  (void)topic_ptr;
  (void)topic_len;
  (void)msg_ptr;
  (void)msg_len;
}

static int32_t host_ctl(void* ctx,
                        int32_t ctl_handle,
                        uint8_t* mem,
                        size_t mem_cap,
                        int32_t req_ptr,
                        int32_t req_len,
                        int32_t resp_ptr,
                        int32_t resp_cap,
                        int32_t timeout_ms) {
  (void)ctx;
  (void)ctl_handle;
  (void)mem;
  (void)mem_cap;
  (void)req_ptr;
  (void)req_len;
  (void)resp_ptr;
  (void)resp_cap;
  (void)timeout_ms;
  return -1;
}

int main(void) {
  struct heap_ctx heap = { (int32_t)zprog_heap_base_value() };
  struct host_ctx host = { 1, 0 };
  struct zprog_sys sys = {
    .ctx = &heap,
    .alloc_fn = host_alloc,
    .free_fn = host_free
  };
  int rc = lembeh_handle(ZCAP_IN,
                         ZCAP_OUT,
                         host_in,
                         host_out,
                         host_end,
                         host_log,
                         host_ctl,
                         &host,
                         &sys);
  if (rc != 0) return rc;
  if (!host.ok || !host.saw_out) return 1;
  return 0;
}
