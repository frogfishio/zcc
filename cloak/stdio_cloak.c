/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zprog_rt.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../zing_abi_pack_v1/zcl1.h"

struct host_ctx {
  FILE* in;
  FILE* out;
  FILE* log;
  int stdout_closed;
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
  if (host->stdout_closed) return -1;
  size_t want = (size_t)len;
  if ((size_t)ptr + want > mem_cap) return -1;
  size_t wrote = fwrite(mem + ptr, 1, want, host->out);
  if (wrote != want) return -1;
  fflush(host->out);
  return (int32_t)wrote;
}

static void cloak_end(void* ctx, int32_t res_handle) {
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (!host) return;
  if (res_handle == ZCAP_OUT) {
    if (!host->stdout_closed) fflush(host->out);
    host->stdout_closed = 1;
  }
}

static int32_t clamp_i32_from_size(size_t v) {
  if (v > INT32_MAX) return ZCTL_ERR;
  return (int32_t)v;
}

static int32_t cloak_ctl(void* ctx,
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
  (void)timeout_ms;
  if (!mem || req_ptr < 0 || req_len < 0 || resp_ptr < 0 || resp_cap < 0) {
    return ZCTL_ERR;
  }
  size_t req_start = (size_t)req_ptr;
  size_t req_len_sz = (size_t)req_len;
  if (req_start + req_len_sz > mem_cap) return ZCTL_ERR;
  if (req_len_sz < ZCL1_REQ_HEADER_LEN) return ZCTL_ERR;

  const uint8_t* req = mem + req_start;
  zcl1_req_header hdr;
  if (zcl1_decode_req_header(&hdr, req, req_len_sz) != 0) return ZCTL_ERR;
  size_t payload_len = req_len_sz - ZCL1_REQ_HEADER_LEN;
  if (hdr.payload_len != payload_len) return ZCTL_ERR;

  if (hdr.op != ZCL1_OP_CAPS_LIST) {
    return ZCTL_ERR;
  }

  size_t resp_payload = ZCL1_RESP_OK_PREFIX_LEN + sizeof(uint32_t);
  size_t resp_bytes = ZCL1_RESP_HEADER_LEN + resp_payload;
  size_t resp_cap_sz = (size_t)resp_cap;
  size_t resp_start = (size_t)resp_ptr;
  if (resp_start + resp_bytes > mem_cap || resp_cap_sz < resp_bytes) {
    return ZCTL_ERR;
  }

  zcl1_resp_header resp_hdr;
  zcl1_init_resp_from_req(&resp_hdr, &hdr);
  resp_hdr.payload_len = (uint32_t)resp_payload;

  uint8_t* resp = mem + resp_start;
  if (zcl1_encode_resp_header(resp, resp_cap_sz, &resp_hdr) != 0) return ZCTL_ERR;

  size_t off = ZCL1_RESP_HEADER_LEN;
  resp[off + 0] = 1;
  resp[off + 1] = 0;
  resp[off + 2] = 0;
  resp[off + 3] = 0;
  memset(resp + off + 4, 0, sizeof(uint32_t));

  return clamp_i32_from_size(resp_bytes);
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
                         zprog_end_fn end_fn,
                         zprog_log_fn log_fn,
                         zprog_ctl_fn ctl_fn,
                         void* host_ctx,
                         const struct zprog_sys* sys);
int main(void) {
  struct host_ctx host = { stdin, stdout, stderr, 0 };
  struct heap_ctx heap = { (int32_t)zprog_heap_base_value() };
  struct zprog_sys sys = {
    .ctx = &heap,
    .alloc_fn = cloak_alloc,
    .free_fn = cloak_free
  };
  return lembeh_handle(ZCAP_IN,
                       ZCAP_OUT,
                       cloak_in,
                       cloak_out,
                       cloak_end,
                       cloak_log,
                       cloak_ctl,
                       &host,
                       &sys);
}
