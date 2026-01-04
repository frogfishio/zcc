/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zprog_rt.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZCL1_MAGIC_0 'Z'
#define ZCL1_MAGIC_1 'C'
#define ZCL1_MAGIC_2 'L'
#define ZCL1_MAGIC_3 '1'

#define ZCL1_VERSION 1u
#define ZCL1_FLAGS_NONE 0u

#define ZCL1_REQ_HEADER_LEN 24u
#define ZCL1_RESP_HEADER_LEN 20u
#define ZCL1_RESP_OK_PREFIX_LEN 4u

#define ZCL1_OP_CAPS_LIST 1u
#define ZCL1_OP_CAPS_DESCRIBE 2u
#define ZCL1_OP_CAPS_OPEN 3u

typedef struct zcl1_req_header {
  uint8_t magic[4];
  uint16_t version;
  uint16_t op;
  uint32_t rid;
  uint32_t timeout_ms;
  uint32_t flags;
  uint32_t payload_len;
} zcl1_req_header;

typedef struct zcl1_resp_header {
  uint8_t magic[4];
  uint16_t version;
  uint16_t op;
  uint32_t rid;
  uint32_t flags;
  uint32_t payload_len;
} zcl1_resp_header;

static void zcl1_set_magic(uint8_t dst[4]) {
  dst[0] = (uint8_t)ZCL1_MAGIC_0;
  dst[1] = (uint8_t)ZCL1_MAGIC_1;
  dst[2] = (uint8_t)ZCL1_MAGIC_2;
  dst[3] = (uint8_t)ZCL1_MAGIC_3;
}

static int zcl1_magic_valid(const uint8_t magic[4]) {
  return magic[0] == (uint8_t)ZCL1_MAGIC_0 &&
         magic[1] == (uint8_t)ZCL1_MAGIC_1 &&
         magic[2] == (uint8_t)ZCL1_MAGIC_2 &&
         magic[3] == (uint8_t)ZCL1_MAGIC_3;
}

static void zcl1_init_resp_from_req(zcl1_resp_header* resp, const zcl1_req_header* req) {
  if (!resp) return;
  zcl1_set_magic(resp->magic);
  resp->version = ZCL1_VERSION;
  resp->op = req ? req->op : 0;
  resp->rid = req ? req->rid : 0;
  resp->flags = ZCL1_FLAGS_NONE;
  resp->payload_len = 0;
}

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
  if (v > INT32_MAX) return -1;
  return (int32_t)v;
}

static uint16_t load_le16(const uint8_t* p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t load_le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le16(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xffu);
  p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void store_le32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xffu);
  p[1] = (uint8_t)((v >> 8) & 0xffu);
  p[2] = (uint8_t)((v >> 16) & 0xffu);
  p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static size_t hopper_field_size(size_t len) {
  return len + 4u;
}

static void hopper_write_field(uint8_t** cursor, const uint8_t* bytes, size_t len) {
  store_le32(*cursor, (uint32_t)len);
  *cursor += 4;
  if (len && bytes) {
    memcpy(*cursor, bytes, len);
  } else if (len) {
    memset(*cursor, 0, len);
  }
  *cursor += len;
}

static int zcl1_parse_req_header(zcl1_req_header* out, const uint8_t* buf, size_t len) {
  if (!out || !buf || len < ZCL1_REQ_HEADER_LEN) return -1;
  memcpy(out->magic, buf, 4);
  out->version = load_le16(buf + 4);
  out->op = load_le16(buf + 6);
  out->rid = load_le32(buf + 8);
  out->timeout_ms = load_le32(buf + 12);
  out->flags = load_le32(buf + 16);
  out->payload_len = load_le32(buf + 20);
  return 0;
}

static int zcl1_write_resp_header(uint8_t* buf, size_t cap, const zcl1_resp_header* h) {
  if (!buf || !h || cap < ZCL1_RESP_HEADER_LEN) return -1;
  zcl1_set_magic(buf);
  store_le16(buf + 4, h->version);
  store_le16(buf + 6, h->op);
  store_le32(buf + 8, h->rid);
  store_le32(buf + 12, h->flags);
  store_le32(buf + 16, h->payload_len);
  return 0;
}

static int write_error_response(uint8_t* mem, size_t mem_cap,
                                int32_t resp_ptr, int32_t resp_cap,
                                const zcl1_req_header* req,
                                const char* trace, const char* msg) {
  size_t trace_len = trace ? strlen(trace) : 0;
  size_t msg_len = msg ? strlen(msg) : 0;
  size_t payload_len = ZCL1_RESP_OK_PREFIX_LEN +
                       hopper_field_size(trace_len) +
                       hopper_field_size(msg_len) +
                       hopper_field_size(0);
  size_t total = ZCL1_RESP_HEADER_LEN + payload_len;
  if (resp_ptr < 0 || resp_cap < 0) return -1;
  size_t resp_start = (size_t)resp_ptr;
  size_t resp_cap_sz = (size_t)resp_cap;
  if (total > resp_cap_sz) return -1;
  if (resp_start + total > mem_cap) return -1;

  zcl1_resp_header rh;
  zcl1_init_resp_from_req(&rh, req);
  rh.payload_len = (uint32_t)payload_len;
  uint8_t* out = mem + resp_start;
  if (zcl1_write_resp_header(out, resp_cap_sz, &rh) != 0) return -1;

  uint8_t* cursor = out + ZCL1_RESP_HEADER_LEN;
  cursor[0] = 0;
  cursor[1] = 0;
  cursor[2] = 0;
  cursor[3] = 0;
  cursor += ZCL1_RESP_OK_PREFIX_LEN;
  hopper_write_field(&cursor, (const uint8_t*)trace, trace_len);
  hopper_write_field(&cursor, (const uint8_t*)msg, msg_len);
  hopper_write_field(&cursor, NULL, 0);
  return clamp_i32_from_size(total);
}

static int write_caps_list_empty(uint8_t* mem, size_t mem_cap,
                                 int32_t resp_ptr, int32_t resp_cap,
                                 const zcl1_req_header* req) {
  size_t payload_len = ZCL1_RESP_OK_PREFIX_LEN + sizeof(uint32_t);
  size_t total = ZCL1_RESP_HEADER_LEN + payload_len;
  if (resp_ptr < 0 || resp_cap < 0) return -1;
  size_t resp_start = (size_t)resp_ptr;
  size_t resp_cap_sz = (size_t)resp_cap;
  if (total > resp_cap_sz) return -1;
  if (resp_start + total > mem_cap) return -1;

  zcl1_resp_header rh;
  zcl1_init_resp_from_req(&rh, req);
  rh.payload_len = (uint32_t)payload_len;
  uint8_t* out = mem + resp_start;
  if (zcl1_write_resp_header(out, resp_cap_sz, &rh) != 0) return -1;

  size_t off = ZCL1_RESP_HEADER_LEN;
  out[off + 0] = 1;
  out[off + 1] = 0;
  out[off + 2] = 0;
  out[off + 3] = 0;
  memset(out + off + 4, 0, sizeof(uint32_t));
  return clamp_i32_from_size(total);
}

static int32_t cloak_ctl(void* ctx,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t req_ptr,
                         int32_t req_len,
                         int32_t resp_ptr,
                         int32_t resp_cap) {
  (void)ctx;
  if (!mem || req_ptr < 0 || req_len < 0 || resp_ptr < 0 || resp_cap < 0) {
    return -1;
  }
  size_t req_start = (size_t)req_ptr;
  size_t req_len_sz = (size_t)req_len;
  if (req_start + req_len_sz > mem_cap) return -1;
  if (req_len_sz < ZCL1_REQ_HEADER_LEN) return -1;

  const uint8_t* req = mem + req_start;
  zcl1_req_header hdr;
  if (zcl1_parse_req_header(&hdr, req, req_len_sz) != 0) return -1;
  if (!zcl1_magic_valid(hdr.magic)) return -1;
  if (hdr.version != ZCL1_VERSION) {
    return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                &hdr, "t_ctl_bad_version", "unsupported version");
  }
  if (hdr.flags != ZCL1_FLAGS_NONE) {
    return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                &hdr, "t_ctl_bad_frame", "flags must be zero");
  }
  size_t payload_len = req_len_sz - ZCL1_REQ_HEADER_LEN;
  if (hdr.payload_len != payload_len) return -1;

  if (hdr.op == ZCL1_OP_CAPS_LIST) {
    if (hdr.payload_len != 0) {
      return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                  &hdr, "t_ctl_bad_params", "CAPS_LIST payload must be empty");
    }
    return write_caps_list_empty(mem, mem_cap, resp_ptr, resp_cap, &hdr);
  }

  return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                              &hdr, "t_ctl_unknown_op", "unsupported op");
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
