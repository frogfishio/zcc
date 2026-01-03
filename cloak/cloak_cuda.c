/* SPDX-FileCopyrightText: 2026 Frogfish
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "zprog_rt.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../normative/zing_zctl1_kernel_backplane_pack_v1/c/zctl1.h"

struct cuda_kernel_meta {
  uint32_t id;
  const char* name;
  uint64_t sig_hash;
  uint32_t flags;
};

static const struct cuda_kernel_meta CUDA_KERNELS[] = {
  { 1u, "noop",        0x0000000000000000ull, 0u },
  { 2u, "tensor_add",  0x00000000000000A1ull, 0u },
};

struct cuda_capability_meta {
  uint32_t cap_id;
  const char* name;
};

static const struct cuda_capability_meta CUDA_CAPS[] = {
  { 0x0001u, "cuda.kernel.list" },
  { 0x0002u, "cuda.kernel.run" }
};

struct cuda_backend {
  int initialized;
  int available;
  char last_error[256];
};

struct host_ctx {
  FILE* in;
  FILE* out;
  FILE* log;
  int stdout_closed;
  struct cuda_backend backend;
};

struct heap_ctx {
  int32_t head;
};

static void cuda_backend_init(struct cuda_backend* backend) {
  if (!backend) return;
  memset(backend, 0, sizeof(*backend));
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  /* TODO: wire CUDA driver initialization when building on a CUDA host. */
  backend->available = 1;
  snprintf(backend->last_error, sizeof(backend->last_error), "CUDA runtime hooks pending implementation");
#else
  snprintf(backend->last_error, sizeof(backend->last_error),
           "CUDA backend disabled; rebuild with ZCC_ENABLE_CUDA_RUNTIME on a CUDA host");
#endif
  backend->initialized = 1;
}

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

static int in_bounds(size_t mem_cap, int32_t ptr, int32_t len) {
  if (ptr < 0 || len < 0) return 0;
  size_t p = (size_t)ptr;
  size_t l = (size_t)len;
  return p + l <= mem_cap;
}

static int32_t clamp_i32(size_t v) {
  return v > INT32_MAX ? ZCTL_ERR : (int32_t)v;
}

static size_t calc_caps_payload(void) {
  size_t payload = sizeof(uint32_t);
  for (size_t i = 0; i < sizeof(CUDA_CAPS) / sizeof(CUDA_CAPS[0]); i++) {
    payload += sizeof(uint32_t) * 2; /* cap_id + name_len */
    payload += strlen(CUDA_CAPS[i].name);
  }
  return payload;
}

static uint8_t* write_u32(uint8_t* dst, uint32_t v) {
  memcpy(dst, &v, sizeof(uint32_t));
  return dst + sizeof(uint32_t);
}

static int32_t respond_caps_list(const zctl1_req_header* req,
                                 uint8_t* resp,
                                 size_t resp_cap) {
  size_t payload_len = calc_caps_payload();
  size_t total = ZCTL1_RESP_HEADER_LEN + payload_len;
  if (resp_cap < total) return ZCTL_ERR;

  zctl1_resp_header rh;
  zctl1_init_resp_from_req(&rh, req);
  rh.status = ZCTL1_OK;
  rh.payload_len = (uint32_t)payload_len;
  zctl1_encode_resp_header(resp, resp_cap, &rh);

  uint8_t* p = resp + ZCTL1_RESP_HEADER_LEN;
  p = write_u32(p, (uint32_t)(sizeof(CUDA_CAPS) / sizeof(CUDA_CAPS[0])));
  for (size_t i = 0; i < sizeof(CUDA_CAPS) / sizeof(CUDA_CAPS[0]); i++) {
    const struct cuda_capability_meta* cap = &CUDA_CAPS[i];
    uint32_t name_len = (uint32_t)strlen(cap->name);
    p = write_u32(p, cap->cap_id);
    p = write_u32(p, name_len);
    memcpy(p, cap->name, name_len);
    p += name_len;
  }
  return clamp_i32(total);
}

static const struct cuda_kernel_meta* find_kernel(uint32_t kernel_id) {
  for (size_t i = 0; i < sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]); i++) {
    if (CUDA_KERNELS[i].id == kernel_id) return &CUDA_KERNELS[i];
  }
  return NULL;
}

static size_t calc_kernel_list_payload(void) {
  size_t payload = sizeof(uint32_t);
  for (size_t i = 0; i < sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]); i++) {
    payload += sizeof(uint32_t) * 3; /* kernel_id, name_len, flags */
    payload += sizeof(uint64_t);     /* sig_hash */
    payload += strlen(CUDA_KERNELS[i].name);
  }
  return payload;
}

static int32_t respond_kernel_list(const zctl1_req_header* req,
                                   uint8_t* resp,
                                   size_t resp_cap) {
  size_t payload_len = calc_kernel_list_payload();
  size_t total = ZCTL1_RESP_HEADER_LEN + payload_len;
  if (resp_cap < total) return ZCTL_ERR;

  zctl1_resp_header rh;
  zctl1_init_resp_from_req(&rh, req);
  rh.status = ZCTL1_OK;
  rh.payload_len = (uint32_t)payload_len;
  zctl1_encode_resp_header(resp, resp_cap, &rh);

  uint8_t* p = resp + ZCTL1_RESP_HEADER_LEN;
  p = write_u32(p, (uint32_t)(sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0])));
  for (size_t i = 0; i < sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]); i++) {
    const struct cuda_kernel_meta* meta = &CUDA_KERNELS[i];
    uint32_t name_len = (uint32_t)strlen(meta->name);
    p = write_u32(p, meta->id);
    p = write_u32(p, name_len);
    memcpy(p, meta->name, name_len);
    p += name_len;
    memcpy(p, &meta->sig_hash, sizeof(uint64_t));
    p += sizeof(uint64_t);
    p = write_u32(p, meta->flags);
  }
  return clamp_i32(total);
}

static int32_t respond_kernel_run_stub(const zctl1_req_header* req,
                                       uint8_t* resp,
                                       size_t resp_cap,
                                       const char* message,
                                       uint32_t err_code) {
  size_t msg_len = message ? strlen(message) : 0;
  size_t payload_len = sizeof(zctl1_kernel_run_resp) + msg_len;
  size_t total = ZCTL1_RESP_HEADER_LEN + payload_len;
  if (resp_cap < total) return ZCTL_ERR;

  zctl1_resp_header rh;
  zctl1_init_resp_from_req(&rh, req);
  rh.status = ZCTL1_OK;
  rh.payload_len = (uint32_t)payload_len;
  if (zctl1_encode_resp_header(resp, resp_cap, &rh) != 0) return ZCTL_ERR;

  zctl1_kernel_run_resp body;
  body.ok = 0;
  body.err_code = err_code;
  body.err_msg_len = (uint32_t)msg_len;
  memcpy(resp + ZCTL1_RESP_HEADER_LEN, &body, sizeof(body));
  if (msg_len) memcpy(resp + ZCTL1_RESP_HEADER_LEN + sizeof(body), message, msg_len);
  return clamp_i32(total);
}

static int32_t handle_kernel_run(const zctl1_req_header* req,
                                 const uint8_t* payload,
                                 size_t payload_len,
                                 struct host_ctx* host,
                                 uint8_t* resp,
                                 size_t resp_cap) {
  if (payload_len < sizeof(zctl1_kernel_run_req)) return respond_kernel_run_stub(req, resp, resp_cap, "payload too small", ZCTL1_ERR_MALFORMED);
  const zctl1_kernel_run_req* run = (const zctl1_kernel_run_req*)payload;
  size_t needed = sizeof(*run) + ((size_t)run->arg_count * sizeof(zctl1_arg));
  if (payload_len < needed) {
    return respond_kernel_run_stub(req, resp, resp_cap, "args truncated", ZCTL1_ERR_MALFORMED);
  }

  const struct cuda_kernel_meta* kernel = find_kernel(run->kernel_id);
  if (!kernel) {
    return respond_kernel_run_stub(req, resp, resp_cap, "kernel id not found", ZCTL1_ERR_BAD_ARGS);
  }

  (void)host;
  const char* err = host && host->backend.available
                      ? "CUDA backend hooks not implemented yet"
                      : host && host->backend.initialized
                          ? host->backend.last_error
                          : "CUDA backend unavailable";
  return respond_kernel_run_stub(req, resp, resp_cap, err, ZCTL1_ERR_BACKEND);
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
  (void)ctl_handle;
  (void)timeout_ms;
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (!mem) return ZCTL_ERR;
  if (!in_bounds(mem_cap, req_ptr, req_len)) return ZCTL_ERR;
  if (!in_bounds(mem_cap, resp_ptr, resp_cap)) return ZCTL_ERR;
  if (req_len < (int32_t)ZCTL1_REQ_HEADER_LEN) return ZCTL_ERR;

  const uint8_t* req_buf = mem + (size_t)req_ptr;
  zctl1_req_header req;
  if (zctl1_decode_req_header(&req, req_buf, (size_t)req_len) != 0) return ZCTL_ERR;
  if ((size_t)req_len != ZCTL1_REQ_HEADER_LEN + req.payload_len) return ZCTL_ERR;

  uint8_t* resp = mem + (size_t)resp_ptr;
  const uint8_t* payload = req_buf + ZCTL1_REQ_HEADER_LEN;
  size_t payload_len = (size_t)req.payload_len;

  switch (req.op) {
    case ZCTL1_OP_CAPS_LIST:
      return respond_caps_list(&req, resp, (size_t)resp_cap);
    case ZCTL1_OP_KERNEL_LIST:
      return respond_kernel_list(&req, resp, (size_t)resp_cap);
    case ZCTL1_OP_KERNEL_RUN:
      return handle_kernel_run(&req, payload, payload_len, host, resp, (size_t)resp_cap);
    default:
      zctl1_write_err_resp(resp, (size_t)resp_cap, &req, ZCTL1_ERR_UNSUPPORTED);
      return (int32_t)ZCTL1_RESP_HEADER_LEN;
  }
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
  struct host_ctx host = {
    .in = stdin,
    .out = stdout,
    .log = stderr,
    .stdout_closed = 0,
  };
  cuda_backend_init(&host.backend);

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
