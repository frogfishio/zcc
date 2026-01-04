/* SPDX-FileCopyrightText: 2026 Frogfish
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 199309L

#include "zprog_rt.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(ZCC_ENABLE_CUDA_RUNTIME)
#include <cuda.h>
#endif

#if defined(CLOAK_BENCH_EXPORTS)
#define CLOAK_BENCH_API
#else
#define CLOAK_BENCH_API static
#endif

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

#define ACCEL_HANDLE_BASE 3
#define ACCEL_MAX_HANDLES 64

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

enum accel_handle_kind {
  ACCEL_HANDLE_NONE = 0,
  ACCEL_HANDLE_STREAM = 1,
  ACCEL_HANDLE_BUFFER = 2
};

struct accel_handle {
  int in_use;
  enum accel_handle_kind kind;
  size_t size;
  size_t offset;
  uint8_t* host_buf;
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  CUdeviceptr dev_ptr;
#endif
};

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

#if defined(ZCC_ENABLE_CUDA_RUNTIME)
static void format_cuda_error(char* dst, size_t dst_len, CUresult res, const char* step) {
  const char* name = NULL;
  const char* desc = NULL;
  if (cuGetErrorName(res, &name) != CUDA_SUCCESS || !name) name = "CUDA_ERROR";
  if (cuGetErrorString(res, &desc) != CUDA_SUCCESS || !desc) desc = "(no detail)";
  snprintf(dst, dst_len, "%s failed: %s (%s)", step ? step : "CUDA call", name, desc);
}
#endif

struct cuda_kernel_meta {
  uint32_t id;
  const char* name;
  uint64_t sig_hash;
  uint32_t flags;
  const char* ptx_code;
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  CUmodule module;
  CUfunction function;
#endif
};

/* Simple noop kernel PTX */
static const char KERNEL_NOOP_PTX[] = 
".version 7.0\n"
".target sm_50\n"
".address_size 64\n"
".visible .entry noop() {\n"
"  ret;\n"
"}\n";

/* Simple vector add kernel PTX */
static const char KERNEL_ADD_PTX[] = 
".version 7.0\n"
".target sm_50\n"
".address_size 64\n"
".visible .entry tensor_add(\n"
"  .param .u64 tensor_add_param_0,\n"
"  .param .u64 tensor_add_param_1,\n"
"  .param .u64 tensor_add_param_2,\n"
"  .param .u32 tensor_add_param_3\n"
") {\n"
"  .reg .pred %p<2>;\n"
"  .reg .b32 %r<6>;\n"
"  .reg .f32 %f<4>;\n"
"  .reg .b64 %rd<11>;\n"
"  ld.param.u64 %rd1, [tensor_add_param_0];\n"
"  ld.param.u64 %rd2, [tensor_add_param_1];\n"
"  ld.param.u64 %rd3, [tensor_add_param_2];\n"
"  ld.param.u32 %r2, [tensor_add_param_3];\n"
"  mov.u32 %r3, %ntid.x;\n"
"  mov.u32 %r4, %ctaid.x;\n"
"  mov.u32 %r5, %tid.x;\n"
"  mad.lo.s32 %r1, %r3, %r4, %r5;\n"
"  setp.ge.s32 %p1, %r1, %r2;\n"
"  @%p1 bra $L__BB0_2;\n"
"  cvta.to.global.u64 %rd4, %rd1;\n"
"  mul.wide.s32 %rd5, %r1, 4;\n"
"  add.s64 %rd6, %rd4, %rd5;\n"
"  cvta.to.global.u64 %rd7, %rd2;\n"
"  add.s64 %rd8, %rd7, %rd5;\n"
"  ld.global.f32 %f1, [%rd8];\n"
"  ld.global.f32 %f2, [%rd6];\n"
"  add.f32 %f3, %f2, %f1;\n"
"  cvta.to.global.u64 %rd9, %rd3;\n"
"  add.s64 %rd10, %rd9, %rd5;\n"
"  st.global.f32 [%rd10], %f3;\n"
"$L__BB0_2:\n"
"  ret;\n"
"}\n";

static struct cuda_kernel_meta CUDA_KERNELS[] = {
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  { 1u, "noop",        0x0000000000000000ull, 0u, KERNEL_NOOP_PTX, NULL, NULL },
  { 2u, "tensor_add",  0x00000000000000A1ull, 0u, KERNEL_ADD_PTX, NULL, NULL },
#else
  { 1u, "noop",        0x0000000000000000ull, 0u, KERNEL_NOOP_PTX },
  { 2u, "tensor_add",  0x00000000000000A1ull, 0u, KERNEL_ADD_PTX },
#endif
};

struct cuda_backend {
  int initialized;
  int available;
  char last_error[256];
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  CUcontext context;
  CUdevice device;
  int device_count;
  int has_context;
  int kernels_loaded;
#endif
};

struct host_ctx {
  FILE* in;
  FILE* out;
  FILE* log;
  int stdout_closed;
  struct cuda_backend backend;
  struct accel_handle handles[ACCEL_MAX_HANDLES];
};

struct heap_ctx {
  int32_t head;
};

static uint16_t load_le16(const uint8_t* p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t load_le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t load_le64(const uint8_t* p) {
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
         ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
         ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
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

static void store_le64(uint8_t* p, uint64_t v) {
  p[0] = (uint8_t)(v & 0xffu);
  p[1] = (uint8_t)((v >> 8) & 0xffu);
  p[2] = (uint8_t)((v >> 16) & 0xffu);
  p[3] = (uint8_t)((v >> 24) & 0xffu);
  p[4] = (uint8_t)((v >> 32) & 0xffu);
  p[5] = (uint8_t)((v >> 40) & 0xffu);
  p[6] = (uint8_t)((v >> 48) & 0xffu);
  p[7] = (uint8_t)((v >> 56) & 0xffu);
}

static int bench_debug_enabled(void) {
  static int enabled = -1;
  if (enabled < 0) {
    const char* env = getenv("ZCC_BENCH_DEBUG");
    enabled = (env && env[0] && env[0] != '0') ? 1 : 0;
  }
  return enabled;
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

static int hopper_read_field(const uint8_t* buf, size_t len, size_t* off,
                             const uint8_t** out_bytes, size_t* out_len) {
  if (!buf || !off || *off > len || len - *off < 4) return -1;
  uint32_t n = load_le32(buf + *off);
  *off += 4;
  if (n > len - *off) return -1;
  if (out_bytes) *out_bytes = buf + *off;
  if (out_len) *out_len = (size_t)n;
  *off += n;
  return 0;
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

static struct accel_handle* accel_handle_get(struct host_ctx* host, int32_t handle) {
  if (!host) return NULL;
  if (handle < ACCEL_HANDLE_BASE) return NULL;
  int idx = handle - ACCEL_HANDLE_BASE;
  if (idx < 0 || idx >= ACCEL_MAX_HANDLES) return NULL;
  if (!host->handles[idx].in_use) return NULL;
  return &host->handles[idx];
}

static int accel_handle_alloc(struct host_ctx* host, enum accel_handle_kind kind,
                              struct accel_handle** out_handle) {
  if (!host || !out_handle) return -1;
  for (int i = 0; i < ACCEL_MAX_HANDLES; i++) {
    if (!host->handles[i].in_use) {
      struct accel_handle* h = &host->handles[i];
      memset(h, 0, sizeof(*h));
      h->in_use = 1;
      h->kind = kind;
      *out_handle = h;
      return ACCEL_HANDLE_BASE + i;
    }
  }
  return -1;
}

static void accel_handle_release(struct host_ctx* host, int32_t handle) {
  struct accel_handle* h = accel_handle_get(host, handle);
  if (!h) return;
  if (bench_debug_enabled()) {
    fprintf(stderr,
            "[cloak] release handle=%d kind=%d host_buf=%p size=%zu offset=%zu\n",
            handle, h->kind, (void*)h->host_buf, h->size, h->offset);
  }
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  if (h->kind == ACCEL_HANDLE_BUFFER && h->dev_ptr) {
    cuMemFree(h->dev_ptr);
  }
#endif
#if defined(CLOAK_BENCH_EXPORTS)
  if (h->kind != ACCEL_HANDLE_STREAM) {
    free(h->host_buf);
  }
#else
  free(h->host_buf);
#endif
  memset(h, 0, sizeof(*h));
}

CLOAK_BENCH_API void cuda_backend_init(struct cuda_backend* backend) {
  if (!backend) return;
  memset(backend, 0, sizeof(*backend));
  fprintf(stderr, "[cloak] Initializing CUDA backend...\n");
  fflush(stderr);
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  CUresult res = cuInit(0);
  fprintf(stderr, "[cloak] cuInit returned %d\n", res);
  fflush(stderr);
  if (res != CUDA_SUCCESS) {
    snprintf(backend->last_error, sizeof(backend->last_error), "cuInit failed with code %d", res);
    fprintf(stderr, "[cloak] %s\n", backend->last_error);
    backend->initialized = 1;
    return;
  }

  int device_count = 0;
  res = cuDeviceGetCount(&device_count);
  fprintf(stderr, "[cloak] Device count: %d (res=%d)\n", device_count, res);
  if (res != CUDA_SUCCESS || device_count <= 0) {
    if (res != CUDA_SUCCESS) {
      snprintf(backend->last_error, sizeof(backend->last_error), "cuDeviceGetCount failed with code %d", res);
    } else {
      snprintf(backend->last_error, sizeof(backend->last_error), "No CUDA devices detected");
    }
    backend->initialized = 1;
    return;
  }

  backend->device_count = device_count;
  res = cuDeviceGet(&backend->device, 0);
  if (res != CUDA_SUCCESS) {
    snprintf(backend->last_error, sizeof(backend->last_error), "cuDeviceGet failed with code %d", res);
    backend->initialized = 1;
    return;
  }

  res = cuCtxCreate(&backend->context, 0, backend->device);
  fprintf(stderr, "[cloak] cuCtxCreate returned %d\n", res);
  if (res != CUDA_SUCCESS) {
    snprintf(backend->last_error, sizeof(backend->last_error), "cuCtxCreate failed with code %d", res);
    backend->initialized = 1;
    return;
  }

  backend->has_context = 1;
  
  fprintf(stderr, "[cloak] Loading %zu CUDA kernels...\n", sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]));
  
  /* Load kernel modules */
  for (size_t i = 0; i < sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]); i++) {
    struct cuda_kernel_meta* k = &CUDA_KERNELS[i];
    if (!k->ptx_code) continue;
    
    fprintf(stderr, "[cloak] Loading kernel %u (%s)...\n", k->id, k->name);
    
    res = cuModuleLoadDataEx(&k->module, k->ptx_code, 0, NULL, NULL);
    if (res != CUDA_SUCCESS) {
      format_cuda_error(backend->last_error, sizeof(backend->last_error), res, "cuModuleLoadDataEx");
      fprintf(stderr, "[cloak] Module load failed: %s\n", backend->last_error);
      backend->initialized = 1;
      return;
    }
    
    res = cuModuleGetFunction(&k->function, k->module, k->name);
    if (res != CUDA_SUCCESS) {
      format_cuda_error(backend->last_error, sizeof(backend->last_error), res, "cuModuleGetFunction");
      fprintf(stderr, "[cloak] Function lookup failed: %s\n", backend->last_error);
      cuModuleUnload(k->module);
      backend->initialized = 1;
      return;
    }
    
    fprintf(stderr, "[cloak] Kernel %s loaded successfully\n", k->name);
  }
  
  backend->kernels_loaded = 1;
  backend->available = 1;
  backend->last_error[0] = '\0';
#else
  snprintf(backend->last_error, sizeof(backend->last_error),
           "CUDA backend disabled; rebuild with ZCC_ENABLE_CUDA_RUNTIME on a CUDA host");
#endif
  backend->initialized = 1;
}

static void cuda_backend_shutdown(struct cuda_backend* backend) {
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  if (!backend) return;
  if (backend->kernels_loaded) {
    for (size_t i = 0; i < sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]); i++) {
      if (CUDA_KERNELS[i].module) {
        cuModuleUnload(CUDA_KERNELS[i].module);
        CUDA_KERNELS[i].module = NULL;
        CUDA_KERNELS[i].function = NULL;
      }
    }
    backend->kernels_loaded = 0;
  }
  if (backend->has_context) {
    cuCtxDestroy(backend->context);
    backend->has_context = 0;
  }
#else
  (void)backend;
#endif
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

static void log_host_msg(struct host_ctx* host, const char* msg) {
  if (!host || !host->log || !msg) return;
  fprintf(host->log, "[cloak] %s\n", msg);
}

CLOAK_BENCH_API int32_t cloak_in(void* ctx,
                        int32_t req_handle,
                        uint8_t* mem,
                        size_t mem_cap,
                        int32_t ptr,
                        int32_t cap) {
  if (!ctx || !mem || cap < 0) return -1;
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (req_handle >= ACCEL_HANDLE_BASE) {
    struct accel_handle* h = accel_handle_get(host, req_handle);
    if (!h) return -1;
    if (h->kind == ACCEL_HANDLE_STREAM) {
      size_t remaining = h->size > h->offset ? h->size - h->offset : 0;
      if (remaining == 0) return 0;
      size_t want = (size_t)cap;
      if ((size_t)ptr + want > mem_cap) return -1;
      size_t n = remaining < want ? remaining : want;
      memcpy(mem + ptr, h->host_buf + h->offset, n);
      h->offset += n;
      return (int32_t)n;
    }
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
    if (h->kind == ACCEL_HANDLE_BUFFER) {
      size_t remaining = h->size > h->offset ? h->size - h->offset : 0;
      if (remaining == 0) return 0;
      size_t want = (size_t)cap;
      if ((size_t)ptr + want > mem_cap) return -1;
      size_t n = remaining < want ? remaining : want;
      CUresult res = cuMemcpyDtoH(mem + ptr, h->dev_ptr + h->offset, n);
      if (res != CUDA_SUCCESS) return -1;
      h->offset += n;
      return (int32_t)n;
    }
#endif
    return -1;
  }
  size_t want = (size_t)cap;
  if ((size_t)ptr + want > mem_cap) return -1;
  size_t got = fread(mem + ptr, 1, want, host->in);
  if (ferror(host->in)) return -1;
  return (int32_t)got;
}

CLOAK_BENCH_API int32_t cloak_out(void* ctx,
                         int32_t res_handle,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t ptr,
                         int32_t len) {
  if (!ctx || !mem || len < 0) return -1;
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (res_handle >= ACCEL_HANDLE_BASE) {
    struct accel_handle* h = accel_handle_get(host, res_handle);
    if (!h) return -1;
    if (h->kind == ACCEL_HANDLE_STREAM) return -1;
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
    if (h->kind == ACCEL_HANDLE_BUFFER) {
      size_t want = (size_t)len;
      if ((size_t)ptr + want > mem_cap) return -1;
      if (h->offset + want > h->size) return -1;
      CUresult res = cuMemcpyHtoD(h->dev_ptr + h->offset, mem + ptr, want);
      if (res != CUDA_SUCCESS) return -1;
      h->offset += want;
      return (int32_t)want;
    }
#endif
    return -1;
  }
  if (host->stdout_closed) return -1;
  size_t want = (size_t)len;
  if ((size_t)ptr + want > mem_cap) return -1;
  size_t wrote = fwrite(mem + ptr, 1, want, host->out);
  if (wrote != want) {
    log_host_msg(host, "stdout write failed");
    return -1;
  }
  fflush(host->out);
  return (int32_t)wrote;
}

CLOAK_BENCH_API void cloak_end(void* ctx, int32_t res_handle) {
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (!host) return;
  if (res_handle >= ACCEL_HANDLE_BASE) {
    accel_handle_release(host, res_handle);
    return;
  }
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

static int32_t clamp_i32_from_size(size_t v) {
  if (v > INT32_MAX) return -1;
  return (int32_t)v;
}

static int hstr_eq(const uint8_t* s, size_t len, const char* lit) {
  size_t lit_len = strlen(lit);
  return len == lit_len && memcmp(s, lit, lit_len) == 0;
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

static int write_caps_list(uint8_t* mem, size_t mem_cap,
                           int32_t resp_ptr, int32_t resp_cap,
                           const zcl1_req_header* req,
                           const struct host_ctx* host) {
  const char* kind = "accel";
  const char* name = "default";
  size_t n = (host && host->backend.available) ? 1u : 0u;
  size_t payload_len = ZCL1_RESP_OK_PREFIX_LEN + sizeof(uint32_t);
  if (n) {
    payload_len += hopper_field_size(strlen(kind));
    payload_len += hopper_field_size(strlen(name));
    payload_len += sizeof(uint32_t);
    payload_len += hopper_field_size(0);
  }
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
  cursor[0] = 1;
  cursor[1] = 0;
  cursor[2] = 0;
  cursor[3] = 0;
  cursor += ZCL1_RESP_OK_PREFIX_LEN;
  store_le32(cursor, (uint32_t)n);
  cursor += sizeof(uint32_t);
  if (n) {
    hopper_write_field(&cursor, (const uint8_t*)kind, strlen(kind));
    hopper_write_field(&cursor, (const uint8_t*)name, strlen(name));
    store_le32(cursor, 0);
    cursor += sizeof(uint32_t);
    hopper_write_field(&cursor, NULL, 0);
  }
  return clamp_i32_from_size(total);
}

static int write_caps_describe(uint8_t* mem, size_t mem_cap,
                               int32_t resp_ptr, int32_t resp_cap,
                               const zcl1_req_header* req,
                               const uint8_t* payload, size_t payload_len) {
  size_t off = 0;
  const uint8_t* kind = NULL;
  size_t kind_len = 0;
  const uint8_t* name = NULL;
  size_t name_len = 0;
  if (hopper_read_field(payload, payload_len, &off, &kind, &kind_len) != 0 ||
      hopper_read_field(payload, payload_len, &off, &name, &name_len) != 0 ||
      off != payload_len) {
    return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                req, "t_ctl_bad_params", "CAPS_DESCRIBE params invalid");
  }
  if (!hstr_eq(kind, kind_len, "accel") || !hstr_eq(name, name_len, "default")) {
    return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                req, "t_cap_missing", "capability not found");
  }

  static const char k_meta[] =
    "{\"id\":\"cap.accel.v1\",\"backends\":[\"cuda\"],"
    "\"module_registry\":[\"preload\"],\"max_arg_count\":64,"
    "\"max_inline_arg_bytes\":256}";
  size_t meta_len = strlen(k_meta);
  size_t payload_total = ZCL1_RESP_OK_PREFIX_LEN + sizeof(uint32_t) + hopper_field_size(meta_len);
  size_t total = ZCL1_RESP_HEADER_LEN + payload_total;
  if (resp_ptr < 0 || resp_cap < 0) return -1;
  size_t resp_start = (size_t)resp_ptr;
  size_t resp_cap_sz = (size_t)resp_cap;
  if (total > resp_cap_sz) return -1;
  if (resp_start + total > mem_cap) return -1;

  zcl1_resp_header rh;
  zcl1_init_resp_from_req(&rh, req);
  rh.payload_len = (uint32_t)payload_total;
  uint8_t* out = mem + resp_start;
  if (zcl1_write_resp_header(out, resp_cap_sz, &rh) != 0) return -1;

  uint8_t* cursor = out + ZCL1_RESP_HEADER_LEN;
  cursor[0] = 1;
  cursor[1] = 0;
  cursor[2] = 0;
  cursor[3] = 0;
  cursor += ZCL1_RESP_OK_PREFIX_LEN;
  store_le32(cursor, 0);
  cursor += sizeof(uint32_t);
  hopper_write_field(&cursor, (const uint8_t*)k_meta, meta_len);
  return clamp_i32_from_size(total);
}

static int build_query_record(struct host_ctx* host, uint8_t** out_buf, size_t* out_len) {
  if (!out_buf || !out_len) return -1;
  *out_buf = NULL;
  *out_len = 0;
  if (!host || !host->backend.available) return -1;

  const char* dev_id = "0";
  char dev_name[128] = "cuda0";
  uint64_t mem_bytes = 0;
  uint32_t compute_units = 0;
  uint32_t flags = 0;

#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  if (host->backend.has_context) {
    cuDeviceGetName(dev_name, (int)sizeof(dev_name), host->backend.device);
    size_t total_mem = 0;
    if (cuDeviceTotalMem(&total_mem, host->backend.device) == CUDA_SUCCESS) {
      mem_bytes = (uint64_t)total_mem;
    }
    int sm_count = 0;
    if (cuDeviceGetAttribute(&sm_count, CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
                             host->backend.device) == CUDA_SUCCESS) {
      compute_units = (uint32_t)sm_count;
    }
  }
#endif

  size_t payload_len = sizeof(uint32_t);
  payload_len += hopper_field_size(strlen(dev_id));
  payload_len += hopper_field_size(strlen(dev_name));
  payload_len += sizeof(uint64_t);
  payload_len += sizeof(uint32_t) * 2;

  uint8_t* buf = (uint8_t*)malloc(payload_len);
  if (!buf) return -1;
  uint8_t* cursor = buf;
  store_le32(cursor, 1);
  cursor += sizeof(uint32_t);
  hopper_write_field(&cursor, (const uint8_t*)dev_id, strlen(dev_id));
  hopper_write_field(&cursor, (const uint8_t*)dev_name, strlen(dev_name));
  store_le64(cursor, mem_bytes);
  cursor += sizeof(uint64_t);
  store_le32(cursor, compute_units);
  cursor += sizeof(uint32_t);
  store_le32(cursor, flags);
  cursor += sizeof(uint32_t);

  *out_buf = buf;
  *out_len = payload_len;
  return 0;
}

static int build_status_record(int ok, const char* trace, const char* msg,
                               uint8_t** out_buf, size_t* out_len) {
  if (!out_buf || !out_len) return -1;
  *out_buf = NULL;
  *out_len = 0;
  size_t trace_len = trace ? strlen(trace) : 0;
  size_t msg_len = msg ? strlen(msg) : 0;
  size_t payload_len = 1;
  if (!ok) {
    payload_len += hopper_field_size(trace_len);
    payload_len += hopper_field_size(msg_len);
    payload_len += hopper_field_size(0);
  }
  uint8_t* buf = (uint8_t*)malloc(payload_len);
  if (!buf) return -1;
  uint8_t* cursor = buf;
  cursor[0] = ok ? 0 : 1;
  cursor += 1;
  if (!ok) {
    hopper_write_field(&cursor, (const uint8_t*)trace, trace_len);
    hopper_write_field(&cursor, (const uint8_t*)msg, msg_len);
    hopper_write_field(&cursor, NULL, 0);
  }
  *out_buf = buf;
  *out_len = payload_len;
  return 0;
}

static int build_sync_record(uint8_t** out_buf, size_t* out_len, int ok) {
  if (!out_buf || !out_len) return -1;
  *out_buf = NULL;
  *out_len = 0;
  uint8_t* buf = (uint8_t*)malloc(1);
  if (!buf) return -1;
  buf[0] = ok ? 1 : 0;
  *out_buf = buf;
  *out_len = 1;
  return 0;
}

static const struct cuda_kernel_meta* find_kernel_by_name(const uint8_t* name, size_t len) {
  for (size_t i = 0; i < sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]); i++) {
    const struct cuda_kernel_meta* k = &CUDA_KERNELS[i];
    size_t klen = strlen(k->name);
    if (klen == len && memcmp(k->name, name, klen) == 0) return k;
  }
  return NULL;
}

static int submit_kernel(struct host_ctx* host,
                         const struct cuda_kernel_meta* kernel,
                         uint32_t grid_x, uint32_t grid_y, uint32_t grid_z,
                         uint32_t block_x, uint32_t block_y, uint32_t block_z,
                         uint32_t shared_mem_bytes,
                         const uint8_t* args_buf, size_t args_len,
                         uint32_t arg_count,
                         char* err_buf, size_t err_buf_len) {
  if (!host || !kernel || !host->backend.available) {
    snprintf(err_buf, err_buf_len, "CUDA backend unavailable");
    return -1;
  }
#if !defined(ZCC_ENABLE_CUDA_RUNTIME)
  (void)grid_x; (void)grid_y; (void)grid_z;
  (void)block_x; (void)block_y; (void)block_z;
  (void)shared_mem_bytes; (void)args_buf; (void)args_len; (void)arg_count;
  snprintf(err_buf, err_buf_len, "CUDA runtime disabled");
  return -1;
#else
  size_t off = 0;
  if (kernel->id == 1u) {
    if (arg_count != 0) {
      snprintf(err_buf, err_buf_len, "noop expects 0 args");
      return -1;
    }
    CUresult res = cuLaunchKernel(kernel->function,
                                  grid_x, grid_y, grid_z,
                                  block_x, block_y, block_z,
                                  shared_mem_bytes, NULL, NULL, NULL);
    if (res != CUDA_SUCCESS) {
      format_cuda_error(err_buf, err_buf_len, res, "cuLaunchKernel(noop)");
      return -1;
    }
    cuCtxSynchronize();
    return 0;
  }

  if (kernel->id == 2u) {
    if (arg_count != 4) {
      snprintf(err_buf, err_buf_len, "tensor_add expects 4 args");
      return -1;
    }
    CUdeviceptr dev_ptrs[3] = {0};
    uint32_t n = 0;
    void* kernel_args[4] = {0};

    for (uint32_t i = 0; i < arg_count; i++) {
      if (off + 8 > args_len) {
        snprintf(err_buf, err_buf_len, "args truncated");
        return -1;
      }
      uint8_t kind = args_buf[off];
      uint32_t size = load_le32(args_buf + off + 4);
      off += 8;
      if (off + size > args_len) {
        snprintf(err_buf, err_buf_len, "arg payload truncated");
        return -1;
      }
      if (i < 3) {
        if (kind != 2 || size != 4) {
          snprintf(err_buf, err_buf_len, "expected buffer handle args");
          return -1;
        }
        int32_t handle = (int32_t)load_le32(args_buf + off);
        struct accel_handle* h = accel_handle_get(host, handle);
        if (!h || h->kind != ACCEL_HANDLE_BUFFER) {
          snprintf(err_buf, err_buf_len, "invalid buffer handle");
          return -1;
        }
        if (!h->dev_ptr) {
          snprintf(err_buf, err_buf_len, "buffer handle missing device pointer");
          return -1;
        }
        dev_ptrs[i] = h->dev_ptr;
        kernel_args[i] = &dev_ptrs[i];
      } else {
        if (kind != 1 || size != 4) {
          snprintf(err_buf, err_buf_len, "expected inline u32 arg");
          return -1;
        }
        n = load_le32(args_buf + off);
        kernel_args[3] = &n;
      }
      off += size;
    }

    if (bench_debug_enabled()) {
      fprintf(stderr,
              "[cloak] submit tensor_add grid=%u block=%u n=%u ptrs=%llx/%llx/%llx\n",
              grid_x, block_x, n,
              (unsigned long long)dev_ptrs[0],
              (unsigned long long)dev_ptrs[1],
              (unsigned long long)dev_ptrs[2]);
    }
    CUresult res = cuLaunchKernel(kernel->function,
                                  grid_x, grid_y, grid_z,
                                  block_x, block_y, block_z,
                                  shared_mem_bytes, NULL, kernel_args, NULL);
    if (res != CUDA_SUCCESS) {
      format_cuda_error(err_buf, err_buf_len, res, "cuLaunchKernel(tensor_add)");
      return -1;
    }
    if (bench_debug_enabled()) {
      fprintf(stderr, "[cloak] submit tensor_add launch ok\n");
    }
    cuCtxSynchronize();
    if (bench_debug_enabled()) {
      fprintf(stderr, "[cloak] submit tensor_add sync ok\n");
    }
    return 0;
  }

  snprintf(err_buf, err_buf_len, "unsupported kernel");
  return -1;
#endif
}

CLOAK_BENCH_API int32_t cloak_ctl(void* ctx,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t req_ptr,
                         int32_t req_len,
                         int32_t resp_ptr,
                         int32_t resp_cap) {
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (!mem) return -1;
  if (!in_bounds(mem_cap, req_ptr, req_len)) return -1;
  if (!in_bounds(mem_cap, resp_ptr, resp_cap)) return -1;
  if (req_len < (int32_t)ZCL1_REQ_HEADER_LEN) return -1;

  const uint8_t* req_buf = mem + (size_t)req_ptr;
  zcl1_req_header req;
  if (zcl1_parse_req_header(&req, req_buf, (size_t)req_len) != 0) return -1;
  if (!zcl1_magic_valid(req.magic)) return -1;
  if (req.version != ZCL1_VERSION) {
    return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                &req, "t_ctl_bad_version", "unsupported version");
  }
  if (req.flags != ZCL1_FLAGS_NONE) {
    return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                &req, "t_ctl_bad_frame", "flags must be zero");
  }
  if ((size_t)req_len != ZCL1_REQ_HEADER_LEN + req.payload_len) {
    return -1;
  }

  const uint8_t* payload = req_buf + ZCL1_REQ_HEADER_LEN;
  size_t payload_len = (size_t)req.payload_len;

  if (req.op == ZCL1_OP_CAPS_LIST) {
    if (payload_len != 0) {
      return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                  &req, "t_ctl_bad_params", "CAPS_LIST payload must be empty");
    }
    return write_caps_list(mem, mem_cap, resp_ptr, resp_cap, &req, host);
  }

  if (req.op == ZCL1_OP_CAPS_DESCRIBE) {
    return write_caps_describe(mem, mem_cap, resp_ptr, resp_cap, &req, payload, payload_len);
  }

  if (req.op == ZCL1_OP_CAPS_OPEN) {
    size_t off = 0;
    const uint8_t* kind = NULL;
    size_t kind_len = 0;
    const uint8_t* name = NULL;
    size_t name_len = 0;
    const uint8_t* params = NULL;
    size_t params_len = 0;

    if (hopper_read_field(payload, payload_len, &off, &kind, &kind_len) != 0 ||
        hopper_read_field(payload, payload_len, &off, &name, &name_len) != 0 ||
        off + 4 > payload_len) {
      return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                  &req, "t_ctl_bad_params", "CAPS_OPEN params invalid");
    }
    uint32_t mode = load_le32(payload + off);
    off += 4;
    if (hopper_read_field(payload, payload_len, &off, &params, &params_len) != 0 ||
        off != payload_len) {
      return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                  &req, "t_ctl_bad_params", "CAPS_OPEN params invalid");
    }
    if (!hstr_eq(kind, kind_len, "accel") || !hstr_eq(name, name_len, "default")) {
      return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                  &req, "t_cap_missing", "capability not found");
    }

    int32_t handle_id = -1;
    uint32_t hflags = 0;
    uint8_t* stream_buf = NULL;
    size_t stream_len = 0;

    if (mode == 1u) {
      size_t poff = 0;
      const uint8_t* backend = NULL;
      size_t backend_len = 0;
      if (hopper_read_field(params, params_len, &poff, &backend, &backend_len) != 0 ||
          poff != params_len) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "QUERY params invalid");
      }
      if (!hstr_eq(backend, backend_len, "cuda")) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_accel_no_device", "backend not available");
      }
      if (build_query_record(host, &stream_buf, &stream_len) != 0) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_accel_no_device", "CUDA backend unavailable");
      }
      struct accel_handle* h = NULL;
      handle_id = accel_handle_alloc(host, ACCEL_HANDLE_STREAM, &h);
      if (handle_id < 0 || !h) {
        free(stream_buf);
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_overflow", "no handles available");
      }
      h->host_buf = stream_buf;
      h->size = stream_len;
      h->offset = 0;
      hflags = 0x5;
    } else if (mode == 2u) {
      size_t poff = 0;
      const uint8_t* backend = NULL;
      size_t backend_len = 0;
      const uint8_t* device_id = NULL;
      size_t device_id_len = 0;
      const uint8_t* bytes_ptr = NULL;
      size_t bytes_len = 0;
      const uint8_t* flags_ptr = NULL;
      size_t flags_len = 0;
      if (hopper_read_field(params, params_len, &poff, &backend, &backend_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &device_id, &device_id_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &bytes_ptr, &bytes_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &flags_ptr, &flags_len) != 0 ||
          poff != params_len) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "BUFFER params invalid");
      }
      if (!hstr_eq(backend, backend_len, "cuda") || !hstr_eq(device_id, device_id_len, "0")) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_accel_no_device", "device not available");
      }
      if (bytes_len != 8 || flags_len != 4) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "BUFFER params invalid");
      }
      uint64_t bytes = load_le64(bytes_ptr);
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
      if (!host || !host->backend.available) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_accel_no_device", "CUDA backend unavailable");
      }
      struct accel_handle* h = NULL;
      handle_id = accel_handle_alloc(host, ACCEL_HANDLE_BUFFER, &h);
      if (handle_id < 0 || !h) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_overflow", "no handles available");
      }
      CUresult res = cuMemAlloc(&h->dev_ptr, (size_t)bytes);
      if (res != CUDA_SUCCESS) {
        accel_handle_release(host, handle_id);
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_overflow", "buffer alloc failed");
      }
      h->size = (size_t)bytes;
      h->offset = 0;
      hflags = 0x7;
#else
      return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                  &req, "t_accel_no_device", "CUDA runtime disabled");
#endif
    } else if (mode == 3u) {
      size_t poff = 0;
      const uint8_t* backend = NULL;
      size_t backend_len = 0;
      const uint8_t* device_id = NULL;
      size_t device_id_len = 0;
      const uint8_t* module_id = NULL;
      size_t module_id_len = 0;
      const uint8_t* kernel_id = NULL;
      size_t kernel_id_len = 0;
      if (hopper_read_field(params, params_len, &poff, &backend, &backend_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &device_id, &device_id_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &module_id, &module_id_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &kernel_id, &kernel_id_len) != 0 ||
          poff + 4 * 9 > params_len) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "SUBMIT params invalid");
      }
      if (!hstr_eq(backend, backend_len, "cuda") || !hstr_eq(device_id, device_id_len, "0")) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_accel_no_device", "device not available");
      }
      if (!hstr_eq(module_id, module_id_len, "builtin")) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "unknown module id");
      }
      uint32_t grid_x = load_le32(params + poff); poff += 4;
      uint32_t grid_y = load_le32(params + poff); poff += 4;
      uint32_t grid_z = load_le32(params + poff); poff += 4;
      uint32_t block_x = load_le32(params + poff); poff += 4;
      uint32_t block_y = load_le32(params + poff); poff += 4;
      uint32_t block_z = load_le32(params + poff); poff += 4;
      uint32_t shared_mem = load_le32(params + poff); poff += 4;
      uint32_t arg_count = load_le32(params + poff); poff += 4;
      if (poff > params_len) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "SUBMIT params invalid");
      }
      const uint8_t* args_buf = params + poff;
      size_t args_len = params_len - poff;
      if (args_len < 4 || args_len < (size_t)(arg_count * 8)) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "SUBMIT args invalid");
      }
      const struct cuda_kernel_meta* kernel = find_kernel_by_name(kernel_id, kernel_id_len);
      if (!kernel) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "unknown kernel id");
      }
      char err_buf[256];
      if (submit_kernel(host, kernel, grid_x, grid_y, grid_z, block_x, block_y, block_z,
                        shared_mem, args_buf, args_len, arg_count,
                        err_buf, sizeof(err_buf)) != 0) {
        if (build_status_record(0, "t_accel_backend", err_buf, &stream_buf, &stream_len) != 0) {
          return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                      &req, "t_ctl_overflow", "response build failed");
        }
      } else {
        if (build_status_record(1, NULL, NULL, &stream_buf, &stream_len) != 0) {
          return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                      &req, "t_ctl_overflow", "response build failed");
        }
      }
      struct accel_handle* h = NULL;
      handle_id = accel_handle_alloc(host, ACCEL_HANDLE_STREAM, &h);
      if (handle_id < 0 || !h) {
        free(stream_buf);
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_overflow", "no handles available");
      }
      h->host_buf = stream_buf;
      h->size = stream_len;
      h->offset = 0;
      hflags = 0x5;
    } else if (mode == 4u) {
      size_t poff = 0;
      const uint8_t* backend = NULL;
      size_t backend_len = 0;
      const uint8_t* device_id = NULL;
      size_t device_id_len = 0;
      const uint8_t* queue_id = NULL;
      size_t queue_id_len = 0;
      if (hopper_read_field(params, params_len, &poff, &backend, &backend_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &device_id, &device_id_len) != 0 ||
          hopper_read_field(params, params_len, &poff, &queue_id, &queue_id_len) != 0 ||
          poff != params_len) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_bad_params", "SYNC params invalid");
      }
      if (!hstr_eq(backend, backend_len, "cuda") || !hstr_eq(device_id, device_id_len, "0")) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_accel_no_device", "device not available");
      }
      int ok = 0;
#if defined(ZCC_ENABLE_CUDA_RUNTIME)
      if (host && host->backend.available && cuCtxSynchronize() == CUDA_SUCCESS) {
        ok = 1;
      }
#endif
      if (build_sync_record(&stream_buf, &stream_len, ok) != 0) {
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_overflow", "response build failed");
      }
      struct accel_handle* h = NULL;
      handle_id = accel_handle_alloc(host, ACCEL_HANDLE_STREAM, &h);
      if (handle_id < 0 || !h) {
        free(stream_buf);
        return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                    &req, "t_ctl_overflow", "no handles available");
      }
      h->host_buf = stream_buf;
      h->size = stream_len;
      h->offset = 0;
      hflags = 0x5;
      (void)queue_id;
      (void)queue_id_len;
    } else {
      return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                                  &req, "t_ctl_bad_params", "unknown CAPS_OPEN mode");
    }

    size_t payload_total = ZCL1_RESP_OK_PREFIX_LEN + sizeof(uint32_t) * 2 + hopper_field_size(0);
    size_t total = ZCL1_RESP_HEADER_LEN + payload_total;
    if (resp_ptr < 0 || resp_cap < 0) return -1;
    size_t resp_start = (size_t)resp_ptr;
    size_t resp_cap_sz = (size_t)resp_cap;
    if (total > resp_cap_sz) return -1;
    if (resp_start + total > mem_cap) return -1;

    zcl1_resp_header rh;
    zcl1_init_resp_from_req(&rh, &req);
    rh.payload_len = (uint32_t)payload_total;
    uint8_t* out = mem + resp_start;
    if (zcl1_write_resp_header(out, resp_cap_sz, &rh) != 0) return -1;

    uint8_t* cursor = out + ZCL1_RESP_HEADER_LEN;
    cursor[0] = 1;
    cursor[1] = 0;
    cursor[2] = 0;
    cursor[3] = 0;
    cursor += ZCL1_RESP_OK_PREFIX_LEN;
    store_le32(cursor, (uint32_t)handle_id);
    cursor += sizeof(uint32_t);
    store_le32(cursor, hflags);
    cursor += sizeof(uint32_t);
    hopper_write_field(&cursor, NULL, 0);
    return clamp_i32_from_size(total);
  }

  return write_error_response(mem, mem_cap, resp_ptr, resp_cap,
                              &req, "t_ctl_unknown_op", "unsupported op");
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

/* Get monotonic nanosecond timestamp */
void _clock_gettime_monotonic_ns(uint64_t* out) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    *out = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  } else {
    *out = 0;
  }
}

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

  int rc = lembeh_handle(ZCAP_IN,
                         ZCAP_OUT,
                         cloak_in,
                         cloak_out,
                         cloak_end,
                         cloak_log,
                         cloak_ctl,
                         &host,
                         &sys);
  cuda_backend_shutdown(&host.backend);
  return rc;
}
