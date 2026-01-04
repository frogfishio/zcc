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

#include "../normative/zing_zctl1_kernel_backplane_pack_v1/c/zctl1.h"

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
};

struct heap_ctx {
  int32_t head;
};

static void cuda_backend_init(struct cuda_backend* backend) {
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
  if (wrote != want) {
    log_host_msg(host, "stdout write failed");
    return -1;
  }
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

static int32_t respond_kernel_run_success(const zctl1_req_header* req,
                                          uint8_t* resp,
                                          size_t resp_cap) {
  size_t payload_len = sizeof(zctl1_kernel_run_resp);
  size_t total = ZCTL1_RESP_HEADER_LEN + payload_len;
  if (resp_cap < total) return ZCTL_ERR;

  zctl1_resp_header rh;
  zctl1_init_resp_from_req(&rh, req);
  rh.status = ZCTL1_OK;
  rh.payload_len = (uint32_t)payload_len;
  if (zctl1_encode_resp_header(resp, resp_cap, &rh) != 0) return ZCTL_ERR;

  zctl1_kernel_run_resp body;
  body.ok = 1;
  body.err_code = 0;
  body.err_msg_len = 0;
  memcpy(resp + ZCTL1_RESP_HEADER_LEN, &body, sizeof(body));
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

  struct cuda_kernel_meta* kernel = NULL;
  for (size_t i = 0; i < sizeof(CUDA_KERNELS) / sizeof(CUDA_KERNELS[0]); i++) {
    if (CUDA_KERNELS[i].id == run->kernel_id) {
      kernel = &CUDA_KERNELS[i];
      break;
    }
  }
  if (!kernel) {
    return respond_kernel_run_stub(req, resp, resp_cap, "kernel id not found", ZCTL1_ERR_BAD_ARGS);
  }

  if (!host || !host->backend.available) {
    const char* err = host && host->backend.initialized
                        ? host->backend.last_error
                        : "CUDA backend unavailable";
    return respond_kernel_run_stub(req, resp, resp_cap, err, ZCTL1_ERR_BACKEND);
  }

#if defined(ZCC_ENABLE_CUDA_RUNTIME)
  /* Execute kernel */
  const zctl1_arg* args = (const zctl1_arg*)(payload + sizeof(zctl1_kernel_run_req));
  
  fprintf(stderr, "[cloak] Executing kernel %u with %u args\n", kernel->id, run->arg_count);
  fflush(stderr);
  
  /* Simple execution for noop kernel (no args) */
  if (kernel->id == 1u && run->arg_count == 0) {
    fprintf(stderr, "[cloak] Launching noop kernel...\n");
    fflush(stderr);
    CUresult res = cuLaunchKernel(kernel->function, 1, 1, 1, 1, 1, 1, 0, NULL, NULL, NULL);
    fprintf(stderr, "[cloak] cuLaunchKernel returned %d\n", res);
    fflush(stderr);
    if (res != CUDA_SUCCESS) {
      char err_buf[256];
      format_cuda_error(err_buf, sizeof(err_buf), res, "cuLaunchKernel(noop)");
      return respond_kernel_run_stub(req, resp, resp_cap, err_buf, ZCTL1_ERR_BACKEND);
    }
    cuCtxSynchronize();
    return respond_kernel_run_success(req, resp, resp_cap);
  }
  
  /* For tensor_add: expect 3 buffer args (a, b, c) + 1 scalar (n) */
  if (kernel->id == 2u && run->arg_count == 4) {
    void* kernel_args[4];
    CUdeviceptr dev_ptrs[3] = {0};
    int allocated_count = 0;
    
    /* Allocate device memory for 3 float arrays */
    for (int i = 0; i < 3; i++) {
      if (args[i].kind != ZCTL1_ARG_U32) {
        for (int j = 0; j < allocated_count; j++) cuMemFree(dev_ptrs[j]);
        return respond_kernel_run_stub(req, resp, resp_cap, "expected u32 size args", ZCTL1_ERR_BAD_ARGS);
      }
      size_t buf_size = args[i].a * sizeof(float);
      CUresult res = cuMemAlloc(&dev_ptrs[i], buf_size);
      if (res != CUDA_SUCCESS) {
        for (int j = 0; j < allocated_count; j++) cuMemFree(dev_ptrs[j]);
        return respond_kernel_run_stub(req, resp, resp_cap, "cuMemAlloc failed", ZCTL1_ERR_NO_MEM);
      }
      allocated_count++;
      
      /* Initialize inputs with test data */
      if (i < 2) {
        float* host_buf = (float*)malloc(buf_size);
        if (host_buf) {
          for (size_t k = 0; k < args[i].a; k++) host_buf[k] = (float)(i + 1) * (k + 1);
          cuMemcpyHtoD(dev_ptrs[i], host_buf, buf_size);
          free(host_buf);
        }
      }
      kernel_args[i] = &dev_ptrs[i];
    }
    
    /* Fourth arg is element count */
    uint32_t n = args[3].a;
    kernel_args[3] = &n;
    
    /* Launch kernel */
    unsigned int block_size = 256;
    unsigned int grid_size = (n + block_size - 1) / block_size;
    
    static int launch_count = 0;
    if (launch_count < 2) {
      fprintf(stderr, "[cloak] Launching tensor_add: grid=%u, block=%u, n=%u\n", 
              grid_size, block_size, n);
      fflush(stderr);
    }
    
    CUresult res = cuLaunchKernel(kernel->function,
                                  grid_size, 1, 1,
                                  block_size, 1, 1,
                                  0, NULL, kernel_args, NULL);
    cuCtxSynchronize();
    
    if (launch_count < 2) {
      fprintf(stderr, "[cloak] tensor_add completed (cuLaunchKernel result=%d)\n", res);
      fflush(stderr);
      launch_count++;
    }
    
    /* Cleanup */
    for (int i = 0; i < 3; i++) cuMemFree(dev_ptrs[i]);
    
    if (res != CUDA_SUCCESS) {
      char err_buf[256];
      format_cuda_error(err_buf, sizeof(err_buf), res, "cuLaunchKernel(tensor_add)");
      return respond_kernel_run_stub(req, resp, resp_cap, err_buf, ZCTL1_ERR_BACKEND);
    }
    
    return respond_kernel_run_success(req, resp, resp_cap);
  }
  
  return respond_kernel_run_stub(req, resp, resp_cap, "unsupported kernel/args combination", ZCTL1_ERR_BAD_ARGS);
#else
  return respond_kernel_run_stub(req, resp, resp_cap, "CUDA runtime disabled", ZCTL1_ERR_BACKEND);
#endif
}

static int32_t cloak_ctl(void* ctx,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t req_ptr,
                         int32_t req_len,
                         int32_t resp_ptr,
                         int32_t resp_cap) {
  struct host_ctx* host = (struct host_ctx*)ctx;
  if (!mem) {
    log_host_msg(host, "_ctl missing memory pointer");
    return ZCTL_ERR;
  }
  if (!in_bounds(mem_cap, req_ptr, req_len)) {
    log_host_msg(host, "_ctl request buffer OOB");
    return ZCTL_ERR;
  }
  if (!in_bounds(mem_cap, resp_ptr, resp_cap)) {
    log_host_msg(host, "_ctl response buffer OOB");
    return ZCTL_ERR;
  }
  if (req_len < (int32_t)ZCTL1_REQ_HEADER_LEN) {
    log_host_msg(host, "_ctl header truncated");
    return ZCTL_ERR;
  }

  const uint8_t* req_buf = mem + (size_t)req_ptr;
  zctl1_req_header req;
  if (zctl1_decode_req_header(&req, req_buf, (size_t)req_len) != 0) {
    log_host_msg(host, "_ctl header decode failed");
    return ZCTL_ERR;
  }
  
  if ((size_t)req_len != ZCTL1_REQ_HEADER_LEN + req.payload_len) {
    log_host_msg(host, "_ctl payload length mismatch");
    return ZCTL_ERR;
  }

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
