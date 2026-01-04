/* Standalone benchmark stub - provides _ctl/_in/_out by wrapping cloak cloaks */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(ZCC_ENABLE_CUDA_RUNTIME)
#include <cuda.h>
#endif

/* Simple memory buffer */
static uint8_t bench_mem[2 * 1024 * 1024];

/* Match the structs from cloak_cuda.c */
#define ACCEL_MAX_HANDLES 64

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

/* Forward declarations - these are actually static in cloak_cuda.c */
/* We'll need to expose them or work around it */

/* Stubs for functions we don't need */
int32_t zprog_heap_base_value(void) { return 0; }

int32_t lembeh_handle(int32_t in_handle,
                      int32_t out_handle,
                      void* in_fn,
                      void* out_fn,
                      void* end_fn,
                      void* log_fn,
                      void* ctl_fn,
                      void* host_ctx,
                      void* sys) {
  (void)in_handle; (void)out_handle;
  (void)in_fn; (void)out_fn; (void)end_fn;
  (void)log_fn; (void)ctl_fn;
  (void)host_ctx; (void)sys;
  return 0;
}

/* Global host context for benchmark */
static struct host_ctx g_host = {
  .in = NULL,
  .out = NULL,
  .log = NULL,
  .stdout_closed = 0,
};

/* The cloak functions we need are static; cloak_bench.c redefines static to expose them. */
 
/* For now, declare them as weak and they'll be linked from cloak_bench.c */
extern void cuda_backend_init(struct cuda_backend* backend) __attribute__((weak));
extern int32_t cloak_in(void* ctx,
                        int32_t req_handle,
                        uint8_t* mem,
                        size_t mem_cap,
                        int32_t ptr,
                        int32_t cap) __attribute__((weak));
extern int32_t cloak_out(void* ctx,
                         int32_t res_handle,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t ptr,
                         int32_t len) __attribute__((weak));
extern void cloak_end(void* ctx, int32_t res_handle) __attribute__((weak));
extern int32_t cloak_ctl(void* ctx,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t req_ptr,
                         int32_t req_len,
                         int32_t resp_ptr,
                         int32_t resp_cap) __attribute__((weak));

/* Initialize the host context (call this once) */
void bench_init(void) {
  memset(&g_host, 0, sizeof(g_host));
  g_host.in = stdin;
  g_host.out = stdout;
  g_host.log = stderr;
  if (cuda_backend_init) {
    cuda_backend_init(&g_host.backend);
  }
}

/* _ctl wrapper that the benchmark calls */
int32_t _ctl(uint8_t* req, uint32_t req_len, uint8_t* resp, uint32_t resp_cap) {
  /* Copy request into memory */
  if (req_len > sizeof(bench_mem) / 2) return -1;
  
  for (uint32_t i = 0; i < req_len; i++) {
    bench_mem[i] = req[i];
  }
  
  /* Call cloak_ctl */
  int32_t result = -1;
  if (cloak_ctl) {
    result = cloak_ctl(&g_host, 
                       bench_mem, 
                       sizeof(bench_mem),
                       0,           /* req at offset 0 */
                       req_len,
                       req_len,     /* resp after req */
                       resp_cap);
  }
  if (getenv("ZCC_BENCH_DEBUG")) {
    fprintf(stderr, "[bench] _ctl result=%d resp_cap=%u req_len=%u\n",
            result, resp_cap, req_len);
    if (result > 0 && (uint32_t)result > resp_cap) {
      fprintf(stderr, "[bench] _ctl result exceeds resp_cap\n");
    }
  }
  
  /* Copy response out */
  if (result > 0 && (uint32_t)result <= resp_cap) {
    for (int32_t i = 0; i < result; i++) {
      resp[i] = bench_mem[req_len + i];
    }
  }
  
  return result;
}

/* _in wrapper for reading from stream/buffer handles */
int32_t _in(int32_t handle, uint8_t* dst, uint32_t cap) {
  if (!dst || cap > sizeof(bench_mem)) return -1;
  if (!cloak_in) return -1;
  int32_t result = cloak_in(&g_host, handle, bench_mem, sizeof(bench_mem), 0, (int32_t)cap);
  if (result > 0) {
    memcpy(dst, bench_mem, (size_t)result);
  }
  return result;
}

/* _out wrapper for writing to buffer handles */
int32_t _out(int32_t handle, const uint8_t* src, uint32_t len) {
  if (!src || len > sizeof(bench_mem)) return -1;
  if (!cloak_out) return -1;
  memcpy(bench_mem, src, len);
  return cloak_out(&g_host, handle, bench_mem, sizeof(bench_mem), 0, (int32_t)len);
}

/* _end wrapper for releasing handles */
void _end(int32_t handle) {
  if (cloak_end) {
    if (getenv("ZCC_BENCH_DEBUG")) {
      fprintf(stderr, "[bench] end handle=%d\n", handle);
      fflush(stderr);
    }
    cloak_end(&g_host, handle);
  }
}
