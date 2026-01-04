/* Standalone benchmark stub - provides _ctl by wrapping cloak_ctl */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* Simple memory buffer */
static uint8_t bench_mem[2 * 1024 * 1024];

/* Match the structs from cloak_cuda.c */
struct cuda_backend {
  int initialized;
  int available;
  char last_error[256];
  /* CUDA-specific fields omitted - will be filled by cuda_backend_init */
  char _opaque[256];
};

struct host_ctx {
  FILE* in;
  FILE* out;
  FILE* log;
  int stdout_closed;
  struct cuda_backend backend;
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

/* The cloak functions we need are static, so we can't call them directly.
 * Instead, we'll compile cloak_cuda.c with -DBENCH_MODE which will expose them.
 */
 
/* For now, declare them as weak and they'll be linked from cloak_bench.c */
extern void cuda_backend_init(struct cuda_backend* backend) __attribute__((weak));
extern int32_t cloak_ctl(void* ctx,
                         uint8_t* mem,
                         size_t mem_cap,
                         int32_t req_ptr,
                         int32_t req_len,
                         int32_t resp_ptr,
                         int32_t resp_cap) __attribute__((weak));

/* Initialize the host context (call this once) */
void bench_init(void) {
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
  
  /* Copy response out */
  if (result > 0 && (uint32_t)result <= resp_cap) {
    for (int32_t i = 0; i < result; i++) {
      resp[i] = bench_mem[req_len + i];
    }
  }
  
  return result;
}
