/* Minimal CUDA cloak for benchmarking - exposes internal functions */
#define _POSIX_C_SOURCE 199309L

/* Make internal functions non-static for benchmarking */
#define static

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(ZCC_ENABLE_CUDA_RUNTIME)
#include <cuda.h>
#endif

#include "../normative/zing_zctl1_kernel_backplane_pack_v1/c/zctl1.h"

/* Include the full cloak implementation but exclude main */
#define main _disabled_main_from_cloak
#include "cloak_cuda.c"
#undef main
