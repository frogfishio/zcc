/* Minimal CUDA cloak for benchmarking - exposes internal functions */
#define _POSIX_C_SOURCE 199309L

#include "zprog_rt.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(ZCC_ENABLE_CUDA_RUNTIME)
#include <cuda.h>
#endif

/* Include the full cloak implementation but exclude main */
#define main _disabled_main_from_cloak
#include "cloak_cuda.c"
#undef main
