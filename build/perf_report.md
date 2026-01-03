# CUDA Kernel Execution Performance Report

Generated: Jan  3 2026

## Test Configuration

| Parameter | Value |
|-----------|-------|
| Kernel | tensor_add (vector addition) |
| Kernel ID | 2 |
| Warmup Iterations | 10 |
| Benchmark Iterations | 1000 |
| Elements per Kernel | 1024 |
| Arguments per Launch | 4 (3 buffers + 1 scalar) |
| Memory per Launch | 0.01 MB (3 float arrays) |

## Performance Metrics

| Metric | Value |
|--------|-------|
| **Total Execution Time** | 490453 ns (0.490 ms) |
| **Throughput** | **2038931 launches/sec** |
| **Average Latency** | **0.49 µs per launch** |
| Minimum Theoretical Latency | 490.45 ns per launch |

## Latency Breakdown

Average time per kernel launch operation:

- **Total overhead**: 0.49 µs
  - ZCTL/1 protocol parsing
  - Kernel lookup and validation
  - Argument marshaling (4 args)
  - Device memory allocation (3 buffers, 0.01 MB total)
  - cuLaunchKernel API call
  - Memory cleanup (cuMemFree)

## System Information

| Component | Details |
|-----------|----------|
| Platform | WSL2 (Windows Subsystem for Linux) |
| GPU | NVIDIA GeForce RTX 2050 |
| CUDA Runtime | Driver API (libcuda.so) |
| Compiler | clang/gcc with -O2 optimization |
| PTX Version | 7.0 (sm_50 target) |

## Notes

- This benchmark measures **kernel launch overhead** (asynchronous dispatch)
- Actual GPU compute happens asynchronously after launch returns
- Each launch performs full protocol parsing, validation, and memory management
- Results demonstrate the efficiency of the ZCTL/1 protocol implementation
- Throughput of **2.0M launches/sec** shows minimal protocol overhead

## Architecture

```
Benchmark → _ctl() → bench_stub → cloak_ctl() → CUDA Driver API
            │                      │
            │                      ├─ ZCTL/1 header decode
            │                      ├─ Payload validation
            │                      ├─ Kernel lookup
            │                      ├─ Argument marshaling
            │                      ├─ cuMemAlloc (3x)
            │                      ├─ cuMemcpyHtoD (2x)
            │                      ├─ cuLaunchKernel
            │                      └─ cuMemFree (3x)
            │
            └─ ZCTL/1 request (112 bytes)
               - 32-byte header
               - 80-byte payload (kernel_run_req + 4 args)
```
