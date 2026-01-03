# Building zcc with CUDA Support

This guide covers building and testing the zcc CUDA cloak on WSL2 with NVIDIA GPU support.

## Prerequisites

### WSL2 CUDA Setup
1. Install NVIDIA Windows driver (v581.15+ includes WSL2 CUDA support)
2. Verify GPU visibility: `nvidia-smi`
3. Install CUDA toolkit in WSL2:
   ```bash
   sudo apt update
   sudo apt install -y build-essential clang pkg-config nvidia-cuda-toolkit
   ```

## Building

### 1. Build the Compiler
```bash
make clean
make zcc
```

### 2. Run Basic Tests
```bash
make test
```

### 3. Build CUDA Cloak Examples
```bash
make examples
```

### 4. Test CUDA Cloak
```bash
make test-cuda-cloak
```

## Manual Build Steps

If you need to build components separately:

```bash
# Build zcc compiler
make zcc

# Build CUDA cloak object (with runtime enabled)
make cloak-cuda

# Compile a JSONL program to C
./bin/zcc --output build/program.c < examples/ctl_probe.jsonl

# Link with CUDA cloak
clang -Iinclude -Inormative \
  build/program.c \
  cloak/cloak_cuda.c \
  normative/zing_zctl1_kernel_backplane_pack_v1/c/zctl1.c \
  -o build/program_cuda \
  -L/usr/lib/x86_64-linux-gnu -lcuda

# Run
./build/program_cuda
```

## CUDA Runtime Status

The CUDA cloak is built with `ZCC_ENABLE_CUDA_RUNTIME` enabled, which:
- Initializes the CUDA driver via `cuInit(0)`
- Selects device 0 and creates a context
- Implements the ZCTL/1 kernel backplane protocol
- Supports `CAPS_LIST`, `KERNEL_LIST`, and `KERNEL_RUN` operations

### Current Capabilities

✅ CUDA driver initialization  
✅ Device context management  
✅ Control plane protocol (`_ctl`)  
✅ Capability discovery  
✅ Kernel catalog listing  
✅ PTX kernel loading (module management)
✅ Kernel execution (noop and tensor_add)
✅ Device memory allocation
✅ Argument marshaling

The CUDA cloak now supports full kernel execution for:
- **noop**: Simple no-op kernel with no arguments
- **tensor_add**: Vector addition kernel with device memory allocation

### Extending Further

To complete kernel execution support, implement in `cloak/cloak_cuda.c`:

1. **Load kernel modules**: Store PTX/cubin paths in `CUDA_KERNELS` and load with `cuModuleLoad`
2. **Argument marshaling**: Map `zctl1_arg` records to CUDA kernel parameters
3. **Device memory**: Allocate buffers via `cuMemAlloc` for tensor/buffer arguments
4. **Launch**: Call `cuLaunchKernel` with grid/block dimensions
5. **Synchronize**: Wait for completion and copy results back
6. **Update response**: Set `ok=1` in `zctl1_kernel_run_resp` on success

See `docs/CLOAK_CUDA.md` for the complete roadmap.

## Troubleshooting

### GPU Not Visible
- Ensure Windows NVIDIA driver is up to date
- Restart WSL: `wsl --shutdown` then relaunch
- Check: `nvidia-smi` should show GPU details

### Linker Errors
- Verify libcuda.so location: `ldconfig -p | grep cuda`
- Adjust `-L` path in Makefile if needed

### Runtime Failures
- Check stderr for `[cloak]` diagnostic messages
- Verify JSONL request headers match ZCTL/1 spec (magic `0x4C54435A`)
- Increase response buffer if `_ctl` returns `ZCTL_ERR`

## Testing

The `examples/ctl_probe.jsonl` program exercises:
- ZCTL/1 request encoding
- `_ctl` backplane invocation
- `CAPS_LIST` response handling
- Stdio output via `_out`

Expected output:
```
Caps list ok
```

Exit code 0 indicates success.
