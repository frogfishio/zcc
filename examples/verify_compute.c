/* Verification test to prove GPU computation actually happens */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <cuda.h>

int main(void) {
    printf("=== CUDA Computation Verification Test ===\n\n");
    
    /* Initialize CUDA */
    CUresult res = cuInit(0);
    if (res != CUDA_SUCCESS) {
        printf("✗ cuInit failed: %d\n", res);
        return 1;
    }
    
    CUdevice device;
    CUcontext context;
    cuDeviceGet(&device, 0);
    cuCtxCreate(&context, 0, device);
    
    /* Simple PTX kernel that adds vectors */
    const char* ptx = 
        ".version 7.0\n"
        ".target sm_50\n"
        ".address_size 64\n"
        ".visible .entry tensor_add(.param .u64 a, .param .u64 b, .param .u64 c, .param .u32 n) {\n"
        "  .reg .pred %p<2>;\n"
        "  .reg .b32 %r<6>;\n"
        "  .reg .f32 %f<4>;\n"
        "  .reg .b64 %rd<11>;\n"
        "  ld.param.u64 %rd1, [a];\n"
        "  ld.param.u64 %rd2, [b];\n"
        "  ld.param.u64 %rd3, [c];\n"
        "  ld.param.u32 %r2, [n];\n"
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
    
    CUmodule module;
    CUfunction function;
    res = cuModuleLoadDataEx(&module, ptx, 0, NULL, NULL);
    if (res != CUDA_SUCCESS) {
        printf("✗ Module load failed: %d\n", res);
        return 1;
    }
    
    cuModuleGetFunction(&function, module, "tensor_add");
    
    /* Allocate and initialize test data */
    const int N = 1024;
    float a[N], b[N], c[N];
    for (int i = 0; i < N; i++) {
        a[i] = (float)i;
        b[i] = (float)(i * 2);
        c[i] = 0.0f;
    }
    
    CUdeviceptr d_a, d_b, d_c;
    cuMemAlloc(&d_a, N * sizeof(float));
    cuMemAlloc(&d_b, N * sizeof(float));
    cuMemAlloc(&d_c, N * sizeof(float));
    
    cuMemcpyHtoD(d_a, a, N * sizeof(float));
    cuMemcpyHtoD(d_b, b, N * sizeof(float));
    
    /* Launch kernel */
    void* args[] = { &d_a, &d_b, &d_c, &N };
    unsigned int grid = (N + 255) / 256;
    unsigned int block = 256;
    
    printf("Launching kernel: grid=%u, block=%u, n=%d\n", grid, block, N);
    res = cuLaunchKernel(function, grid, 1, 1, block, 1, 1, 0, NULL, args, NULL);
    if (res != CUDA_SUCCESS) {
        printf("✗ Kernel launch failed: %d\n", res);
        return 1;
    }
    
    /* Wait for completion and copy results */
    cuCtxSynchronize();
    cuMemcpyDtoH(c, d_c, N * sizeof(float));
    
    /* Verify results */
    int errors = 0;
    for (int i = 0; i < N && errors < 5; i++) {
        float expected = a[i] + b[i];
        if (c[i] != expected) {
            printf("✗ Error at index %d: expected %.1f, got %.1f\n", i, expected, c[i]);
            errors++;
        }
    }
    
    if (errors == 0) {
        printf("✓ All %d results correct!\n", N);
        printf("  Sample: a[0]=%.1f + b[0]=%.1f = c[0]=%.1f\n", a[0], b[0], c[0]);
        printf("  Sample: a[100]=%.1f + b[100]=%.1f = c[100]=%.1f\n", a[100], b[100], c[100]);
        printf("  Sample: a[1023]=%.1f + b[1023]=%.1f = c[1023]=%.1f\n", 
               a[1023], b[1023], c[1023]);
        printf("\n✓ GPU computation VERIFIED - kernel actually computes!\n");
    } else {
        printf("\n✗ Computation failed - %d errors detected\n", errors);
    }
    
    cuMemFree(d_a);
    cuMemFree(d_b);
    cuMemFree(d_c);
    cuCtxDestroy(context);
    
    return errors > 0 ? 1 : 0;
}
