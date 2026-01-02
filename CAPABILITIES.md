# zcc: ZASM to C Cross-Compiler

**zcc** is a cross-compiler that translates ZASM (a Z80-inspired assembly language) into high-performance C code, targeting the Lembeh ABI for deterministic, sandboxed execution.

This document provides complete standalone documentation for resuming development on zcc without external dependencies.

## Overview

zcc takes JSONL IR (produced by `zas`) and emits C code that:
- Implements the Z80-inspired ISA in C
- Uses a linear memory model with bounds checking
- Integrates with host systems via the Lembeh ABI
- Compiles to native binaries when linked with a "cloak" runtime

### Key Principles

1. **Determinism**: Identical ZASM input always produces identical C output
2. **Safety**: All memory accesses are bounds-checked
3. **Auditability**: Host interactions are explicit and prefixed with `_`
4. **Performance**: Generated C is optimized for speed with minimal overhead
5. **Modularity**: Cloaks provide interchangeable host runtimes

## Architecture

### Pipeline
```
ZASM → zas → JSONL IR → zcc → C code + Cloak → Native binary
```

### Components
- **zcc**: Core compiler (main.c, emit_c.c)
- **Runtime Header**: `include/zprog_rt.h` - ABI definitions
- **Cloak**: Host runtime implementation (e.g., `cloak/stdio_cloak.c`)

### Memory Model
- Single linear `uint8_t mem[ZPROG_MEM_CAP]` buffer
- Heap starts at `ZPROG_HEAP_BASE` (configurable via `--heap-slack`)
- All addresses are 32-bit signed integers
- Bounds checking prevents OOB access

### Registers
Z80-inspired 16-bit registers:
- `HL`: General purpose (often pointer)
- `DE`: General purpose (often length)
- `A`: 8-bit accumulator
- `BC`: General purpose
- `IX`: General purpose

## Lembeh ABI

The Lembeh ABI defines the interface between compiled ZASM programs and host systems.

### Entry Point
```c
int lembeh_handle(int32_t req_handle,
                  int32_t res_handle,
                  zprog_in_fn in_fn,
                  zprog_out_fn out_fn,
                  zprog_log_fn log_fn,
                  void* host_ctx,
                  const struct zprog_sys* sys);
```

- **req_handle/res_handle**: Opaque handles for request/response (unused in stdio cloak)
- **in_fn/out_fn/log_fn**: Host I/O callbacks
- **host_ctx**: Host-specific context
- **sys**: System primitives (alloc/free)
- **Return**: 0 on success, nonzero on trap

### Host Callbacks

#### Input
```c
typedef int32_t (*zprog_in_fn)(void* ctx,
                               int32_t req_handle,
                               uint8_t* mem,
                               size_t mem_cap,
                               int32_t ptr,
                               int32_t cap);
```
Reads up to `cap` bytes into `mem[ptr..ptr+cap]`, returns bytes read or negative on error.

#### Output
```c
typedef int32_t (*zprog_out_fn)(void* ctx,
                                int32_t res_handle,
                                uint8_t* mem,
                                size_t mem_cap,
                                int32_t ptr,
                                int32_t len);
```
Writes `len` bytes from `mem[ptr..ptr+len]`, returns bytes written or negative on error.

#### Logging
```c
typedef void (*zprog_log_fn)(void* ctx,
                             uint8_t* mem,
                             size_t mem_cap,
                             int32_t topic_ptr,
                             int32_t topic_len,
                             int32_t msg_ptr,
                             int32_t msg_len);
```
Logs a message with topic and body from memory slices.

### System Primitives
```c
struct zprog_sys {
  void* ctx;
  int32_t (*alloc_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t size);
  void (*free_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t ptr);
};
```

- **alloc_fn**: Allocates `size` bytes from heap, returns pointer or negative
- **free_fn**: Frees memory at `ptr` (no-op in simple cloaks)

### Trap Codes
- `ZPROG_TRAP_OOB = 1`: Out-of-bounds memory access
- `ZPROG_TRAP_CALL_DEPTH = 2`: Call stack overflow
- `ZPROG_TRAP_HOST_MISSING = 3`: Required host function missing
- `ZPROG_TRAP_HOST_FAIL = 4`: Host function failed
- `ZPROG_TRAP_ALLOC = 5`: Allocation failure

## ZASM ISA Subset

zcc supports a subset of Z80-inspired instructions:

### Data Movement
- `LD dst, src`: Load register/immediate/memory
- `INC reg`: Increment register
- `DEC reg`: Decrement register

### Arithmetic
- `ADD HL, rhs`: HL += rhs
- `SUB HL, rhs`: HL -= rhs

### Control Flow
- `CP lhs, rhs`: Compare and set flags
- `JR cond, label`: Conditional jump
- `CALL label`: Call subroutine
- `RET`: Return from subroutine

### Host Calls
- `CALL _in`: Read input
- `CALL _out`: Write output
- `CALL _log`: Log message
- `CALL _alloc`: Allocate memory
- `CALL _free`: Free memory

### Directives
- `DB bytes...`: Define byte data
- `DW words...`: Define word data
- `EQU name, value`: Define constant
- `STR "string"`: Define string with auto-length
- `RESB size`: Reserve bytes

## Code Structure

### Source Files
- `src/main.c`: CLI entry point, JSONL parsing
- `src/emit_c.c`: C code generation
- `src/emit_c.h`: Internal headers
- `include/zprog_rt.h`: Public ABI header
- `cloak/stdio_cloak.c`: Example stdio-based runtime

### Key Data Structures
- `record_t`: JSONL record from zas
- `datavec_t`: Data segments
- `gsymtab_t`: Global symbols
- `labelvec_t`: Labels and PCs
- `namemap_t`: C identifier sanitization

### Compilation Phases
1. Parse JSONL records
2. Build data/globals from directives
3. Collect labels and instruction PCs
4. Emit C prologue (includes, defines, structs)
5. Emit data segments
6. Emit switch-based interpreter loop
7. Emit epilogue

## Building zcc

### Prerequisites
- C11 compiler (clang/gcc)
- make

### Build
```bash
make
```

### Install
```bash
make install
```

### Test
```bash
make test-zcc-cat  # Test with cat example
```

## Using zcc

### Basic Usage
```bash
cat program.zasm | zas | zcc --heap-slack=4096 > program.c
cc -Iinclude program.c cloak/stdio_cloak.c -o program
```

### Options
- `--heap-slack=N`: Set heap start offset (default 65536)
- `--version`: Show version

## Extending zcc

### Adding Instructions
1. Add case in `emit_instruction()` in `emit_c.c`
2. Handle operands and emit C statements
3. Update bounds checks for memory ops

### Adding Directives
1. Extend `build_data_and_globals()` in `emit_c.c`
2. Handle new directive types
3. Update symbol table

### Creating Cloaks
1. Implement host callbacks
2. Provide alloc/free if needed
3. Call `lembeh_handle()` with appropriate args

## Testing

### Unit Tests
- Compile examples with zcc
- Link with cloak
- Compare output to fixtures

### Integration Tests
- Full pipeline: ZASM → JSONL → C → Binary → Output
- Validate against WASM reference implementation

### Fuzzing
- Test with malformed JSONL
- Ensure no crashes or undefined behavior

## Debugging

### Common Issues
- **Infinite loops**: Check JR conditions and label targets
- **OOB traps**: Verify memory bounds in ZASM
- **Host failures**: Check cloak implementation

### Generated Code Inspection
- Review emitted C for correctness
- Check switch cases match instruction count
- Validate bounds checks

## Performance Considerations

- Generated C uses computed goto for speed (if supported)
- Memory is linear array for cache efficiency
- Bounds checks are minimal inline functions
- No dynamic allocation in hot path

## Future Directions

- Support more Z80 instructions
- Add structured control flow
- Optimize register allocation
- Support multiple memory spaces

## License

GPL-3.0-or-later for code, MIT for examples.