# zcc: ZASM JSONL IR → C (native) backend

[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL%203.0--or--later-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)

**zcc** is a cross-compiler that translates **ZASM JSONL IR** (emitted by `zas`) into a single, portable C translation unit. The generated C implements the ABI entrypoint (`lembeh_handle`) and can be compiled into a native binary with Clang/GCC. The focus is **determinism**, **auditability**, and **bounds-checked linear memory** — ideal for sandboxed, stream-first programs.

## Features

- **Deterministic output**: identical JSONL IR input produces byte-for-byte identical C (no timestamps or host-dependent formatting).
- **Bounds-checked memory**: generated loads/stores validate addresses against the configured linear memory size.
- **Explicit host surface**: host calls are routed through ABI callbacks (no ambient OS access).
- **Fast native builds**: emit plain C11 suitable for Clang/GCC optimization.
- **Cloaks (host runtimes)**: swap in different host implementations (e.g. stdio cloak) without changing program code.
- **Z80-flavored authoring model**: HL/DE/A/BC/IX registers map cleanly onto efficient C locals.
- **JSONL contract**: consumes the versioned ZASM IR stream (required: `"ir":"zasm-v1.0"`).

## Quick Start

### Prerequisites
- C compiler with C11 support (Clang or GCC)
- `zas` (ZASM assembler) to produce JSONL IR

### Installation
```bash
git clone git@github.com:frogfishio/zcc.git
cd zcc
make
make install  # Optional: Install to /usr/local (may require sudo depending on your setup)
```

This builds the platform binary in `./bin/<platform>/zcc` and provides a
`./bin/zcc` shim that selects the right platform directory.

### Basic Usage
```bash
# 1) Assemble ZASM text to JSONL IR
cat program.zasm | zas > program.jsonl

# 2) Compile JSONL IR to a single C translation unit
zcc < program.jsonl > program.c

# 3) Compile + link with a cloak (host runtime)
clang -Iinclude program.c cloak/stdio_cloak.c -o program

# 4) Run the native binary
./program
```

Full pipeline in one command:
```bash
cat program.zasm | zas | zcc --heap-slack=4096 > program.c
clang -Iinclude program.c cloak/stdio_cloak.c -o program
```

Options:
- `--heap-slack=N`: Reserve `N` bytes of extra heap space above the static data region (default: implementation-defined).
- `--output=FILE`: Write generated C to `FILE` instead of stdout.
- `--version`: Print version and exit.

## Building from Source

zcc uses a simple Makefile:
```bash
make  # Builds zcc
make test  # Runs basic tests
make clean  # Cleans build artifacts
make install  # Installs zcc and headers
```

Requires:
- Clang or GCC (C11 support)
- Make

## Architecture

### Pipeline
```
ZASM text → zas → JSONL IR → zcc → C → clang/gcc (+ cloak) → native binary
```

### Key Components
- **Input**: JSONL records from `zas` (labels, instructions, directives).
- **Output**: a single C translation unit implementing the program and ABI glue.
- **Runtime header**: `include/zprog_rt.h` defines the ABI surface and shared types.
- **Cloaks**: host-specific implementations (e.g. `cloak/stdio_cloak.c` for stdio I/O, `cloak/cloak_cuda.c` for the CUDA/ZCTL/1 control plane).

### Memory Model
- Linear `uint8_t mem[ZPROG_MEM_CAP]` buffer (compile-time constant, cloak/runtime controlled).
- Static data placed deterministically with alignment (matches the IR/lowering contract).
- All memory accesses are bounds-checked in generated C (hard error/trap on violation).

### ABI
The ABI provides host callbacks for streaming I/O, allocation, logging, handle finalization, and the `_ctl` control plane. Programs interact via `lembeh_handle`, passing request/response handles plus the callback table declared in `include/zprog_rt.h` and described by `normative/CLOAK_INTEGRATOR_GUIDE.md`.

## Examples

See the `examples/` directory for small end-to-end programs and golden tests. The recommended workflow is to assemble `.zasm` to JSONL with `zas`, then compile to C with `zcc`, then link with a cloak.

The sample [`examples/ctl_probe.jsonl`](examples/ctl_probe.jsonl) exercises `_ctl` by issuing a `CAPS_LIST` request and printing a confirmation message. Run it end-to-end with:

```bash
./bin/zcc --output build/ctl_probe.c < examples/ctl_probe.jsonl
cc -Iinclude build/ctl_probe.c cloak/stdio_cloak.c -o build/ctl_probe
./build/ctl_probe
```

### CUDA cloak (preview)

`cloak/cloak_cuda.c` wires the standard Lembeh entrypoint to the normative ZCTL/1 kernel backplane. It currently exposes capability and kernel listings plus a stubbed `KERNEL_RUN` path that will forward to the CUDA driver once available. Build the object with `make cloak-cuda` (or compile manually with the same flags used for `cloak-stdio`).

On a CUDA-enabled host you can finish the GPU plumbing by rebuilding with `-DZCC_ENABLE_CUDA_RUNTIME` and extending `cuda_backend_init()` / `handle_kernel_run()` as described in [docs/CLOAK_CUDA.md](docs/CLOAK_CUDA.md).

## Testing

Run `make test` for basic verification. For integration tests:
1. Assemble a `.zasm` file with `zas`.
2. Compile the JSONL IR with `zcc`.
3. Link with a cloak and build a native binary.
4. Run and compare stdout/stderr (and exit code if relevant) against expected outputs.

Fuzzing and unit tests can be extended using the provided fixtures in `CAPABILITIES.md`.

## Contributing

Contributions are welcome! Please:
- Fork the repo and create a feature branch.
- Add tests for new features.
- Ensure code passes `make test`.
- Submit a pull request.

See [CAPABILITIES.md](CAPABILITIES.md) for development details and the full spec.

## License

This project is licensed under the GPL-3.0-or-later. See [LICENSE](LICENSE) for details.

## Related Projects
- `zas` — ZASM assembler (text → JSONL IR)
- `zld` — JSONL IR linker/lowerer (JSONL IR → WAT/WASM)
- `zrun` — local harness/runner for golden tests

For questions, open an issue or contact the maintainers.
