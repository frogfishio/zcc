# zcc: JSONL IR → C Cross-Compiler (ZASM toolchain backend)

[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL%203.0-or--later-blue.svg)](https://www.gnu.org/licenses/gpl-3.0-standalone.html)

**zcc** is a cross-compiler that translates **ZASM JSONL IR** (emitted by `zas`) into a single, portable C translation unit. The generated C implements the ABI entrypoint (`lembeh_handle`) and can be compiled into a native binary with Clang/GCC. The focus is **determinism**, **auditability**, and **bounds-checked linear memory** — ideal for sandboxed, stream-first programs.

## Features

- **Deterministic output**: identical JSONL IR input produces byte-for-byte identical C (no timestamps or host-dependent formatting).
- **Bounds-checked memory**: generated loads/stores validate addresses against the configured linear memory size.
- **Explicit host surface**: host calls are routed through ABI callbacks (no ambient OS access).
- **Fast native builds**: emit plain C11 suitable for Clang/GCC optimization.
- **Cloaks (host runtimes)**: swap in different host implementations (e.g. stdio cloak) without changing program code.
- **Z80-flavored authoring model**: HL/DE/A/BC/IX registers map cleanly onto efficient C locals.
- **JSONL contract**: consumes the versioned ZASM IR stream (recommended: `ir: zasm-v1.0`).

## Quick Start

### Prerequisites
- C compiler with C11 support (Clang or GCC)
- `zas` (ZASM assembler) to produce JSONL IR

### Installation
```bash
git clone git@github.com:frogfishio/zcc.git
cd zcc
make
sudo make install  # Optional: Install to /usr/local/bin
```

This builds the `zcc` binary in `./bin/`.

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
- **Cloaks**: host-specific implementations (e.g. `cloak/stdio_cloak.c` for stdio I/O).

### Memory Model
- Linear `uint8_t mem[ZPROG_MEM_CAP]` buffer (compile-time constant, cloak/runtime controlled).
- Static data placed deterministically with alignment (matches the IR/lowering contract).
- All memory accesses are bounds-checked in generated C (hard error/trap on violation).

### ABI
The ABI provides host callbacks for I/O, allocation, and logging. Programs interact via `lembeh_handle`, passing request/response handles.

## Examples

See the `examples/` directory for small end-to-end programs and golden tests. The recommended workflow is to assemble `.zasm` to JSONL with `zas`, then compile to C with `zcc`, then link with a cloak.

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

This project is licensed under the GPL-3.0-or-later. See [LICENSE](LICENSE) for details (add if missing).

## Related Projects
- `zas` — ZASM assembler (text → JSONL IR)
- `zld` — JSONL IR linker/lowerer (JSONL IR → WAT/WASM)
- `zrun` — local harness/runner for golden tests

For questions, open an issue or contact the maintainers.