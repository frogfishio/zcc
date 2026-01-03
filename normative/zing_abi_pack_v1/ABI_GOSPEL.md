# Zing / Lembeh ABI Gospel (Normative) — v0

This document is **normative**. Anything described as **MUST / MUST NOT / SHOULD** is a contract between:

- **Zing-compiled WASM modules** (guest)
- **Cloaks** (host runtimes: Lembeh, zcc cloak, Tauri cloak, etc.)
- **Tooling** (Specimen, packer, fuzzers)

Goal: a **minimal** ABI surface that never “explodes” into `_file`, `_net`, `_whatever`.  
All extensibility flows through **one** control-plane call: `_ctl` (ZCL1).

---

## 0. Terms

- **Guest**: the WASM module produced by the Zing compiler.
- **Host / Cloak**: the runtime embedding the guest and providing imports.
- **Handle**: an `i32` identifying a host-backed resource endpoint (stream-like).
- **Capability**: a named resource or service exposed via `_ctl` discovery/opening.
- **Determinism**: for identical inputs + schedule + capability set, the guest’s observable outputs are identical.

---

## 1. The ABI imports (the only ones)

The host MUST provide these imports under a stable module name (e.g. `"lembeh"`).  
Signatures are **exact**.

### 1.1 Streaming IO

```zing
extern req_read(i32, i32, i32) → i32.     ;; (handle, ptr, cap) -> nread | -1
extern res_write(i32, i32, i32) → i32.    ;; (handle, ptr, len) -> nwritten | -1
extern res_end(i32) → unit.               ;; (handle) -> ()
extern log(i32, i32, i32, i32) → unit.    ;; (topic_ptr, topic_len, msg_ptr, msg_len) -> ()
```

**Semantics**

- `req_read(h, ptr, cap)` copies up to `cap` bytes into guest memory at `ptr`.
  - Returns `n` where `0 <= n <= cap`.
  - Returns `0` means **EOF**.
  - Returns `-1` means **failure** (recoverable; guest may convert to `Fail`).

- `res_write(h, ptr, len)` reads `len` bytes from guest memory at `ptr` and writes to handle `h`.
  - Returns `n` where `0 <= n <= len` (hosts SHOULD write all or return `-1`).
  - Returns `-1` means **failure** (recoverable; e.g. handle closed / denied).

- `res_end(h)` marks the handle `h` as **ended** (no more writes accepted).
  - Calling `res_end` does **not** terminate execution.
  - After `res_end(h)`, subsequent `res_write(h, …)` MUST return `-1`.
  - Repeated `res_end(h)` MUST be idempotent.

- `log(topic_ptr, topic_len, msg_ptr, msg_len)` emits best-effort telemetry.
  - Log delivery is NOT guaranteed in production.
  - In tests (Specimen), log events MUST be captured deterministically.

### 1.2 Memory allocation (required)

```zing
extern alloc(i32) → i32.                  ;; size -> ptr | -1
extern free(i32) → unit.                  ;; ptr -> ()
```

**Semantics**

- `alloc(size)` returns a pointer to a contiguous region of guest linear memory, or `-1` on failure.
- `free(ptr)` releases a previously allocated region.
- The guest MUST NOT call `free` on pointers it did not allocate.
- The host MAY implement `free` as a no-op (arena), but MUST preserve determinism.

### 1.3 Control plane (required)

The host MUST provide exactly one control-plane import:

```zing
extern ctl(i32, i32, i32, i32) → i32.     ;; (req_ptr, req_len, resp_ptr, resp_cap) -> nresp | -1
```

**Semantics**

- Writes a response frame to `resp_ptr`, up to `resp_cap` bytes.
- Returns the number of bytes written (`>= 0`) or `-1` for host-fatal.
- `_ctl` MUST NOT block forever. Blocking operations MUST be bounded by a request timeout.

---

## 2. Handles and the baseline contract

### 2.1 Reserved handles

The following handle numbers are **conventions** that MUST be honored unless explicitly overridden by the host:

- `0` = stdin (`_in`)
- `1` = stdout (`_out`)
- `2` = log/telemetry sink (`_log`) — *note:* log also has a direct `log(...)` import

### 2.2 Handle meaning

A handle represents a **stream endpoint**. A handle MAY be:

- a pipe endpoint
- a file stream
- a network stream
- a decompressor/compressor stream
- a crypto hasher stream
- a “virtual resource” provided by the cloak

**Law (uniformity):** once opened, capabilities are used primarily via `req_read/res_write/res_end` on handles.

### 2.3 Lifetime

- Handles are owned by the host.
- The guest can:
  - read from a readable handle via `req_read`
  - write to a writable handle via `res_write`
  - end a handle via `res_end` (if endable)
- Handle closing semantics are capability-specific (but must obey `res_end` rules).

---

## 3. Termination model (no magic)

- **Execution terminates when `main` returns.**
- Ending stdout (`res_end(1)`) only prevents further writes. It does not terminate execution.
- The host MAY choose to discard output written after `main` returns (because there is no “after main” in WASM).

---

## 4. Determinism laws

### 4.1 Core determinism

For identical:

- guest code (WASM)
- capability set and their deterministic behavior
- input bytes (for all readable handles)
- chunk schedule (read segmentation)
- Specimen replay transcript

…the observable output events MUST be identical:

- bytes written to handles
- log events (in Specimen)
- ctl responses (in Specimen)

### 4.2 No ambient nondeterminism

The host MUST NOT leak ambient nondeterminism into deterministic runs unless explicitly exposed as a capability.  
Examples that MUST NOT affect deterministic runs:

- system clock
- OS env vars
- filesystem outside the presented view
- DNS / network ordering
- thread scheduling

If the host exposes a nondeterministic capability (e.g. live network), it MUST do so behind `_ctl`, and tests MUST record/replay it.

---

## 5. Timeout semantics (mandatory clarity)

Timeout is controlled by the **ZCL1 request frame** (see §6).

Rules:

1. Any operation that may block MUST respect `timeout_ms`.
2. `timeout_ms = 0` means **nonblocking**:
   - succeed immediately, or
   - return a timeout failure (`#t_ctl_timeout`) immediately.
3. A timeout failure is **recoverable** and MUST be returned as a ZCL1 failure envelope.
4. `_ctl` MUST NOT block beyond the timeout.

---

## 6. ZCL1 (Zing Control Link) — exact wire schema

All multi-byte integers are **little-endian**.

### 6.1 Request frame (bytes at `req_ptr`)

```
u8[4] magic      = "ZCL1"   (0x5A 0x43 0x4C 0x31)
u16   v          = 1
u16   op
u32   rid        ; request id (guest-chosen)
u32   timeout_ms ; 0 = nonblocking
u32   flags      ; 0 for now
u32   payload_len
u8[payload_len] payload
```

**Law:** `payload_len` MUST equal the remaining bytes in the frame.

### 6.2 Response frame (bytes written at `resp_ptr`)

```
u8[4] magic      = "ZCL1"
u16   v          = 1
u16   op         ; echoed
u32   rid        ; echoed
u32   flags      ; 0 for now
u32   payload_len
u8[payload_len] payload
```

### 6.3 Universal response payload header (inside payload)

Every response payload begins with:

```
u8  ok    ; 1 = success, 0 = fail
u8  rsv8  ; 0
u16 rsv16 ; 0
```

If `ok == 0`, the payload continues with the failure envelope:

```
sym trace
str msg
bytes cause
```

If `ok == 1`, op-specific payload follows immediately.

### 6.4 Primitive encodings

**str**
```
u32 len
u8[len] bytes    ; UTF-8 (or bytes-as-text; caller’s decision)
```

**sym** (trace codes: greppable identifiers)
```
u32 len
u8[len] bytes    ; ASCII [a-z0-9_], e.g. "t_ctl_timeout"
```

**bytes**
```
u32 len
u8[len] bytes
```

---

## 7. Required `_ctl` operations (v0)

### 7.1 `CAPS_LIST` (op = 1)

Request payload: empty.

Success payload:

```
u32 n
repeat n:
  str kind
  str name
  u32 cap_flags
  bytes meta
```

**cap_flags bits (v0):**
- bit0: `can_open` (supports `CAPS_OPEN`)
- bit1: `pure` (deterministic given inputs)
- bit2: `may_block` (requires timeout discipline)
- bit3: `produces_handles`

**Ordering law:** sorted lexicographically by `(kind, name)`.

**Minimum contract:** returning `n = 0` is valid and MUST succeed.

---

### 7.2 `CAPS_DESCRIBE` (op = 2) — strongly recommended

Request payload:
```
str kind
str name
```

Success payload:
```
u32 cap_flags
bytes schema   ; UTF-8 JSON blob (machine-readable)
```

Schema is intentionally flexible but MUST be deterministic and stable-key-ordered if JSON.

---

### 7.3 `CAPS_OPEN` (op = 3)

Request payload:
```
str kind
str name
u32 mode
bytes params
```

Success payload:
```
i32 handle
u32 hflags
bytes meta
```

**hflags bits (v0):**
- bit0: readable
- bit1: writable
- bit2: endable
- bit3: seekable (future)
- bit4: ctl_backed (debugging / provenance)

---

## 8. Capability kinds v0 (recommended baseline)

This section defines exact `params` payloads for initial “industrial” caps.
Cloaks MAY omit any cap, but MUST report what exists via `CAPS_LIST`.

### 8.1 `file/view` (kind="file", name="view")

**Mode bits** (`u32 mode`):
- bit0: read
- bit1: write
- bit2: create
- bit3: truncate

`params` begins with:

```
u8 variant
```

Variant 1: open by id
```
u8 variant = 1
bytes file_id
```

Variant 2: open by path (optional)
```
u8 variant = 2
str path
```

**Law:** if `variant` is unknown, return Fail `#t_ctl_bad_params`.

---

### 8.2 `net/tcp` (kind="net", name="tcp")

Mode values (`u32 mode`):
- `1` = connect

Params for connect:

```
u8  variant = 1
str host
u16 port
u32 connect_flags
```

connect_flags bits:
- bit0: allow_dns (if 0, host must be literal IP)
- bit1: prefer_ipv6
- bit2: nodelay

**Timeout:** bounded by `timeout_ms`.

---

### 8.3 `crypto` (recommended: op-based primitives)

Crypto can be done without handle streams in v0.

- `CRYPTO_HASH` (op = 50):
  - payload: `str alg, bytes data`
  - returns: `bytes digest`

- `CRYPTO_HMAC` (op = 51):
  - payload: `str alg, bytes key, bytes data`
  - returns: `bytes mac`

- `CRYPTO_RANDOM` (op = 52) **deterministic**:
  - payload: `bytes seed, u32 n`
  - returns: `bytes out`

**Law:** `CRYPTO_RANDOM` MUST be deterministic for a given seed.

---

## 9. Trace codes (stable + greppable)

The following trace codes MUST exist and remain stable:

- `#t_ctl_bad_frame`
- `#t_ctl_bad_version`
- `#t_ctl_unknown_op`
- `#t_ctl_timeout`
- `#t_ctl_overflow`
- `#t_ctl_bad_params`
- `#t_cap_missing`
- `#t_cap_denied`

---

## 10. Specimen requirements (test rig integration)

Specimen MUST be able to **record and replay** `_ctl` deterministically.

### 10.1 Transcript record kinds (required)

Record raw ZCL1 frames:

```json
{"k":"ctl_req","i":0,"b64":"..."}
{"k":"ctl_res","i":0,"b64":"..."}
```

Generalize IO to arbitrary handles:

```json
{"k":"read","i":0,"h":0,"ret":5,"b64":"SGVsbG8="}
{"k":"write","i":0,"h":1,"ret":6,"b64":"SGVsbG8K"}
{"k":"end","i":0,"h":1}
```

**Replay law:** replay MUST return identical `ctl_res` for each `ctl_req`, and identical read/write/end sequences, or fail at the first divergence.

### 10.2 Chunk schedule fuzzing

Specimen MUST support deterministic chunk schedules for stdin (`h=0`) at minimum:
- all-at-once
- one-byte
- powers-of-two
- crlf-adversary
- seeded-random

---

## 11. Identifier reservations (clarification)

Zing reserves certain identifiers (e.g. `__caps`, `stdin`, `stdout`, `log`) at **binding positions**.  
This ABI does **not** require banning underscore-prefixed struct fields.

Recommendation:
- Treat names beginning with `_` as “reserved-by-convention” in public APIs.
- Internal padding fields like `_pad` in a struct are acceptable, but SHOULD NOT be exported.

---

## 12. Conformance tests (must exist)

A cloak is conformant if it passes all:

1. **Echo determinism**: stdin bytes == stdout bytes across all chunk schedules.
2. **res_end semantics**:
   - after `res_end(1)`, `res_write(1, …)` returns `-1`.
   - repeated `res_end(1)` is safe.
3. **CAPS_LIST empty contract**:
   - returns `Ok` with `n=0` if no caps.
4. **Timeout law**:
   - `_ctl` call with `timeout_ms=0` never blocks.
5. **Specimen replay**:
   - a recorded specimen replays bit-for-bit.

---

## 13. Rationale (why this shape)

- `_in/_out/_log` give you the universal pipeline model.
- `alloc/free` is unavoidable (explicit memory, no GC).
- `res_end` is about **protocol finalization**, not scheduling.
- `_ctl` prevents ABI explosion:
  - files, net, crypto, compression, image transforms, DB views… all become *capabilities*.
- Specimen makes the whole system **debuggable and replayable** without exceptions.
