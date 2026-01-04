# Cloak Integrator Guide (Normative) — v1.0

This guide is the single, unambiguous explanation of how to integrate with a cloak.
It covers both sides:
- **Guest-side producer** (code that runs inside the cloak)
- **Host-side provider** (outer app embedding the cloak and providing services)

All **MUST / MUST NOT / SHOULD** statements are normative.

---

## 0. One Mental Model (No Ambiguity)

```
[ Guest module (Zing/ZASM/WASM) ]  <->  [ Cloak Runtime ]  <->  [ Outer App / Host Services ]
```

- The cloak is the only boundary. Guests never talk to the outer app directly.
- All host services are exposed via `_ctl` capability discovery and handles.
- There are **no extra imports** beyond the core ABI surface.

---

## 1. Canonical ABI Source of Truth

This guide is the canonical ABI v1.0 source of truth.
If any other document conflicts with it, this guide wins.

---

## 2. Core ABI Surface (Required)

The host MUST provide exactly these imports under a stable module (e.g., `"lembeh"`):

```
req_read(i32 handle, i32 dst_ptr, i32 dst_cap) -> i32
res_write(i32 handle, i32 src_ptr, i32 src_len) -> i32
res_end(i32 handle) -> ()
log(i32 topic_ptr, i32 topic_len, i32 msg_ptr, i32 msg_len) -> ()
_alloc(i32 size) -> i32
_free(i32 ptr) -> ()
_ctl(i32 req_ptr, i32 req_len, i32 resp_ptr, i32 resp_cap) -> i32
```

**No more, no less.** All new features MUST go through `_ctl`.

---

## 3. Guest Memory Model (WASM and non-WASM)

The ABI defines a **flat guest byte space**. For WASM guests this is the linear
memory. For non-WASM guests, the host MUST provide an equivalent contiguous
byte buffer and the same pointer semantics apply.

**Law:** All pointers are offsets into the guest byte space `[0 .. mem_cap)`.

`_alloc(size)` and `_free(ptr)` are required regardless of runtime:
- The host MUST provide them even if the guest is not WASM.
- `_alloc` MUST return offsets within the guest byte space.
- `_free` MUST NOT crash even if given an invalid pointer.

**Determinism:** For identical call sequences, `_alloc` results MUST be deterministic.

---

## 4. ZCL1 Control Plane (Required)

`_ctl` MUST implement **ZCL1** framing and Hopper binary payloads.
See Section 9 for a concrete CAPS_LIST example framing.

Minimum contract (even when the host has **zero capabilities**):
1. `_ctl` MUST parse ZCL1 frames.
2. `_ctl` MUST support `CAPS_LIST` (op=1).
3. If no capabilities exist, `CAPS_LIST` MUST return a valid response with `n=0`.
4. Unknown ops MUST return `#t_ctl_unknown_op` in a ZCL1 error envelope.

---

## 5. Guest Integrator Requirements

### 5.1 Entrypoints

A guest module MUST export the entrypoint expected by the embedding host. If using
Lembeh’s default nanoservice ABI:

```
lembeh_handle(req_handle: i32, res_handle: i32) -> ()
```

### 5.2 Reserved Handles

- 0 = stdin (`_in`)
- 1 = stdout (`_out`)
- 2 = log (`_log`)

Handles are **opaque**. Guests MUST NOT assume any host internals.

### 5.3 Minimal Guest Flow (No Capabilities)

1. Read from handle 0 with `req_read`.
2. Write to handle 1 with `res_write`.
3. Optionally log via `log`.

If `_ctl` returns an empty capability list, continue in isolated mode.

### 5.4 Guest Example (Zing-style)

```zing
fn main() {
    let buf = _alloc(1024)
    loop {
        let n = req_read(0, buf, 1024)
        if n <= 0 { break }
        res_write(1, buf, n)
    }
    res_end(1)
}
```

### 5.5 `_ctl` Usage (Guest)

- `_ctl` requests MUST use ZCL1 headers and Hopper payloads.
- `timeout_ms = 0` means **nonblocking**: return immediately or fail with `#t_ctl_timeout`.
- Guests MUST handle `#t_cap_missing` and continue without that capability.

---

## 6. Host Integrator Requirements

### 6.1 Determinism

For identical inputs + schedules + capabilities, outputs MUST be identical.
If you expose nondeterministic services (e.g., network/time), they MUST be:
- capability-gated via `_ctl`, and
- record/replayable (Specimen semantics in the gospel).

### 6.2 Handles

- Newly created handles returned by `_ctl` MUST NOT be 0–2.
- Handles MUST be stable within a run.

### 6.3 Error Handling

- ZCL1 errors MUST use the standard error envelope.
- Malformed ZCL1 frames that cannot be parsed MUST return `-1`.
- Response too large for `resp_cap` MUST return `-1` (no partial writes).

### 6.4 No Capabilities Is Valid

If the host provides no services beyond `_in/_out/_log`, it MUST still:
- Implement `_ctl`.
- Support `CAPS_LIST` with an empty response list.

---

## 7. Capability Packs (Optional)

Capability packs are optional and host-defined.
Each pack defines binary Hopper layouts for params and records.

Hosts MAY implement **none** of these and still be compliant.
Guests MUST NOT assume any are present.

---

## 8. ZASM Modules Fronted by Cloak

ZASM (assembly) modules that run as services are treated exactly like any other guest:
- The cloak is the only boundary.
- The outer app MUST NOT bypass `_ctl` or expose new imports.
- If a service needs host data, it must request a capability (or accept no data).

---

## 9. Concrete Examples

### 9.1 CAPS_LIST Request/Response (Binary)

**Request header only, payload_len = 0:**

```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
01 00          ; op = 1 (CAPS_LIST)
01 00 00 00    ; rid = 1
00 00 00 00    ; timeout_ms = 0
00 00 00 00    ; flags = 0
00 00 00 00    ; payload_len = 0
```

**Response (success, n = 0):**

```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
01 00          ; op = 1
01 00 00 00    ; rid = 1
00 00 00 00    ; flags = 0
08 00 00 00    ; payload_len = 8
01 00 00 00    ; ok=1, rsv
00 00 00 00    ; n = 0
```

### 9.2 Host Skeleton (Minimal, C-like)

```c
// Pseudocode skeleton for a minimal cloak host
struct host_ctx { /* io handles */ };
struct heap_ctx { int32_t head; };

int32_t _alloc(void* ctx, uint8_t* mem, size_t mem_cap, int32_t size) {
  // bounds-checked arena allocator
}

void _free(void* ctx, uint8_t* mem, size_t mem_cap, int32_t ptr) {
  // no-op allowed, MUST NOT crash
}

int32_t _ctl(void* ctx, uint8_t* mem, size_t mem_cap,
             int32_t req_ptr, int32_t req_len,
             int32_t resp_ptr, int32_t resp_cap) {
  // parse ZCL1, support CAPS_LIST, return n=0
}
```

### 9.3 Guest Flow (Capability Optional)

1. Call `_ctl` CAPS_LIST.
2. If list empty, continue in isolated mode.
3. If a capability is present, call CAPS_OPEN or the specific op.
4. Use returned handle via req_read/res_write/res_end.

---

## 10. Compliance Checklist

Guest MUST:
- Use only the core ABI imports.
- Treat all handles as opaque.
- Use ZCL1 framing for `_ctl`.
- Handle `CAPS_LIST` empty response.

Host MUST:
- Provide the exact ABI import surface.
- Implement ZCL1 framing and error envelopes.
- Respect `timeout_ms` and never block forever.
- Return deterministic results for identical inputs.

---

## 11. Versioning

This guide is locked to ABI v1.0.0.
Any future changes MUST be introduced as a new versioned guide.

---

# Appendix A — ZCL1 Wire Framing (Standalone)

ZCL1 is the binary wire format for `_ctl` requests and responses. All integers are
little-endian.

## A.1 Request Frame (fixed header + payload)

```
Offset  Size  Field         Description
──────  ────  ────────────  ───────────────────────────────
0       4     magic         "ZCL1" (0x5A 0x43 0x4C 0x31)
4       2     v             Protocol version (1)
6       2     op            Operation code
8       4     rid           Request ID (caller-chosen)
12      4     timeout_ms    Timeout in ms (0 = nonblocking)
16      4     flags         Reserved (0)
20      4     payload_len   Length of payload in bytes
24      var   payload       Operation-specific payload
```

**Law:** `payload_len` MUST equal the remaining bytes in the frame.  
**Law:** `flags` MUST be 0 in v1.  
**Fatal:** If the frame is too short to read `op` and `rid`, `_ctl` MUST return `-1`.

## A.2 Response Frame (fixed header + payload)

```
Offset  Size  Field         Description
──────  ────  ────────────  ───────────────────────────────
0       4     magic         "ZCL1" (0x5A 0x43 0x4C 0x31)
4       2     v             Protocol version (1)
6       2     op            Echoed from request
8       4     rid           Echoed from request
12      4     flags         Reserved (0)
16      4     payload_len   Length of payload in bytes
20      var   payload       Response payload
```

**Law:** `op` and `rid` MUST echo the request.

## A.3 Response Payload Prefix (all ops)

Every response payload begins with a fixed status header:

```
Offset  Size  Field     Description
──────  ────  ────────  ───────────────────────────────
0       1     ok        1 = success, 0 = fail
1       1     rsv8      Reserved (0)
2       2     rsv16     Reserved (0)
```

If `ok == 0`, the remainder is the error envelope:

```
trace: HSTR (ASCII [a-z0-9_])
msg:   HSTR (UTF-8)
cause: HBYTES (opaque, may be empty)
```

If `ok == 1`, the remainder is the op-specific success payload.

---

# Appendix B — Hopper Binary Types (Standalone)

All `_ctl` payloads use Hopper binary layouts. There are no native ints or pointers
on the wire.

## B.1 Scalar Types

| Name | Size | Meaning | Encoding |
|------|------|---------|----------|
| H1 | 1 | Hopper byte | Unsigned byte |
| H2 | 2 | Hopper word | Little-endian unsigned |
| H4 | 4 | Hopper dword | Little-endian unsigned |
| H8 | 8 | Hopper qword | Little-endian unsigned |

## B.2 Variable Types

| Name | Layout | Meaning |
|------|--------|---------|
| HSTR | `H4 len` + `len bytes` | UTF-8 string (no null) |
| HBYTES | `H4 len` + `len bytes` | Raw bytes |

**Law:** `len` MUST NOT exceed remaining payload bytes. Zero-length is valid.

---

# Appendix C — Minimal `_ctl` Ops (Standalone)

Only these ops are required for a compliant host with zero capabilities.

## C.1 CAPS_LIST (op = 1)

**Request payload:** empty

**Success payload:**

```
H4 n
repeat n:
  HSTR kind
  HSTR name
  H4 cap_flags
  HBYTES meta
```

**Ordering law:** sorted lexicographically by `(kind, name)`.  
**Empty contract:** `n=0` is valid and MUST succeed.

## C.2 CAPS_DESCRIBE (op = 2) — optional but recommended

**Request payload:**

```
HSTR kind
HSTR name
```

**Success payload:**

```
H4 cap_flags
HBYTES schema   ; opaque bytes
```

## C.3 CAPS_OPEN (op = 3)

**Request payload:**

```
HSTR kind
HSTR name
H4 mode
HBYTES params
```

**Success payload:**

```
H4 handle
H4 hflags
HBYTES meta
```

**hflags bits:**
- bit0: READABLE
- bit1: WRITABLE
- bit2: ENDABLE

**Timeouts:** bound by the ZCL1 request header `timeout_ms`.

---

# Appendix D — Minimal Error Codes (Standalone)

These trace symbols MUST exist for interoperability:

- `t_ctl_bad_frame`
- `t_ctl_bad_version`
- `t_ctl_unknown_op`
- `t_ctl_timeout`
- `t_ctl_overflow`
- `t_ctl_bad_params`
- `t_cap_missing`
- `t_cap_denied`

---

# Appendix E — Worked Example: CAPS_OPEN Byte Layout

This example opens a TCP capability using `CAPS_OPEN` to show exact byte layout.
It is illustrative and uses host `127.0.0.1:7444`.

### E.1 CAPS_OPEN Request Payload (Hopper)

Fields:
- kind = \"net\"
- name = \"tcp\"
- mode = 1 (connect)
- params = variant(1) + host + port + flags

Params layout:

```
H1 variant = 1
HSTR host = \"127.0.0.1\"
H2 port = 7444
H4 connect_flags = 0
```

### E.2 CAPS_OPEN Request Frame (hex, annotated)

```
5A 43 4C 31    ; magic \"ZCL1\"
01 00          ; v = 1
03 00          ; op = 3 (CAPS_OPEN)
01 00 00 00    ; rid = 1
00 00 00 00    ; timeout_ms = 0 (nonblocking)
00 00 00 00    ; flags = 0
1B 00 00 00    ; payload_len = 27

03 00 00 00    ; kind_len = 3
6E 65 74       ; \"net\"
03 00 00 00    ; name_len = 3
74 63 70       ; \"tcp\"
01 00 00 00    ; mode = 1
0B 00 00 00    ; params_len = 11
01             ; variant = 1
09 00 00 00    ; host_len = 9
31 32 37 2E 30 2E 30 2E 31 ; \"127.0.0.1\"
14 1D          ; port = 7444 (0x1D14 LE)
00 00 00 00    ; connect_flags = 0
```

### E.3 CAPS_OPEN Success Payload (example)

```
ok = 1
H4 handle = 3
H4 hflags = 0x00000007   ; readable | writable | endable
HBYTES meta = empty
```

This is returned inside a ZCL1 response frame with the ok-prefix header.

---

# Appendix F — Host Implementation Checklist (Minimal)

Use this checklist to validate a minimal host implementation:

1. Export core imports: `req_read`, `res_write`, `res_end`, `log`, `_alloc`, `_free`, `_ctl`.
2. Provide a guest byte space `[0 .. mem_cap)` and enforce bounds checks.
3. Implement `_alloc`/`_free` deterministically (arena allocator is OK).
4. Parse ZCL1 headers and verify `magic`, `v`, and `payload_len`.
5. Implement `CAPS_LIST` and return `n=0` when no capabilities exist.
6. For unknown ops, return ZCL1 error envelope `#t_ctl_unknown_op`.
7. If response does not fit `resp_cap`, return `-1` and write nothing.
8. For any blocking operation, respect `timeout_ms` (nonblocking if 0).

---

# Appendix G — CAPS_LIST Example (Non-Empty)

This shows a CAPS_LIST response with one capability (`kind=\"file\"`, `name=\"default\"`).

### G.1 Success Payload (Hopper)

```
H4 n = 1
HSTR kind = \"file\"
HSTR name = \"default\"
H4 cap_flags = 0x00000009   ; CAN_OPEN + PRODUCES_HANDLES
HBYTES meta = empty
```

### G.2 Response Frame (hex, annotated)

```
5A 43 4C 31    ; magic \"ZCL1\"
01 00          ; v = 1
01 00          ; op = 1 (CAPS_LIST)
01 00 00 00    ; rid = 1
00 00 00 00    ; flags = 0
1D 00 00 00    ; payload_len = 29

01 00 00 00    ; ok=1, rsv
01 00 00 00    ; n = 1
04 00 00 00    ; kind_len = 4
66 69 6C 65    ; \"file\"
07 00 00 00    ; name_len = 7
64 65 66 61 75 6C 74 ; \"default\"
09 00 00 00    ; cap_flags
00 00 00 00    ; meta_len = 0
```

---

# Appendix H — Minimal Guest C Snippet (Parse CAPS_LIST)

```c
// Assumes resp points to a full ZCL1 response frame
uint32_t payload_len = read_u32(resp + 16);
uint8_t* payload = resp + 20;

// ok prefix
if (payload_len < 4 || payload[0] != 1) return -1;

uint32_t n = read_u32(payload + 4);
size_t off = 8;
for (uint32_t i = 0; i < n; i++) {
  uint32_t kind_len = read_u32(payload + off); off += 4;
  const uint8_t* kind = payload + off; off += kind_len;
  uint32_t name_len = read_u32(payload + off); off += 4;
  const uint8_t* name = payload + off; off += name_len;
  uint32_t cap_flags = read_u32(payload + off); off += 4;
  uint32_t meta_len = read_u32(payload + off); off += 4;
  off += meta_len;
  // use kind/name/cap_flags
}
```

---

# Appendix I — Error Envelope Example (Unknown Op)

This shows a failure response for an unknown opcode using the ZCL1 error envelope.

### I.1 Response Frame (hex, annotated)

```

---

# Appendix J — Error Envelope Example (Timeout)

This shows a timeout failure for an operation that exceeded `timeout_ms`.

### J.1 Response Frame (hex, annotated)

```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
03 00          ; op = 3 (CAPS_OPEN, echoed)
02 00 00 00    ; rid = 2
00 00 00 00    ; flags = 0
2E 00 00 00    ; payload_len = 46

00             ; ok = 0
00             ; rsv8
00 00          ; rsv16
0D 00 00 00    ; trace_len = 13
74 5F 63 74 6C 5F 74 69 6D 65 6F 75 74
               ; "t_ctl_timeout"
12 00 00 00    ; msg_len = 18
6F 70 65 72 61 74 69 6F 6E 20 74 69 6D 65 64 20 6F 75 74
               ; "operation timed out"
00 00 00 00    ; cause_len = 0
```

---

# Appendix K — Error Envelope Example (Bad Frame)

This shows a malformed frame response. If the header cannot be parsed at all,
`_ctl` MUST return `-1` and write nothing. If the header is valid but the payload
is malformed, return a structured error.

### K.1 Response Frame (hex, annotated)

```

---

# Appendix L — Error Envelope Example (Capability Missing)

This shows a failure when a guest requests a capability that is not present.

### L.1 Response Frame (hex, annotated)

```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
02 00          ; op = 2 (CAPS_DESCRIBE, echoed)
04 00 00 00    ; rid = 4
00 00 00 00    ; flags = 0
33 00 00 00    ; payload_len = 51

00             ; ok = 0
00             ; rsv8
00 00          ; rsv16
0D 00 00 00    ; trace_len = 13
74 5F 63 61 70 5F 6D 69 73 73 69 6E 67
               ; "t_cap_missing"
17 00 00 00    ; msg_len = 23
63 61 70 61 62 69 6C 69 74 79 20 6E 6F 74 20 61 76 61 69 6C 61 62 6C 65
               ; "capability not available"
00 00 00 00    ; cause_len = 0
```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
01 00          ; op = 1 (CAPS_LIST, echoed)
03 00 00 00    ; rid = 3
00 00 00 00    ; flags = 0
2F 00 00 00    ; payload_len = 47

00             ; ok = 0
00             ; rsv8
00 00          ; rsv16
0F 00 00 00    ; trace_len = 15
74 5F 63 74 6C 5F 62 61 64 5F 66 72 61 6D 65
               ; "t_ctl_bad_frame"
0E 00 00 00    ; msg_len = 14
62 61 64 20 66 72 61 6D 65 20 66 6F 72 6D
               ; "bad frame form"
00 00 00 00    ; cause_len = 0
```
5A 43 4C 31    ; magic "ZCL1"
01 00          ; v = 1
FF 00          ; op = 255 (echoed)
01 00 00 00    ; rid = 1
00 00 00 00    ; flags = 0
33 00 00 00    ; payload_len = 51

00             ; ok = 0
00             ; rsv8
00 00          ; rsv16
10 00 00 00    ; trace_len = 16
74 5F 63 74 6C 5F 75 6E 6B 6E 6F 77 6E 5F 6F 70
               ; "t_ctl_unknown_op"
11 00 00 00    ; msg_len = 17
75 6E 6B 6E 6F 77 6E 20 6F 70 65 72 61 74 69 6F 6E
               ; "unknown operation"
00 00 00 00    ; cause_len = 0
```
