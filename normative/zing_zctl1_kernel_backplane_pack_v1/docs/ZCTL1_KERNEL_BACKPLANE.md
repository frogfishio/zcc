# ZCTL/1 — Kernel Backplane (Normative ABI Spec)

**Status:** Normative draft for implementation  
**Scope:** `_ctl` binary message format + required ops for capability listing and kernel execution.  
**Design goal:** **one** control-plane ABI (`_ctl`) that supports *local* (same process) and *remote* (over the wire) execution with **~95% shared structs**.

This document is deliberately strict: *no room for “creative reinterpretation”*.

---

## 0. Definitions

- **Host Zing**: normal Zing program with streams (`_in/_out/_log`) and `_ctl`.
- **Kernel Zing**: Zing compiled in **Kernel Mode** (restricted subset) into a GPU kernel artifact (PTX/cubin or shield-native).
- **Shield / cloak**: host runtime implementing ABI functions, including `_ctl`.
- **Hopper**: the Zing “typed bytes” memory region. In practice this is **WASM linear memory** (or a compatible byte arena) that `_ctl` reads/writes by offsets.

---

## 1. `_ctl` ABI (host function)

The shield MUST provide a single control-plane function:

```c
int32_t _ctl(
  int32_t ctl_handle,
  uint8_t* mem,
  size_t   mem_cap,
  int32_t  req_ptr,
  int32_t  req_len,
  int32_t  resp_ptr,
  int32_t  resp_cap,
  int32_t  timeout_ms
);
```

### 1.1 Handles

Recommended constants:
- `ZCAP_IN  = 1`
- `ZCAP_OUT = 2`
- `ZCAP_LOG = 3`
- `ZCAP_CTL = 4`

### 1.2 Memory contract

`req_ptr/req_len` and `resp_ptr/resp_cap` are **byte offsets** into `mem`.

**Law:** `_ctl` MUST NOT read or write outside `mem[0..mem_cap)` and MUST return `ZCTL_ERR` on any bounds violation.

### 1.3 Timeout contract

- `timeout_ms` is a *caller budget*. The shield MUST respect it.
- If the operation cannot complete within the budget:
  - return a valid response with status `ERR_TIMEOUT`, OR
  - return `ZCTL_ERR` if response cannot be written.

**Law:** `_ctl` MUST NOT block forever if a finite timeout is provided.

---

## 2. Encoding fundamentals

### 2.1 Endianness
All multi-byte integers are **little-endian**.

### 2.2 Packing
All structs are **packed**. No implicit padding.

### 2.3 Stable evolution
Backward-compatible extension ONLY via:
- new opcodes
- new TLV fields with explicit lengths

---

## 3. Common message headers

### 3.1 Request header (32 bytes)

```c
struct zctl_req_v1 {
  uint32_t magic;       // 'ZCTL' = 0x4C54435A
  uint16_t v;           // 1
  uint16_t op;          // opcode
  uint32_t flags;       // must be 0 in v1
  uint32_t req_id;      // caller chosen; echoed
  uint32_t payload_len; // bytes after this header
  uint32_t timeout_ms;  // semantic timeout for this op
  uint32_t crc32;       // optional; 0 means unused in v1
};
```

### 3.2 Response header (32 bytes)

```c
struct zctl_resp_v1 {
  uint32_t magic;       // 'ZCTL'
  uint16_t v;           // 1
  uint16_t op;          // echoed
  uint32_t flags;       // reserved
  uint32_t req_id;      // echoed
  uint32_t status;      // 0 ok, nonzero error
  uint32_t payload_len; // bytes after this header
  uint32_t crc32;       // optional; 0 unused in v1
};
```

**Law:** `payload_len` MUST equal `resp_len - 32`.

---

## 4. Status codes (v1)

| Code | Name            | Meaning |
|------|-----------------|---------|
| 0    | OK              | success |
| 1    | ERR_MALFORMED    | bad lengths/fields/bounds |
| 2    | ERR_UNSUPPORTED  | unknown op |
| 3    | ERR_DENIED       | capability not allowed |
| 4    | ERR_TIMEOUT      | timed out |
| 5    | ERR_NO_MEM       | shield-side memory failure |
| 6    | ERR_BACKEND      | backend (GPU/runtime) failure |
| 7    | ERR_BAD_ARGS     | validated args rejected |

---

## 5. Ops (required minimal set)

### 5.1 CAPS_LIST (op = 0x0001)

**Request payload:** empty

**Response payload:**

```c
struct zctl_caps_list_resp_v1 {
  uint32_t n;
  // followed by n entries:
  //   u32 cap_id
  //   u32 name_len
  //   u8[name_len] name
};
```

**Minimum contract / empty list**

**Law:** `_ctl` MUST support `CAPS_LIST`. A shield MAY return `n=0` (no extra caps). This is valid.

---

### 5.2 KERNEL_LIST (op = 0x0101)

**Request payload:**

```c
struct zctl_kernel_list_req_v1 { uint32_t filter; };
```

**Response payload:**

```c
struct zctl_kernel_list_resp_v1 {
  uint32_t n;
  // entries: kernel_id, name_len+name, sig_hash, flags
};
```

---

### 5.3 KERNEL_RUN (op = 0x0102)

**Request payload:**

```c
struct zctl_kernel_run_req_v1 {
  uint32_t kernel_id;
  uint32_t arg_count;
  uint32_t hopper_base; // 0 = base of wasm linear memory
  uint32_t reserved;    // 0
  // arg_count args follow
};
```

Args are fixed 16 bytes:

```c
struct zctl_arg_v1 { uint32_t kind,a,b,c; };
```

Kinds:
- `ARG_I32/U32`: `a=value`
- `ARG_BYTES`: `a=off, b=len`
- `ARG_TENSOR`: `a=desc_off, b=desc_len` (desc is `zctl_tensor_desc_v1`)
- `ARG_HOPPER_REC`: `a=off, b=len, c=layout_id`

**Response payload:**

```c
struct zctl_kernel_run_resp_v1 {
  uint32_t ok;
  uint32_t err_code;
  uint32_t err_msg_len;
  // err_msg bytes follow
};
```

**Law:** `KERNEL_RUN` MUST be deterministic by default.

---

## 6. Shared Tensor Descriptor (Hopper struct)

```c
struct zctl_tensor_desc_v1 {
  uint32_t dtype;
  uint32_t rank;
  uint32_t flags;
  uint32_t data_off;
  uint32_t data_len;
  uint32_t shape_off;
  uint32_t stride_off; // 0 for contiguous
  uint32_t reserved;   // 0
};
```

**Law:** the shield MUST bounds-check referenced offsets before launching.

---

## 7. Remote compatibility

A remote transport should carry the exact `req_header+payload` and return the exact `resp_header+payload`.

