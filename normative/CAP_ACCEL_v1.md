# Capability: cap.accel.v1 (Normative)

This document defines the accelerator capability for ABI v1.0.
It standardizes GPU and accelerator access without binding Zing to a vendor API.
All payloads are Hopper binary layouts (H1/H2/H4/H8, HSTR, HBYTES).

---

## 1. Capability identity

- kind: `accel`
- name: `default`
- version: `1`
- canonical id: `cap.accel.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("accel","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

Recommended schema keys (optional):
- `backends` (cuda, metal, vulkan, opencl)
- `max_queue`
- `max_buffer_bytes`
- `max_kernel_params`
- `max_shared_mem_bytes`
- `max_arg_count`
- `max_inline_arg_bytes`
- `max_module_bytes`
- `module_registry` (\"preload\" | \"config\" | \"extension\")

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: QUERY
- 2: BUFFER
- 3: SUBMIT
- 4: SYNC

All modes return a stream handle.

### 3.1 QUERY (mode = 1)

Params:

```
HSTR backend
```

Stream record (single record):

```
H4 n
repeat n:
  HSTR id
  HSTR name
  H8 memory_bytes
  H4 compute_units
  H4 flags
```

`flags` bits:
- bit0: supports_fp16
- bit1: supports_tensor
- bit2: supports_unified_mem

### 3.2 BUFFER (mode = 2)

Params:

```
HSTR backend
HSTR device_id
H8 bytes
H4 flags
```

`flags` bits:
- bit0: read_only
- bit1: write_only
- bit2: pinned_host

Response:
- Returns a stream handle representing a device buffer.
- `res_write` copies bytes into the buffer.
- `req_read` reads bytes back out of the buffer.

Buffers MUST be isolated per job unless explicitly shared by policy.

### 3.3 SUBMIT (mode = 3)

Params:

```
HSTR backend
HSTR device_id
HBYTES module_id
HBYTES kernel_id
H4 grid_x
H4 grid_y
H4 grid_z
H4 block_x
H4 block_y
H4 block_z
H4 shared_mem_bytes
H4 arg_count
repeat arg_count:
  ArgDesc
H4 budget_ms
```

ArgDesc layout:

```
H1 kind
H1 reserved
H2 flags
H4 size
... payload ...
```

`kind` values:
- 1 = inline bytes
- 2 = device buffer handle (H4 handle)

If `kind=1`, payload is `size` raw bytes.
If `kind=2`, payload is `H4 handle` (size MUST be 4).

Stream record (single record):

```
H1 status         ; 0 = ok, 1 = fail
if status == 1:
  HSTR trace
  HSTR msg
  HBYTES cause
```

**Limits (deterministic validation):**
- `arg_count` MUST be <= `max_arg_count` (if advertised).
- For `kind=1` args, `size` MUST be <= `max_inline_arg_bytes` (if advertised).
- `module_id` and `kernel_id` MUST be <= `max_kernel_params` total bytes (if advertised).

### 3.4 SYNC (mode = 4)

Params:

```
HSTR backend
HSTR device_id
HSTR queue_id     ; "default" if unused
```

Stream record (single record):

```
H1 ok    ; 1 on completion
```

---

## 4. CUDA Backend (Normative when backend="cuda")

If `backend="cuda"` is advertised, the following semantics are REQUIRED.
All numeric values are little-endian.

### 4.1 QUERY

`id` MUST be a stable CUDA device index string (e.g., "0", "1").
`compute_units` MUST be SM count.

### 4.2 BUFFER

Buffers are CUDA device allocations on the selected device.
If `pinned_host` is set, the host MAY allocate pinned host memory and expose it
through the same handle (implementation-defined, but MUST be deterministic).

### 4.3 SUBMIT

- `module_id` identifies a CUDA module or fatbin previously loaded by the host.
- `kernel_id` identifies a kernel symbol within that module.
- `grid_*` and `block_*` are the CUDA launch dimensions.
- `shared_mem_bytes` sets dynamic shared memory.

`ArgDesc` handling:
- `kind=inline` passes raw parameter bytes as a by-value kernel argument.
- `kind=handle` passes a device pointer bound to the buffer handle.

**Module registry rules (CUDA):**
- `module_id` is an opaque identifier supplied by the host.
- The host MUST document how module IDs are provisioned (preload, config, or extension pack).
- The host MUST resolve `kernel_id` within the selected module or return `#t_accel_kernel_not_found`.
 - If `cap.accel.ext.v1` is implemented, `MODULE_LOAD` MAY be used to provision module IDs.

**Provisioning options (normative, choose one or more):**
1. **Preload list** — Host preloads modules at startup and assigns stable `module_id` values.
2. **Config map** — Host reads a config file that maps `module_id` to module bytes.
3. **Extension pack** — Host enables `cap.accel.ext.v1` and accepts MODULE_LOAD calls.

**Law:** The chosen provisioning method(s) MUST be declared in `CAPS_DESCRIBE` meta.

**Example schema meta (JSON inside HBYTES, optional):**

```json
{
  "id": "cap.accel.v1",
  "backends": ["cuda"],
  "module_registry": ["preload", "extension"],
  "max_arg_count": 64,
  "max_inline_arg_bytes": 256,
  "max_module_bytes": 10485760
}
```

### 4.4 SYNC

SYNC waits for the specified queue or default stream to finish.

---

## 5. Determinism and replay

If a backend is nondeterministic, the host MUST mark it as such in CAPS_DESCRIBE
and ensure Specimen replay captures all submission results.

---

## 6. Errors

Errors MUST use `_ctl` error envelopes:
- `#t_cap_missing`
- `#t_cap_denied`
- `#t_ctl_bad_params`
- `#t_ctl_timeout`
- `#t_accel_no_device`
- `#t_accel_kernel_not_found`
- `#t_accel_launch_failed`

---

## 7. Budgets and safety

- Hosts MUST enforce `budget_ms` and queue limits.
- Buffer sizes MUST be capped by `max_buffer_bytes`.
- Hosts MUST terminate runaway submissions deterministically.

---

## 8. Optional Extensions

Advanced accelerator features (streams, events, module lifecycle, peer copy)
are defined in `cap.accel.ext.v1` (`caps/CAP_ACCEL_EXT_v1.md`). Hosts MAY
advertise it independently and are not required to implement it.
