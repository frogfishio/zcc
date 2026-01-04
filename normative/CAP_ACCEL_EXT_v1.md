# Capability: cap.accel.ext.v1 (Normative)

This document defines optional accelerator extensions for ABI v1.0.
All payloads are Hopper binary layouts (H1/H2/H4/H8, HSTR, HBYTES).
A host MAY expose none, some, or all of these modes.

---

## 1. Capability identity

- kind: `accel.ext`
- name: `default`
- version: `1`
- canonical id: `cap.accel.ext.v1`

---

## 2. CAPS_DESCRIBE schema

`CAPS_DESCRIBE("accel.ext","default")` returns opaque HBYTES.
If a host chooses JSON for tooling, it is carried inside HBYTES and is not
interpreted by the ABI.

Recommended keys (optional):
- `modes` (stream.create, stream.destroy, event.create, event.record, event.wait, buffer.copy, module.load, module.unload)
- `max_streams`
- `max_events`
- `max_module_bytes`

---

## 3. CAPS_OPEN modes

Mode values (H4):
- 1: STREAM_CREATE
- 2: STREAM_DESTROY
- 3: EVENT_CREATE
- 4: EVENT_RECORD
- 5: EVENT_WAIT
- 6: BUFFER_COPY
- 7: MODULE_LOAD
- 8: MODULE_UNLOAD

All modes return a stream handle. The handle MUST be READABLE|ENDABLE and yields
exactly one record, then EOF.

### 3.1 STREAM_CREATE (mode = 1)

Params:

```
HSTR backend
HSTR device_id
H4 flags
```

Flags:
- bit0: low_priority
- bit1: high_priority

Stream record (single record):

```
H4 stream_id
```

**Law:** `stream_id` MUST be stable within a run and unique per `(backend, device_id)`.

### 3.2 STREAM_DESTROY (mode = 2)

Params:

```
HSTR backend
HSTR device_id
H4 stream_id
```

Stream record (single record):

```
H1 ok
```

After the single record is read, further reads MUST return 0.

### 3.3 EVENT_CREATE (mode = 3)

Params:

```
HSTR backend
HSTR device_id
H4 flags
```

Flags:
- bit0: timing

Stream record (single record):

```
H4 event_id
```

**Law:** `event_id` MUST be stable within a run and unique per `(backend, device_id)`.

### 3.4 EVENT_RECORD (mode = 4)

Params:

```
HSTR backend
HSTR device_id
H4 stream_id
H4 event_id
```

Stream record (single record):

```
H1 ok
```

### 3.5 EVENT_WAIT (mode = 5)

Params:

```
HSTR backend
HSTR device_id
H4 stream_id
H4 event_id
H4 timeout_ms
```

**Note:** The ZCL1 request header `timeout_ms` still bounds the overall call. If both
are present, the smaller budget MUST be enforced.

Stream record (single record):

```
H1 status   ; 0 = pending, 1 = signaled, 2 = timeout
```

### 3.6 BUFFER_COPY (mode = 6)

Params:

```
HSTR backend
HSTR device_id
H4 src_handle
H4 dst_handle
H8 bytes
H4 flags
```

Flags:
- bit0: peer_to_peer

Stream record (single record):

```
H1 ok
```

**Law:** If `peer_to_peer` is set, both buffers MUST be peer-compatible or the call
MUST fail with `#t_accel_copy_failed`.

### 3.7 MODULE_LOAD (mode = 7)

Params:

```
HSTR backend
HSTR device_id
HBYTES module_bytes
HBYTES module_id_hint
```

Stream record (single record):

```
HBYTES module_id
```

**Law:** If `module_id_hint` is empty, the host MUST return a stable module_id for
identical module bytes within a run.

### 3.8 MODULE_UNLOAD (mode = 8)

Params:

```
HSTR backend
HSTR device_id
HBYTES module_id
```

Stream record (single record):

```
H1 ok
```

---

## 4. Determinism and replay

If any backend behavior is nondeterministic, hosts MUST record/replay outcomes.
`EVENT_WAIT` with timeout MUST return deterministic outcomes under replay.

---

## 5. Errors

Errors MUST use `_ctl` error envelopes:
- `#t_cap_missing`
- `#t_cap_denied`
- `#t_ctl_bad_params`
- `#t_ctl_timeout`
- `#t_accel_no_device`
- `#t_accel_invalid_handle`
- `#t_accel_module_invalid`
- `#t_accel_copy_failed`
