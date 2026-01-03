# Cloak ABI Conformance Checklist (v0)

This checklist is **normative for host implementations** (“cloaks”) that run Zing/WASM apps via Lembeh.

It is intended to prevent the “_file/_net/_whatever explosion” by forcing everything non-trivial through **`_ctl`**.

> Source of truth: `ABI_GOSPEL.md` (in this pack).  
> This file is a punch-list for implementers and for Specimen conformance tests.

---

## 1) Minimum imports a cloak MUST provide

### Required

- `req_read(handle, ptr, cap) -> i32`
- `res_write(handle, ptr, len) -> i32`
- `res_end(handle) -> unit`
- `log(topic_ptr, topic_len, msg_ptr, msg_len) -> unit`
- `alloc(size) -> i32`
- `free(ptr) -> unit`
- `ctl(handle, req_ptr, req_len, resp_ptr, resp_cap, timeout_ms) -> i32`

### Reserved handles

- `0` = `_in` (stdin stream)
- `1` = `_out` (stdout stream)
- `2` = `_log` (telemetry sink; best-effort)
- `3` = `_ctl` (capability backplane)

All `>=4` are reserved for future expansion; **do not invent new meaning** for them.

---

## 2) IO semantics

### `req_read`

- Returns `n >= 0` bytes read into guest memory.
- Returns `0` for EOF.
- Returns `-1` for error.
- MUST be deterministic under Specimen: same input + same chunk schedule => same read sequence.

### `res_write`

- Returns `n >= 0` bytes written from guest memory.
- May return `< len` only if your cloak supports partial writes **and** the stdlib wrapper is specified to handle it.
- Returns `-1` for error, including “stream closed”.
- MUST NOT silently drop bytes.

### `res_end`

- MUST be **idempotent**.
- After `res_end(1)` (stdout), any `res_write(1, …)` MUST fail deterministically (recommended: `-1`).
- `res_end` MUST NOT terminate the program; the program ends when `main` returns.

### `log`

- MUST NOT trap.
- Best-effort: may drop/reorder in production **but in tests it should be captured deterministically**.

---

## 3) `_ctl` semantics (backplane)

### One law

Everything beyond `_in/_out/_log` goes through `_ctl` and **ZCL1 framing**.

### Return codes

- `>= 0` = response length written to `resp_ptr`
- `-1` = error (malformed request, unknown op, internal failure)
- `-2` = timeout (deadline elapsed; best-effort)

### Timeout rule (normative)

- `timeout_ms == 0` means **non-blocking**: return immediately.
  - If operation cannot complete immediately, return `-2` (timeout) or `-1` (unsupported), but MUST NOT block.
- `timeout_ms > 0` means cloak MAY block, but MUST return within that deadline **or** return `-2`.
- Cloak MAY clamp extreme values to an internal max, but must remain deterministic.

### Empty-list minimum contract (normative)

A cloak that offers no capabilities beyond `_in/_out/_log` MUST still implement `_ctl` and MUST support `CAPS_LIST`.

- Request: `CAPS_LIST` (op = 1), empty payload.
- Response: success with **zero entries**.

This guarantees tooling can always ask “what can you do?” and get a stable answer.

---

## 4) Determinism requirements

A cloak is “Specimen-clean” if:

- Given identical (a) stdin bytes, (b) chunk schedule, (c) wasm binary, and (d) cloak build,
  it produces identical stdout bytes and identical captured log events.
- `_ctl` responses are byte-for-byte deterministic for the same request bytes.

No timestamps, random IDs, filesystem ordering nondeterminism, or locale-dependent formatting unless explicitly injected as a capability input.

---

## 5) Failure modes MUST be stable

- Malformed ZCL1 header => `_ctl` returns `-1`.
- Unsupported op => `_ctl` returns `-1` (or a structured error payload if you define it, but be consistent).
- Response buffer too small => `_ctl` returns `-1` (or `-1` + “needed length” pattern if you adopt it later; do not guess).

---

## 6) Suggested Specimen conformance tests (host-side)

1) `cloak_caps_list_empty_ok`  
   - Run an app that calls `CAPS_LIST` and prints count; expect `0`.

2) `cloak_timeout_zero_nonblocking`  
   - Call a “slow” op with `timeout_ms=0`; ensure it returns immediately with `-2` or `-1`.

3) `stdout_closed_is_error`  
   - App calls `stdout end` then `stdout writeStr:`; expect deterministic `Fail` (not silent success).

4) `ctl_deterministic_response`  
   - Same request bytes twice => identical response bytes.

---

## 7) Notes for implementers

- If you need “file”, “net”, “crypto”, “ui”, etc: add them as `_ctl` operations with stable schemas.
- Do not add new raw imports like `_file_*` or `_net_*`. That’s how ABI rot starts.
