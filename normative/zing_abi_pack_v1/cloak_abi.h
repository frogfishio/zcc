/* SPDX-FileCopyrightText: 2026 Frogfish
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * cloak_abi.h — minimal host-side ABI surface for Zing apps (lembeh-compatible)
 *
 * This is the host contract: how the WASM module talks to the cloak.
 * Keep this *tiny*. Everything else must go through `_ctl` using ZCL1 frames.
 *
 * See ABI_GOSPEL.md for full normative semantics.
 */
#ifndef CLOAK_ABI_H
#define CLOAK_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Host alloc/free for the guest heap (optional if guest uses its own). */
typedef int32_t (*zcap_alloc_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t size);
typedef void   (*zcap_free_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t ptr);

/* stdin-like input: write up to cap bytes into mem[ptr..ptr+cap). Return:
 *  >=0 bytes read
 *   0  EOF
 *  -1  error
 */
typedef int32_t (*zcap_req_read_fn)(
  void* ctx,
  int32_t req_handle,
  uint8_t* mem,
  size_t mem_cap,
  int32_t ptr,
  int32_t cap
);

/* stdout-like output: write len bytes from mem[ptr..ptr+len). Return:
 *  >=0 bytes written (may be < len if partial writes are supported)
 *  -1 error (including “closed”)
 */
typedef int32_t (*zcap_res_write_fn)(
  void* ctx,
  int32_t res_handle,
  uint8_t* mem,
  size_t mem_cap,
  int32_t ptr,
  int32_t len
);

/* End/close an output resource. Must be idempotent. */
typedef void (*zcap_res_end_fn)(void* ctx, int32_t res_handle);

/* Best-effort telemetry. Must not trap. */
typedef void (*zcap_log_fn)(
  void* ctx,
  uint8_t* mem,
  size_t mem_cap,
  int32_t topic_ptr,
  int32_t topic_len,
  int32_t msg_ptr,
  int32_t msg_len
);

/* `_ctl` backplane call. The request and response buffers are raw bytes.
 * Request is typically a ZCL1 frame + binary payload. Response likewise.
 *
 * Return:
 *  >=0 : number of bytes written to resp_ptr (<= resp_cap)
 *  -1  : error
 *  -2  : timeout (deadline elapsed; best-effort)
 */
typedef int32_t (*zcap_ctl_fn)(
  void* ctx,
  int32_t ctl_handle,
  uint8_t* mem,
  size_t mem_cap,
  int32_t req_ptr,
  int32_t req_len,
  int32_t resp_ptr,
  int32_t resp_cap,
  int32_t timeout_ms
);

/* `_ctl` return codes */
#define ZCTL_OK_MINLEN 0    /* >=0 = bytes written */
#define ZCTL_ERR      (-1)  /* malformed/unsupported */
#define ZCTL_TIMEOUT  (-2)  /* deadline elapsed */

/* Canonical reserved handles (stable). */
enum {
  ZCAP_IN  = 0,
  ZCAP_OUT = 1,
  ZCAP_LOG = 2,
  ZCAP_CTL = 3
};

#ifdef __cplusplus
}
#endif

#endif /* CLOAK_ABI_H */
