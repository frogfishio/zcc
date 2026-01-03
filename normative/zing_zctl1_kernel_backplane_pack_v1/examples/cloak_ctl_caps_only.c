#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../c/zctl1.h"

static int32_t clamp_i32(size_t v) { return v > 0x7fffffff ? ZCTL_ERR : (int32_t)v; }

static int in_bounds(size_t mem_cap, int32_t ptr, int32_t len) {
  if (ptr < 0 || len < 0) return 0;
  size_t p=(size_t)ptr, l=(size_t)len;
  return p + l <= mem_cap;
}

int32_t cloak_ctl(void* ctx,
                  int32_t ctl_handle,
                  uint8_t* mem,
                  size_t mem_cap,
                  int32_t req_ptr,
                  int32_t req_len,
                  int32_t resp_ptr,
                  int32_t resp_cap,
                  int32_t timeout_ms) {
  (void)ctx; (void)ctl_handle; (void)timeout_ms;
  if (!mem) return ZCTL_ERR;
  if (!in_bounds(mem_cap, req_ptr, req_len)) return ZCTL_ERR;
  if (!in_bounds(mem_cap, resp_ptr, resp_cap)) return ZCTL_ERR;
  if (req_len < (int32_t)ZCTL1_REQ_HEADER_LEN) return ZCTL_ERR;
  if (resp_cap < (int32_t)ZCTL1_RESP_HEADER_LEN) return ZCTL_ERR;

  const uint8_t* req = mem + (size_t)req_ptr;
  zctl1_req_header rh;
  if (zctl1_decode_req_header(&rh, req, (size_t)req_len) != 0) return ZCTL_ERR;
  if ((size_t)req_len != ZCTL1_REQ_HEADER_LEN + rh.payload_len) {
    zctl1_write_err_resp(mem + (size_t)resp_ptr, (size_t)resp_cap, &rh, ZCTL1_ERR_MALFORMED);
    return (int32_t)ZCTL1_RESP_HEADER_LEN;
  }

  uint8_t* resp = mem + (size_t)resp_ptr;

  if (rh.op == ZCTL1_OP_CAPS_LIST) {
    size_t payload_len = 4; // n=0
    size_t total = ZCTL1_RESP_HEADER_LEN + payload_len;
    if ((size_t)resp_cap < total) return ZCTL_ERR;

    zctl1_resp_header oh;
    zctl1_init_resp_from_req(&oh, &rh);
    oh.status = ZCTL1_OK;
    oh.payload_len = (uint32_t)payload_len;
    zctl1_encode_resp_header(resp, (size_t)resp_cap, &oh);
    memset(resp + ZCTL1_RESP_HEADER_LEN, 0, 4);
    return clamp_i32(total);
  }

  zctl1_write_err_resp(resp, (size_t)resp_cap, &rh, ZCTL1_ERR_UNSUPPORTED);
  return (int32_t)ZCTL1_RESP_HEADER_LEN;
}
