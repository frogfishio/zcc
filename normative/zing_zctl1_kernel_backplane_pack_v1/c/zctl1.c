#include "zctl1.h"
#include <string.h>

static int chk_len(size_t need, size_t have) { return have < need ? -1 : 0; }

int zctl1_decode_req_header(zctl1_req_header* out, const uint8_t* buf, size_t len) {
  if (!out || !buf) return -1;
  if (chk_len(ZCTL1_REQ_HEADER_LEN, len) != 0) return -1;
  memcpy(out, buf, ZCTL1_REQ_HEADER_LEN);
  if (out->magic != ZCTL1_MAGIC) return -1;
  if (out->v != ZCTL1_V) return -1;
  return 0;
}

int zctl1_decode_resp_header(zctl1_resp_header* out, const uint8_t* buf, size_t len) {
  if (!out || !buf) return -1;
  if (chk_len(ZCTL1_RESP_HEADER_LEN, len) != 0) return -1;
  memcpy(out, buf, ZCTL1_RESP_HEADER_LEN);
  if (out->magic != ZCTL1_MAGIC) return -1;
  if (out->v != ZCTL1_V) return -1;
  return 0;
}

int zctl1_encode_req_header(uint8_t* buf, size_t cap, const zctl1_req_header* h) {
  if (!buf || !h) return -1;
  if (cap < ZCTL1_REQ_HEADER_LEN) return -1;
  memcpy(buf, h, ZCTL1_REQ_HEADER_LEN);
  return 0;
}

int zctl1_encode_resp_header(uint8_t* buf, size_t cap, const zctl1_resp_header* h) {
  if (!buf || !h) return -1;
  if (cap < ZCTL1_RESP_HEADER_LEN) return -1;
  memcpy(buf, h, ZCTL1_RESP_HEADER_LEN);
  return 0;
}

void zctl1_init_resp_from_req(zctl1_resp_header* resp, const zctl1_req_header* req) {
  memset(resp, 0, sizeof(*resp));
  resp->magic = ZCTL1_MAGIC;
  resp->v = ZCTL1_V;
  resp->op = req ? req->op : 0;
  resp->req_id = req ? req->req_id : 0;
}

int zctl1_write_err_resp(uint8_t* buf, size_t cap, const zctl1_req_header* req, uint32_t status) {
  if (!buf) return -1;
  if (cap < ZCTL1_RESP_HEADER_LEN) return -1;
  zctl1_resp_header rh;
  zctl1_init_resp_from_req(&rh, req);
  rh.status = status;
  rh.payload_len = 0;
  rh.crc32 = 0;
  return zctl1_encode_resp_header(buf, cap, &rh);
}
