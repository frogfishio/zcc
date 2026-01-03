/* SPDX-FileCopyrightText: 2026 Frogfish
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * zcl1.h — Zing Cloak Link v1 framing helpers (ZCL1)
 *
 * Helper routines that keep request/response framing in sync with the
 * normative ZCL1 specification (see ABI_GOSPEL.md).
 */
#ifndef ZCL1_H
#define ZCL1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL1_MAGIC_0 'Z'
#define ZCL1_MAGIC_1 'C'
#define ZCL1_MAGIC_2 'L'
#define ZCL1_MAGIC_3 '1'

#define ZCL1_VERSION 1u

#define ZCL1_REQ_HEADER_LEN 24u
#define ZCL1_RESP_HEADER_LEN 20u
#define ZCL1_RESP_OK_PREFIX_LEN 4u

#define ZCL1_FLAGS_NONE 0u

#define ZCL1_OP_CAPS_LIST     1u
#define ZCL1_OP_CAPS_DESCRIBE 2u
#define ZCL1_OP_CAPS_OPEN     3u

struct zcl1_req_header {
  uint8_t  magic[4];
  uint16_t version;
  uint16_t op;
  uint32_t rid;
  uint32_t timeout_ms;
  uint32_t flags;
  uint32_t payload_len;
};
typedef struct zcl1_req_header zcl1_req_header;

struct zcl1_resp_header {
  uint8_t  magic[4];
  uint16_t version;
  uint16_t op;
  uint32_t rid;
  uint32_t flags;
  uint32_t payload_len;
};
typedef struct zcl1_resp_header zcl1_resp_header;

static inline void zcl1_set_magic(uint8_t dst[4]) {
  dst[0] = (uint8_t)ZCL1_MAGIC_0;
  dst[1] = (uint8_t)ZCL1_MAGIC_1;
  dst[2] = (uint8_t)ZCL1_MAGIC_2;
  dst[3] = (uint8_t)ZCL1_MAGIC_3;
}

static inline int zcl1_magic_valid(const uint8_t magic[4]) {
  return magic[0] == (uint8_t)ZCL1_MAGIC_0 &&
         magic[1] == (uint8_t)ZCL1_MAGIC_1 &&
         magic[2] == (uint8_t)ZCL1_MAGIC_2 &&
         magic[3] == (uint8_t)ZCL1_MAGIC_3;
}

static inline void zcl1_init_resp_from_req(zcl1_resp_header* resp,
                                           const zcl1_req_header* req) {
  if (!resp || !req) return;
  zcl1_set_magic(resp->magic);
  resp->version = req->version;
  resp->op = req->op;
  resp->rid = req->rid;
  resp->flags = ZCL1_FLAGS_NONE;
  resp->payload_len = 0;
}

static inline int zcl1_req_header_is_valid(const zcl1_req_header* h) {
  if (!h) return 0;
  if (!zcl1_magic_valid(h->magic)) return 0;
  if (h->version != (uint16_t)ZCL1_VERSION) return 0;
  if (h->flags != ZCL1_FLAGS_NONE) return 0;
  return 1;
}

static inline int zcl1_resp_header_is_valid(const zcl1_resp_header* h) {
  if (!h) return 0;
  if (!zcl1_magic_valid(h->magic)) return 0;
  if (h->version != (uint16_t)ZCL1_VERSION) return 0;
  if (h->flags != ZCL1_FLAGS_NONE) return 0;
  return 1;
}

static inline int zcl1_encode_req_header(uint8_t* out,
                                         size_t out_cap,
                                         const zcl1_req_header* h) {
  if (!out || !h || out_cap < ZCL1_REQ_HEADER_LEN) return -1;
  zcl1_set_magic(out);
  out[4] = (uint8_t)(h->version & 0xFFu);
  out[5] = (uint8_t)((h->version >> 8) & 0xFFu);
  out[6] = (uint8_t)(h->op & 0xFFu);
  out[7] = (uint8_t)((h->op >> 8) & 0xFFu);
  out[8] = (uint8_t)(h->rid & 0xFFu);
  out[9] = (uint8_t)((h->rid >> 8) & 0xFFu);
  out[10] = (uint8_t)((h->rid >> 16) & 0xFFu);
  out[11] = (uint8_t)((h->rid >> 24) & 0xFFu);
  out[12] = (uint8_t)(h->timeout_ms & 0xFFu);
  out[13] = (uint8_t)((h->timeout_ms >> 8) & 0xFFu);
  out[14] = (uint8_t)((h->timeout_ms >> 16) & 0xFFu);
  out[15] = (uint8_t)((h->timeout_ms >> 24) & 0xFFu);
  out[16] = (uint8_t)(h->flags & 0xFFu);
  out[17] = (uint8_t)((h->flags >> 8) & 0xFFu);
  out[18] = (uint8_t)((h->flags >> 16) & 0xFFu);
  out[19] = (uint8_t)((h->flags >> 24) & 0xFFu);
  out[20] = (uint8_t)(h->payload_len & 0xFFu);
  out[21] = (uint8_t)((h->payload_len >> 8) & 0xFFu);
  out[22] = (uint8_t)((h->payload_len >> 16) & 0xFFu);
  out[23] = (uint8_t)((h->payload_len >> 24) & 0xFFu);
  return 0;
}

static inline int zcl1_decode_req_header(zcl1_req_header* out,
                                         const uint8_t* buf,
                                         size_t buf_len) {
  if (!out || !buf || buf_len < ZCL1_REQ_HEADER_LEN) return -1;
  out->magic[0] = buf[0];
  out->magic[1] = buf[1];
  out->magic[2] = buf[2];
  out->magic[3] = buf[3];
  out->version = (uint16_t)buf[4] | ((uint16_t)buf[5] << 8);
  out->op = (uint16_t)buf[6] | ((uint16_t)buf[7] << 8);
  out->rid = (uint32_t)buf[8]
           | ((uint32_t)buf[9] << 8)
           | ((uint32_t)buf[10] << 16)
           | ((uint32_t)buf[11] << 24);
  out->timeout_ms = (uint32_t)buf[12]
                  | ((uint32_t)buf[13] << 8)
                  | ((uint32_t)buf[14] << 16)
                  | ((uint32_t)buf[15] << 24);
  out->flags = (uint32_t)buf[16]
             | ((uint32_t)buf[17] << 8)
             | ((uint32_t)buf[18] << 16)
             | ((uint32_t)buf[19] << 24);
  out->payload_len = (uint32_t)buf[20]
                   | ((uint32_t)buf[21] << 8)
                   | ((uint32_t)buf[22] << 16)
                   | ((uint32_t)buf[23] << 24);
  return zcl1_req_header_is_valid(out) ? 0 : -1;
}

static inline int zcl1_encode_resp_header(uint8_t* out,
                                          size_t out_cap,
                                          const zcl1_resp_header* h) {
  if (!out || !h || out_cap < ZCL1_RESP_HEADER_LEN) return -1;
  zcl1_set_magic(out);
  out[4] = (uint8_t)(h->version & 0xFFu);
  out[5] = (uint8_t)((h->version >> 8) & 0xFFu);
  out[6] = (uint8_t)(h->op & 0xFFu);
  out[7] = (uint8_t)((h->op >> 8) & 0xFFu);
  out[8] = (uint8_t)(h->rid & 0xFFu);
  out[9] = (uint8_t)((h->rid >> 8) & 0xFFu);
  out[10] = (uint8_t)((h->rid >> 16) & 0xFFu);
  out[11] = (uint8_t)((h->rid >> 24) & 0xFFu);
  out[12] = (uint8_t)(h->flags & 0xFFu);
  out[13] = (uint8_t)((h->flags >> 8) & 0xFFu);
  out[14] = (uint8_t)((h->flags >> 16) & 0xFFu);
  out[15] = (uint8_t)((h->flags >> 24) & 0xFFu);
  out[16] = (uint8_t)(h->payload_len & 0xFFu);
  out[17] = (uint8_t)((h->payload_len >> 8) & 0xFFu);
  out[18] = (uint8_t)((h->payload_len >> 16) & 0xFFu);
  out[19] = (uint8_t)((h->payload_len >> 24) & 0xFFu);
  return 0;
}

static inline int zcl1_decode_resp_header(zcl1_resp_header* out,
                                          const uint8_t* buf,
                                          size_t buf_len) {
  if (!out || !buf || buf_len < ZCL1_RESP_HEADER_LEN) return -1;
  out->magic[0] = buf[0];
  out->magic[1] = buf[1];
  out->magic[2] = buf[2];
  out->magic[3] = buf[3];
  out->version = (uint16_t)buf[4] | ((uint16_t)buf[5] << 8);
  out->op = (uint16_t)buf[6] | ((uint16_t)buf[7] << 8);
  out->rid = (uint32_t)buf[8]
           | ((uint32_t)buf[9] << 8)
           | ((uint32_t)buf[10] << 16)
           | ((uint32_t)buf[11] << 24);
  out->flags = (uint32_t)buf[12]
             | ((uint32_t)buf[13] << 8)
             | ((uint32_t)buf[14] << 16)
             | ((uint32_t)buf[15] << 24);
  out->payload_len = (uint32_t)buf[16]
                   | ((uint32_t)buf[17] << 8)
                   | ((uint32_t)buf[18] << 16)
                   | ((uint32_t)buf[19] << 24);
  return zcl1_resp_header_is_valid(out) ? 0 : -1;
}

#ifdef __cplusplus
}
#endif

#endif /* ZCL1_H */
