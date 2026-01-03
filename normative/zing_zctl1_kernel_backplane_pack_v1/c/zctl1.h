#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCTL1_MAGIC 0x4C54435Au
#define ZCTL1_V     1
#define ZCTL_ERR (-1)

typedef enum zctl1_op {
  ZCTL1_OP_CAPS_LIST   = 0x0001,
  ZCTL1_OP_KERNEL_LIST = 0x0101,
  ZCTL1_OP_KERNEL_RUN  = 0x0102,
} zctl1_op;

typedef enum zctl1_status {
  ZCTL1_OK              = 0,
  ZCTL1_ERR_MALFORMED   = 1,
  ZCTL1_ERR_UNSUPPORTED = 2,
  ZCTL1_ERR_DENIED      = 3,
  ZCTL1_ERR_TIMEOUT     = 4,
  ZCTL1_ERR_NO_MEM      = 5,
  ZCTL1_ERR_BACKEND     = 6,
  ZCTL1_ERR_BAD_ARGS    = 7,
} zctl1_status;

#pragma pack(push,1)
typedef struct zctl1_req_header {
  uint32_t magic;
  uint16_t v;
  uint16_t op;
  uint32_t flags;
  uint32_t req_id;
  uint32_t payload_len;
  uint32_t timeout_ms;
  uint32_t crc32;
} zctl1_req_header;

typedef struct zctl1_resp_header {
  uint32_t magic;
  uint16_t v;
  uint16_t op;
  uint32_t flags;
  uint32_t req_id;
  uint32_t status;
  uint32_t payload_len;
  uint32_t crc32;
} zctl1_resp_header;

typedef struct zctl1_kernel_list_req { uint32_t filter; } zctl1_kernel_list_req;

typedef struct zctl1_kernel_run_req {
  uint32_t kernel_id;
  uint32_t arg_count;
  uint32_t hopper_base;
  uint32_t reserved;
} zctl1_kernel_run_req;

typedef enum zctl1_arg_kind {
  ZCTL1_ARG_I32   = 1,
  ZCTL1_ARG_U32   = 2,
  ZCTL1_ARG_I64   = 3,
  ZCTL1_ARG_U64   = 4,
  ZCTL1_ARG_BYTES = 10,
  ZCTL1_ARG_TENSOR= 11,
  ZCTL1_ARG_HOPPER_REC = 12
} zctl1_arg_kind;

typedef struct zctl1_arg { uint32_t kind,a,b,c; } zctl1_arg;

typedef struct zctl1_tensor_desc {
  uint32_t dtype;
  uint32_t rank;
  uint32_t flags;
  uint32_t data_off;
  uint32_t data_len;
  uint32_t shape_off;
  uint32_t stride_off;
  uint32_t reserved;
} zctl1_tensor_desc;

typedef struct zctl1_kernel_run_resp {
  uint32_t ok;
  uint32_t err_code;
  uint32_t err_msg_len;
} zctl1_kernel_run_resp;
#pragma pack(pop)

#define ZCTL1_REQ_HEADER_LEN  32u
#define ZCTL1_RESP_HEADER_LEN 32u

int zctl1_decode_req_header(zctl1_req_header* out, const uint8_t* buf, size_t len);
int zctl1_decode_resp_header(zctl1_resp_header* out, const uint8_t* buf, size_t len);
int zctl1_encode_req_header(uint8_t* buf, size_t cap, const zctl1_req_header* h);
int zctl1_encode_resp_header(uint8_t* buf, size_t cap, const zctl1_resp_header* h);
void zctl1_init_resp_from_req(zctl1_resp_header* resp, const zctl1_req_header* req);
int zctl1_write_err_resp(uint8_t* buf, size_t cap, const zctl1_req_header* req, uint32_t status);

#ifdef __cplusplus
}
#endif
