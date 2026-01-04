/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* ABI typedefs are defined here to avoid external header dependencies. */
typedef int32_t (*zcap_alloc_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t size);
typedef void (*zcap_free_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t ptr);

typedef int32_t (*zcap_req_read_fn)(void* ctx, int32_t handle,
                                    uint8_t* mem, size_t mem_cap,
                                    int32_t ptr, int32_t cap);

typedef int32_t (*zcap_res_write_fn)(void* ctx, int32_t handle,
                                     uint8_t* mem, size_t mem_cap,
                                     int32_t ptr, int32_t len);

typedef void (*zcap_res_end_fn)(void* ctx, int32_t handle);

typedef void (*zcap_log_fn)(void* ctx, uint8_t* mem, size_t mem_cap,
                            int32_t topic_ptr, int32_t topic_len,
                            int32_t msg_ptr, int32_t msg_len);

typedef int32_t (*zcap_ctl_fn)(void* ctx, uint8_t* mem, size_t mem_cap,
                               int32_t req_ptr, int32_t req_len,
                               int32_t resp_ptr, int32_t resp_cap);

enum {
  ZCAP_IN = 0,
  ZCAP_OUT = 1,
  ZCAP_LOG = 2
};

typedef zcap_req_read_fn  zprog_in_fn;
typedef zcap_res_write_fn zprog_out_fn;
typedef zcap_res_end_fn   zprog_end_fn;
typedef zcap_log_fn       zprog_log_fn;
typedef zcap_ctl_fn       zprog_ctl_fn;

struct zprog_sys {
  void* ctx;
  zcap_alloc_fn alloc_fn;
  zcap_free_fn  free_fn;
};

int lembeh_handle(int32_t req_handle,
                  int32_t res_handle,
                  zprog_in_fn in_fn,
                  zprog_out_fn out_fn,
                  zprog_end_fn end_fn,
                  zprog_log_fn log_fn,
                  zprog_ctl_fn ctl_fn,
                  void* host_ctx,
                  const struct zprog_sys* sys);

uint32_t zprog_heap_base_value(void);
