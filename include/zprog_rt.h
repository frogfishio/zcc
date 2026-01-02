/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef int32_t (*zprog_in_fn)(void* ctx,
                               int32_t req_handle,
                               uint8_t* mem,
                               size_t mem_cap,
                               int32_t ptr,
                               int32_t cap);

typedef int32_t (*zprog_out_fn)(void* ctx,
                                int32_t res_handle,
                                uint8_t* mem,
                                size_t mem_cap,
                                int32_t ptr,
                                int32_t len);

typedef void (*zprog_log_fn)(void* ctx,
                              uint8_t* mem,
                              size_t mem_cap,
                              int32_t topic_ptr,
                              int32_t topic_len,
                              int32_t msg_ptr,
                              int32_t msg_len);

struct zprog_sys {
  void* ctx;
  int32_t (*alloc_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t size);
  void (*free_fn)(void* ctx, uint8_t* mem, size_t mem_cap, int32_t ptr);
};

int lembeh_handle(int32_t req_handle,
                  int32_t res_handle,
                  zprog_in_fn in_fn,
                  zprog_out_fn out_fn,
                  zprog_log_fn log_fn,
                  void* host_ctx,
                  const struct zprog_sys* sys);

uint32_t zprog_heap_base_value(void);
