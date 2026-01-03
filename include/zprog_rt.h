/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../zing_abi_pack_v1/cloak_abi.h"

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
