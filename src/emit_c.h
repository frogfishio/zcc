/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stdio.h>
#include "jsonl.h"

int emit_c_module(const recvec_t* recs, unsigned heap_slack, FILE* out);
