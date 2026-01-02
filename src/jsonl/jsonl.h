/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stddef.h>

typedef enum {
  JREC_NONE = 0,
  JREC_INSTR,
  JREC_DIR,
  JREC_LABEL
} rec_kind_t;

typedef enum {
  JOP_NONE = 0,
  JOP_SYM,
  JOP_NUM,
  JOP_STR,
  JOP_MEM
} op_kind_t;

typedef struct {
  op_kind_t t;
  char* s;     // for SYM/STR/MEM base (heap-allocated)
  long n;      // for NUM
} operand_t;

typedef struct {
  rec_kind_t k;
  int line;          // optional: from loc.line if present, else -1

  // instr
  char* m;           // mnemonic
  operand_t* ops;
  size_t nops;

  // dir
  char* d;           // directive
  char* name;        // optional symbol name (for DB/DW)
  operand_t* args;
  size_t nargs;

  // label
  char* label;
} record_t;

typedef struct {
  record_t* v;
  size_t n;
  size_t cap;
} recvec_t;

void recvec_init(recvec_t* r);
void recvec_push(recvec_t* r, record_t rec);
void recvec_free(recvec_t* r);

int parse_jsonl_record(const char* line, record_t* out); // 0=ok, nonzero=error
void record_free(record_t* r);
