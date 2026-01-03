/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "jsonl.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static void* xrealloc(void* p, size_t n) {
  void* r = realloc(p, n);
  if (!r) { fprintf(stderr, "zld: OOM\n"); exit(2); }
  return r;
}

void recvec_init(recvec_t* r) {
  r->v = NULL; r->n = 0; r->cap = 0;
}

void recvec_push(recvec_t* r, record_t rec) {
  if (r->n == r->cap) {
    r->cap = r->cap ? (r->cap * 2) : 64;
    r->v = (record_t*)xrealloc(r->v, r->cap * sizeof(record_t));
  }
  r->v[r->n++] = rec;
}

static void operand_free(operand_t* o) {
  if (!o) return;
  if ((o->t == JOP_SYM || o->t == JOP_STR || o->t == JOP_MEM) && o->s) free(o->s);
  o->s = NULL;
}

void record_free(record_t* r) {
  if (!r) return;

  if (r->m) free(r->m);
  if (r->d) free(r->d);
  if (r->name) free(r->name);
  if (r->label) free(r->label);

  for (size_t i = 0; i < r->nops; i++) operand_free(&r->ops[i]);
  free(r->ops);

  for (size_t i = 0; i < r->nargs; i++) operand_free(&r->args[i]);
  free(r->args);

  memset(r, 0, sizeof(*r));
}

void recvec_free(recvec_t* r) {
  if (!r) return;
  for (size_t i = 0; i < r->n; i++) record_free(&r->v[i]);
  free(r->v);
  r->v = NULL; r->n = 0; r->cap = 0;
}

/* -------- Minimal JSON helpers (for our own JSONL format) -------- */
// We keep this parser intentionally tiny to avoid pulling a JSON dependency into
// the toolchain; the IR schema is small and stable.

static const char* skip_ws(const char* p) {
  while (*p && (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')) p++;
  return p;
}

// parse JSON string starting at opening quote; returns heap string; advances *p past closing quote
static char* parse_json_string(const char** p) {
  const char* s = *p;
  if (*s != '"') return NULL;
  s++;
  char* out = (char*)malloc(1);
  size_t cap = 1, len = 0;

  while (*s && *s != '"') {
    unsigned char c = (unsigned char)*s++;
    if (c == '\\') {
      unsigned char e = (unsigned char)*s++;
      switch (e) {
        case '\\': c = '\\'; break;
        case '"':  c = '"';  break;
        case 'n':  c = '\n'; break;
        case 'r':  c = '\r'; break;
        case 't':  c = '\t'; break;
        default:   c = e;    break; // minimal
      }
    }
    if (len + 2 > cap) { cap *= 2; out = (char*)xrealloc(out, cap); }
    out[len++] = (char)c;
  }
  if (*s != '"') { free(out); return NULL; }
  s++; // closing quote
  out[len] = 0;
  *p = s;
  return out;
}

static int64_t parse_json_int(const char** p, int* ok) {
  const char* s = *p;
  s = skip_ws(s);
  int neg = 0;
  if (*s == '-') { neg = 1; s++; }
  if (!isdigit((unsigned char)*s)) { *ok = 0; return 0; }
  int64_t v = 0;
  while (isdigit((unsigned char)*s)) {
    v = v * 10 + (*s - '0');
    s++;
  }
  *p = s;
  *ok = 1;
  return neg ? -v : v;
}

// find substring key pattern and return pointer just after it, else NULL
static const char* find_key(const char* line, const char* keypat) {
  const char* p = strstr(line, keypat);
  if (!p) return NULL;
  return p + strlen(keypat);
}

// IR version tagging is mandatory; this is our compatibility gate for the pipeline.
static int parse_ir_version(const char* line) {
  const char* p = find_key(line, "\"ir\":\"");
  if (!p) return 0;
  const char* end = strchr(p, '"');
  if (!end) return 0;
  size_t n = (size_t)(end - p);
  if (n == strlen("zasm-v1.0") && strncmp(p, "zasm-v1.0", n) == 0) {
    return 1;
  }
  return -1;
}

// parse loc.line if present: ,"loc":{"line":N}
static int parse_loc_line(const char* line) {
  const char* p = strstr(line, "\"loc\":{\"line\":");
  if (!p) return -1;
  p += strlen("\"loc\":{\"line\":");
  int ok = 0;
  int64_t v = parse_json_int(&p, &ok);
  return ok ? (int)v : -1;
}

static operand_t* parse_operand_array(const char* start, size_t* out_n, int* out_ok) {
  *out_n = 0; *out_ok = 0;
  const char* p = start;
  p = skip_ws(p);
  if (*p != '[') return NULL;
  p++;

  operand_t* arr = NULL;
  size_t n = 0, cap = 0;

  p = skip_ws(p);
  if (*p == ']') { p++; *out_n = 0; *out_ok = 1; return NULL; }

  while (*p) {
    p = skip_ws(p);
    if (*p != '{') break;
    p++;

    operand_t op;
    memset(&op, 0, sizeof(op));

    // Expect "t":"X","v":...
    const char* pt = strstr(p, "\"t\":\"");
    if (!pt) break;
    p = pt + strlen("\"t\":\"");
    if (strncmp(p, "sym", 3) == 0) op.t = JOP_SYM;
    else if (strncmp(p, "num", 3) == 0) op.t = JOP_NUM;
    else if (strncmp(p, "str", 3) == 0) op.t = JOP_STR;
    else if (strncmp(p, "mem", 3) == 0) op.t = JOP_MEM;
    else op.t = JOP_NONE;

    const char* tq = strchr(p, '"'); // end of t value
    if (!tq) break;
    p = tq + 1;

    if (op.t == JOP_MEM) {
      const char* pb = strstr(p, "\"base\":");
      if (!pb) break;
      p = pb + strlen("\"base\":");
      p = skip_ws(p);
      char* s = parse_json_string(&p);
      if (!s) break;
      op.s = s;
    } else {
      const char* pv = strstr(p, "\"v\":");
      if (!pv) break;
      p = pv + strlen("\"v\":");
      p = skip_ws(p);

      if (op.t == JOP_NUM) {
        int ok = 0;
        long v = parse_json_int(&p, &ok);
        if (!ok) break;
        op.n = v;
      } else {
        p = skip_ws(p);
        char* s = parse_json_string(&p);
        if (!s) break;
        op.s = s;
      }
    }

    const char* endobj = strchr(p, '}');
    if (!endobj) break;
    p = endobj + 1;

    if (n == cap) {
      cap = cap ? cap * 2 : 8;
      arr = (operand_t*)xrealloc(arr, cap * sizeof(operand_t));
    }
    arr[n++] = op;

    p = skip_ws(p);
    if (*p == ',') { p++; continue; }
    if (*p == ']') { p++; *out_n = n; *out_ok = 1; return arr; }
  }

  // error cleanup
  if (arr) {
    for (size_t i = 0; i < n; i++) operand_free(&arr[i]);
    free(arr);
  }
  return NULL;
}

int parse_jsonl_record(const char* line, record_t* out) {
  memset(out, 0, sizeof(*out));
  out->line = parse_loc_line(line);

  int ir_ok = parse_ir_version(line);
  if (ir_ok == 0) return 10;
  if (ir_ok < 0) return 11;

  const char* pk = find_key(line, "\"k\":\"");
  if (!pk) return 1;
  const char* p = pk;
  const char* end = strchr(p, '"');
  if (!end) return 1;
  char kind[16];
  size_t klen = (size_t)(end - p);
  if (klen >= sizeof(kind)) return 1;
  memcpy(kind, p, klen);
  kind[klen] = 0;

  if (strcmp(kind, "instr") == 0) {
    out->k = JREC_INSTR;

    const char* pm = find_key(line, "\"m\":\"");
    if (!pm) return 2;
    p = pm;
    end = strchr(p, '"');
    if (!end) return 2;
    out->m = (char*)malloc((size_t)(end - p) + 1);
    memcpy(out->m, p, (size_t)(end - p));
    out->m[end - p] = 0;

    const char* pops = find_key(line, "\"ops\":");
    if (!pops) return 2;
    int ok = 0;
    out->ops = parse_operand_array(pops, &out->nops, &ok);
    if (!ok) return 2;
    return 0;
  }

  if (strcmp(kind, "dir") == 0) {
    out->k = JREC_DIR;

    const char* pd = find_key(line, "\"d\":\"");
    if (!pd) return 3;
    p = pd;
    end = strchr(p, '"');
    if (!end) return 3;
    out->d = (char*)malloc((size_t)(end - p) + 1);
    memcpy(out->d, p, (size_t)(end - p));
    out->d[end - p] = 0;

    const char* pn = find_key(line, "\"name\":\"");
    if (pn) {
      p = pn;
      end = strchr(p, '"');
      if (!end) return 3;
      out->name = (char*)malloc((size_t)(end - p) + 1);
      memcpy(out->name, p, (size_t)(end - p));
      out->name[end - p] = 0;
    }

    const char* pargs = find_key(line, "\"args\":");
    if (!pargs) return 3;
    int ok = 0;
    out->args = parse_operand_array(pargs, &out->nargs, &ok);
    if (!ok) return 3;
    return 0;
  }

  if (strcmp(kind, "label") == 0) {
    out->k = JREC_LABEL;
    const char* pn = find_key(line, "\"name\":\"");
    if (!pn) return 4;
    p = pn;
    end = strchr(p, '"');
    if (!end) return 4;
    out->label = (char*)malloc((size_t)(end - p) + 1);
    memcpy(out->label, p, (size_t)(end - p));
    out->label[end - p] = 0;
    return 0;
  }

  return 9;
}
