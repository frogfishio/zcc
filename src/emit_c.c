/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "emit_c.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifndef ZCC_MAX
#define ZCC_MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

typedef struct {
  uint8_t* bytes;
  size_t len;
  uint32_t offset;
  char* name;
} data_seg_t;

typedef struct {
  data_seg_t* v;
  size_t n;
  size_t cap;
  uint32_t next_off;
} datavec_t;

typedef struct {
  char* name;
  long val;
} gsym_t;

typedef struct {
  gsym_t* v;
  size_t n;
  size_t cap;
} gsymtab_t;

typedef struct {
  const char* name;
  size_t pc;
} label_t;

typedef struct {
  label_t* v;
  size_t n;
  size_t cap;
} labelvec_t;

typedef struct {
  const record_t* rec;
  size_t rec_index;
} instr_t;

typedef struct {
  instr_t* v;
  size_t n;
} instrvec_t;

typedef struct {
  char* orig;
  char* c_name;
} name_entry_t;

typedef struct {
  name_entry_t* v;
  size_t n;
  size_t cap;
} namemap_t;

static void* xalloc(size_t n) {
  void* p = malloc(n);
  if (!p) {
    fprintf(stderr, "zcc: OOM\n");
    exit(2);
  }
  return p;
}

static void* xrealloc(void* p, size_t n) {
  void* r = realloc(p, n);
  if (!r) {
    fprintf(stderr, "zcc: OOM\n");
    exit(2);
  }
  return r;
}

static char* xstrdup(const char* s) {
  size_t n = strlen(s);
  char* out = (char*)xalloc(n + 1);
  memcpy(out, s, n + 1);
  return out;
}

static void datavec_init(datavec_t* d, uint32_t start_off) {
  d->v = NULL;
  d->n = 0;
  d->cap = 0;
  d->next_off = start_off;
}

static void datavec_add(datavec_t* d, const char* name, const uint8_t* bytes, size_t len) {
  if (d->n == d->cap) {
    d->cap = d->cap ? d->cap * 2 : 8;
    d->v = (data_seg_t*)xrealloc(d->v, d->cap * sizeof(data_seg_t));
  }
  data_seg_t* seg = &d->v[d->n++];
  seg->bytes = (uint8_t*)xalloc(len ? len : 1);
  if (len) memcpy(seg->bytes, bytes, len);
  seg->len = len;
  seg->offset = d->next_off;
  seg->name = xstrdup(name);
  d->next_off += (uint32_t)len;
  d->next_off = (d->next_off + 3u) & ~3u;
}

static void datavec_free(datavec_t* d) {
  if (!d) return;
  for (size_t i = 0; i < d->n; i++) {
    free(d->v[i].bytes);
    free(d->v[i].name);
  }
  free(d->v);
  d->v = NULL;
  d->n = d->cap = 0;
}

static void gsymtab_init(gsymtab_t* g) {
  g->v = NULL;
  g->n = 0;
  g->cap = 0;
}

static void gsymtab_free(gsymtab_t* g) {
  if (!g) return;
  for (size_t i = 0; i < g->n; i++) free(g->v[i].name);
  free(g->v);
  g->v = NULL;
  g->n = g->cap = 0;
}

static int gsymtab_put(gsymtab_t* g, const char* name, long val, int line) {
  for (size_t i = 0; i < g->n; i++) {
    if (strcmp(g->v[i].name, name) == 0) {
      fprintf(stderr, "zcc: duplicate symbol %s (line %d)\n", name, line);
      return 1;
    }
  }
  if (g->n == g->cap) {
    g->cap = g->cap ? g->cap * 2 : 16;
    g->v = (gsym_t*)xrealloc(g->v, g->cap * sizeof(gsym_t));
  }
  g->v[g->n].name = xstrdup(name);
  g->v[g->n].val = val;
  g->n++;
  return 0;
}

static int gsymtab_get(const gsymtab_t* g, const char* name, long* out) {
  for (size_t i = 0; i < g->n; i++) {
    if (strcmp(g->v[i].name, name) == 0) {
      *out = g->v[i].val;
      return 1;
    }
  }
  return 0;
}

static void labelvec_init(labelvec_t* v) {
  v->v = NULL;
  v->n = v->cap = 0;
}

static void labelvec_free(labelvec_t* v) {
  free(v->v);
  v->v = NULL;
  v->n = v->cap = 0;
}

static void labelvec_put(labelvec_t* v, const char* name, size_t pc) {
  for (size_t i = 0; i < v->n; i++) {
    if (strcmp(v->v[i].name, name) == 0) {
      v->v[i].pc = pc;
      return;
    }
  }
  if (v->n == v->cap) {
    v->cap = v->cap ? v->cap * 2 : 16;
    v->v = (label_t*)xrealloc(v->v, v->cap * sizeof(label_t));
  }
  v->v[v->n].name = name;
  v->v[v->n].pc = pc;
  v->n++;
}

static int labelvec_get(const labelvec_t* v, const char* name, size_t* out_pc) {
  for (size_t i = 0; i < v->n; i++) {
    if (strcmp(v->v[i].name, name) == 0) {
      *out_pc = v->v[i].pc;
      return 1;
    }
  }
  return 0;
}

static void namemap_init(namemap_t* m) {
  m->v = NULL;
  m->n = m->cap = 0;
}

static void namemap_free(namemap_t* m) {
  if (!m) return;
  for (size_t i = 0; i < m->n; i++) {
    free(m->v[i].orig);
    free(m->v[i].c_name);
  }
  free(m->v);
  m->v = NULL;
  m->n = m->cap = 0;
}

static void sanitize(const char* src, char* dst, size_t cap) {
  size_t di = 0;
  if (!isalpha((unsigned char)src[0]) && src[0] != '_') {
    if (di + 1 < cap) dst[di++] = '_';
  }
  for (size_t i = 0; src[i] && di + 1 < cap; i++) {
    unsigned char c = (unsigned char)src[i];
    if (isalnum(c) || c == '_') dst[di++] = (char)c;
    else dst[di++] = '_';
  }
  dst[di] = 0;
}

static const char* namemap_get(namemap_t* m, const char* orig, const char* prefix) {
  for (size_t i = 0; i < m->n; i++) {
    if (strcmp(m->v[i].orig, orig) == 0) return m->v[i].c_name;
  }
  if (m->n == m->cap) {
    m->cap = m->cap ? m->cap * 2 : 16;
    m->v = (name_entry_t*)xrealloc(m->v, m->cap * sizeof(name_entry_t));
  }
  char buf[256];
  sanitize(orig, buf, sizeof(buf));
  char full[300];
  snprintf(full, sizeof(full), "%s%s", prefix, buf[0] ? buf : "sym");
  int suffix = 1;
  int unique = 0;
  while (!unique) {
    unique = 1;
    for (size_t j = 0; j < m->n; j++) {
      if (strcmp(m->v[j].c_name, full) == 0) {
        unique = 0;
        break;
      }
    }
    if (!unique) {
      snprintf(full, sizeof(full), "%s%s_%d", prefix, buf[0] ? buf : "sym", suffix++);
    }
  }
  m->v[m->n].orig = xstrdup(orig);
  m->v[m->n].c_name = xstrdup(full);
  m->n++;
  return m->v[m->n - 1].c_name;
}

static int build_data_and_globals(const recvec_t* recs, datavec_t* data, gsymtab_t* g) {
  datavec_init(data, 0);
  gsymtab_init(g);
  for (size_t i = 0; i < recs->n; i++) {
    const record_t* r = &recs->v[i];
    if (r->k != JREC_DIR || !r->d) continue;
    if (strcmp(r->d, "DB") == 0) {
      if (!r->name) {
        fprintf(stderr, "zcc: DB missing name (line %d)\n", r->line);
        return 1;
      }
      size_t cap = 64;
      size_t len = 0;
      uint8_t* buf = (uint8_t*)xalloc(cap);
      for (size_t a = 0; a < r->nargs; a++) {
        const operand_t* op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          const unsigned char* s = (const unsigned char*)op->s;
          while (*s) {
            if (len == cap) {
              cap *= 2;
              buf = (uint8_t*)xrealloc(buf, cap);
            }
            buf[len++] = *s++;
          }
        } else if (op->t == JOP_NUM) {
          if (len == cap) {
            cap *= 2;
            buf = (uint8_t*)xrealloc(buf, cap);
          }
          long v = op->n;
          if (v < 0) v = 0;
          if (v > 255) v &= 0xff;
          buf[len++] = (uint8_t)v;
        } else {
          fprintf(stderr, "zcc: DB arg must be string/num (line %d)\n", r->line);
          free(buf);
          return 1;
        }
      }
      datavec_add(data, r->name, buf, len);
      const data_seg_t* seg = &data->v[data->n - 1];
      if (gsymtab_put(g, r->name, (long)seg->offset, r->line) != 0) {
        free(buf);
        return 1;
      }
      free(buf);
      continue;
    }
    if (strcmp(r->d, "RESB") == 0) {
      if (!r->name || r->nargs != 1 || r->args[0].t != JOP_NUM) {
        fprintf(stderr, "zcc: RESB expects numeric arg (line %d)\n", r->line);
        return 1;
      }
      if (gsymtab_put(g, r->name, data->next_off, r->line) != 0) return 1;
      long v = r->args[0].n;
      if (v < 0) v = 0;
      data->next_off += (uint32_t)v;
      data->next_off = (data->next_off + 3u) & ~3u;
      continue;
    }
    if (strcmp(r->d, "DW") == 0 || strcmp(r->d, "EQU") == 0) {
      if (!r->name || r->nargs != 1 || r->args[0].t != JOP_NUM) {
        fprintf(stderr, "zcc: %s expects numeric arg (line %d)\n", r->d, r->line);
        return 1;
      }
      if (gsymtab_put(g, r->name, r->args[0].n, r->line) != 0) return 1;
      continue;
    }
    if (strcmp(r->d, "STR") == 0) {
      if (!r->name) {
        fprintf(stderr, "zcc: STR missing name (line %d)\n", r->line);
        return 1;
      }
      size_t cap = 64;
      size_t len = 0;
      uint8_t* buf = (uint8_t*)xalloc(cap);
      for (size_t a = 0; a < r->nargs; a++) {
        const operand_t* op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          const unsigned char* s = (const unsigned char*)op->s;
          while (*s) {
            if (len == cap) {
              cap *= 2;
              buf = (uint8_t*)xrealloc(buf, cap);
            }
            buf[len++] = *s++;
          }
        } else if (op->t == JOP_NUM) {
          if (len == cap) {
            cap *= 2;
            buf = (uint8_t*)xrealloc(buf, cap);
          }
          long v = op->n;
          if (v < 0) v = 0;
          if (v > 255) v &= 0xff;
          buf[len++] = (uint8_t)v;
        } else {
          fprintf(stderr, "zcc: STR arg must be string/num (line %d)\n", r->line);
          free(buf);
          return 1;
        }
      }
      datavec_add(data, r->name, buf, len);
      const data_seg_t* seg = &data->v[data->n - 1];
      if (gsymtab_put(g, r->name, (long)seg->offset, r->line) != 0) {
        free(buf);
        return 1;
      }
      char len_name[256];
      snprintf(len_name, sizeof(len_name), "%s_len", r->name);
      if (gsymtab_put(g, len_name, (long)len, r->line) != 0) {
        free(buf);
        return 1;
      }
      free(buf);
      continue;
    }
    if (strcmp(r->d, "PUBLIC") == 0 || strcmp(r->d, "EXTERN") == 0) {
      continue;
    }
    fprintf(stderr, "zcc: unsupported directive %s (line %d)\n", r->d, r->line);
    return 1;
  }
  return 0;
}

static int is_register(const char* s) {
  return s && (
      strcmp(s, "HL") == 0 || strcmp(s, "DE") == 0 || strcmp(s, "A") == 0 ||
      strcmp(s, "BC") == 0 || strcmp(s, "IX") == 0);
}

static const char* reg_field(const char* s) {
  if (strcmp(s, "HL") == 0) return "state.HL";
  if (strcmp(s, "DE") == 0) return "state.DE";
  if (strcmp(s, "A") == 0) return "state.A";
  if (strcmp(s, "BC") == 0) return "state.BC";
  if (strcmp(s, "IX") == 0) return "state.IX";
  return NULL;
}

static int operand_value(const operand_t* op, const gsymtab_t* g, long* out) {
  if (op->t == JOP_NUM) {
    *out = op->n;
    return 0;
  }
  if (op->t == JOP_SYM) {
    long v = 0;
    if (!gsymtab_get(g, op->s, &v)) {
      fprintf(stderr, "zcc: unknown symbol %s\n", op->s);
      return 1;
    }
    *out = v;
    return 0;
  }
  fprintf(stderr, "zcc: operand must be numeric or symbol\n");
  return 1;
}

static size_t label_pc_or_die(const labelvec_t* labels, const char* name, size_t ninstr) {
  (void)ninstr;
  size_t pc = 0;
  if (!labelvec_get(labels, name, &pc)) {
    fprintf(stderr, "zcc: unknown label %s\n", name);
    exit(1);
  }
  return pc;
}

static void emit_data_segments(const datavec_t* data, FILE* out) {
  for (size_t i = 0; i < data->n; i++) {
    const data_seg_t* seg = &data->v[i];
    fprintf(out, "static const uint8_t zprog_seg_%zu[] = {", i);
    for (size_t b = 0; b < seg->len; b++) {
      if (b % 16 == 0) fprintf(out, "\n  ");
      fprintf(out, "0x%02x", seg->bytes[b]);
      if (b + 1 != seg->len) fprintf(out, ", ");
    }
    if (seg->len) fprintf(out, "\n");
    fprintf(out, "};\n\n");
  }
}

static void emit_mem_init(const datavec_t* data, FILE* out) {
  fprintf(out, "static void zprog_state_init(struct zprog_state* state) {\n");
  fprintf(out, "  memset(state, 0, sizeof(*state));\n");
  for (size_t i = 0; i < data->n; i++) {
    const data_seg_t* seg = &data->v[i];
    if (seg->len) {
      fprintf(out, "  memcpy(state->mem + %u, zprog_seg_%zu, %zu);\n",
             seg->offset, i, seg->len);
    }
  }
  fprintf(out, "}\n\n");
}

static void emit_symbol_enum(const gsymtab_t* g, namemap_t* map, FILE* out) {
  if (g->n == 0) return;
  fprintf(out, "enum {\n");
  for (size_t i = 0; i < g->n; i++) {
    const char* cname = namemap_get(map, g->v[i].name, "ZSYM_");
    fprintf(out, "  %s = %ld,%s\n", cname, g->v[i].val, i + 1 == g->n ? "" : "");
  }
  fprintf(out, "};\n\n");
}

static const char* cond_name(const char* s) {
  if (!s) return NULL;
  if (strcasecmp(s, "eq") == 0) return "==";
  if (strcasecmp(s, "ne") == 0) return "!=";
  if (strcasecmp(s, "lt") == 0) return "<";
  if (strcasecmp(s, "le") == 0) return "<=";
  if (strcasecmp(s, "gt") == 0) return ">";
  if (strcasecmp(s, "ge") == 0) return ">=";
  return NULL;
}

static int emit_instruction(const record_t* r,
                            size_t pc,
                            size_t next_pc,
                            const labelvec_t* labels,
                            const gsymtab_t* g,
                            namemap_t* symmap,
                            FILE* out) {
  (void)symmap;
  const char* m = r->m ? r->m : "";
  fprintf(out, "    case %zu: { /* line %d %s */\n", pc, r->line, m);
  if (strcmp(m, "LD") == 0) {
    if (r->nops != 2) {
      fprintf(stderr, "zcc: LD expects 2 operands (line %d)\n", r->line);
      return 1;
    }
    const operand_t* dst = &r->ops[0];
    const operand_t* src = &r->ops[1];
    if (dst->t == JOP_SYM && is_register(dst->s)) {
      const char* dst_field = reg_field(dst->s);
      if (!dst_field) {
        fprintf(stderr, "zcc: unknown register %s (line %d)\n", dst->s, r->line);
        return 1;
      }
      if (src->t == JOP_NUM || (src->t == JOP_SYM && !is_register(src->s))) {
        long v = 0;
        if (operand_value(src, g, &v) != 0) return 1;
        fprintf(out, "      %s = %ld;\n", dst_field, v);
      } else if (src->t == JOP_SYM && is_register(src->s)) {
        const char* src_field = reg_field(src->s);
        if (!src_field) {
          fprintf(stderr, "zcc: unknown register %s (line %d)\n", src->s, r->line);
          return 1;
        }
        fprintf(out, "      %s = %s;\n", dst_field, src_field);
      } else if (src->t == JOP_MEM && src->s && strcmp(src->s, "HL") == 0 && strcmp(dst->s, "A") == 0) {
        fprintf(out, "      if (!zprog_bounds(state.HL, 1)) return ZPROG_TRAP_OOB;\n");
        fprintf(out, "      state.A = state.mem[state.HL];\n");
      } else {
        fprintf(stderr, "zcc: unsupported LD form (line %d)\n", r->line);
        return 1;
      }
      fprintf(out, "      pc = %zu;\n", next_pc);
      fprintf(out, "      break;\n    }\n");
      return 0;
    }
    if (dst->t == JOP_MEM && dst->s && strcmp(dst->s, "HL") == 0) {
      if (src->t == JOP_SYM && strcmp(src->s, "A") == 0) {
        fprintf(out, "      if (!zprog_bounds(state.HL, 1)) return ZPROG_TRAP_OOB;\n");
        fprintf(out, "      state.mem[state.HL] = (uint8_t)(state.A & 0xff);\n");
        fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
        return 0;
      }
      fprintf(stderr, "zcc: LD (HL),src supports only register A (line %d)\n", r->line);
      return 1;
    }
    fprintf(stderr, "zcc: unsupported LD operands (line %d)\n", r->line);
    return 1;
  }
  if (strcmp(m, "INC") == 0 || strcmp(m, "DEC") == 0) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !is_register(r->ops[0].s)) {
      fprintf(stderr, "zcc: %s expects register operand (line %d)\n", m, r->line);
      return 1;
    }
    const char* field = reg_field(r->ops[0].s);
    fprintf(out, "      %s %s= 1;\n", field, strcmp(m, "INC") == 0 ? "+" : "-");
    fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
    return 0;
  }
  if (strcmp(m, "ADD") == 0 || strcmp(m, "SUB") == 0) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || strcmp(r->ops[0].s, "HL") != 0) {
      fprintf(stderr, "zcc: %s supports only HL destination (line %d)\n", m, r->line);
      return 1;
    }
    const operand_t* rhs = &r->ops[1];
    const char* op = strcmp(m, "ADD") == 0 ? "+" : "-";
    if (rhs->t == JOP_NUM) {
      fprintf(out, "      state.HL %s= %ld;\n", op, rhs->n);
    } else if (rhs->t == JOP_SYM && is_register(rhs->s) && strcmp(rhs->s, "DE") == 0) {
      fprintf(out, "      state.HL %s= state.DE;\n", op);
    } else if (rhs->t == JOP_SYM && !is_register(rhs->s)) {
      long v = 0;
      if (operand_value(rhs, g, &v) != 0) return 1;
      fprintf(out, "      state.HL %s= %ld;\n", op, v);
    } else {
      fprintf(stderr, "zcc: %s unsupported operand (line %d)\n", m, r->line);
      return 1;
    }
    fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
    return 0;
  }
  if (strcmp(m, "CP") == 0) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || strcmp(r->ops[0].s, "HL") != 0) {
      fprintf(stderr, "zcc: CP expects HL as lhs (line %d)\n", r->line);
      return 1;
    }
    const operand_t* rhs = &r->ops[1];
    if (rhs->t == JOP_NUM) {
      fprintf(out, "      state.cmp = state.HL - %ld;\n", rhs->n);
    } else if (rhs->t == JOP_SYM && is_register(rhs->s)) {
      const char* src = reg_field(rhs->s);
      fprintf(out, "      state.cmp = state.HL - %s;\n", src);
    } else {
      long v = 0;
      if (operand_value(rhs, g, &v) != 0) return 1;
      fprintf(out, "      state.cmp = state.HL - %ld;\n", v);
    }
    fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
    return 0;
  }
  if (strcmp(m, "JR") == 0) {
    if (r->nops == 1) {
      const operand_t* target = &r->ops[0];
      if (target->t != JOP_SYM) {
        fprintf(stderr, "zcc: JR expects label symbol (line %d)\n", r->line);
        return 1;
      }
      size_t pc_target = label_pc_or_die(labels, target->s, next_pc);
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", pc_target);
      return 0;
    }
    if (r->nops == 2) {
      const operand_t* cond = &r->ops[0];
      const operand_t* target = &r->ops[1];
      if (cond->t != JOP_SYM || target->t != JOP_SYM) {
        fprintf(stderr, "zcc: JR cond,label expects symbols (line %d)\n", r->line);
        return 1;
      }
      const char* cmp = cond_name(cond->s);
      if (!cmp) {
        fprintf(stderr, "zcc: unknown JR condition %s (line %d)\n", cond->s, r->line);
        return 1;
      }
      size_t pc_target = label_pc_or_die(labels, target->s, next_pc);
      fprintf(out, "      if (state.cmp %s 0) { pc = %zu; break; }\n", cmp, pc_target);
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    fprintf(stderr, "zcc: JR expects 1 or 2 operands (line %d)\n", r->line);
    return 1;
  }
  if (strcmp(m, "CALL") == 0) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      fprintf(stderr, "zcc: CALL expects symbol (line %d)\n", r->line);
      return 1;
    }
    const char* sym = r->ops[0].s;
    if (strcmp(sym, "_in") == 0) {
      fprintf(out, "      if (!in_fn) return ZPROG_TRAP_HOST_MISSING;\n");
      fprintf(out, "      if (!zprog_bounds(state.HL, state.DE)) return ZPROG_TRAP_OOB;\n");
      fprintf(out, "      int32_t n = in_fn(host_ctx, req_handle, state.mem, ZPROG_MEM_CAP, state.HL, state.DE);\n");
      fprintf(out, "      if (n < 0) return ZPROG_TRAP_HOST_FAIL;\n");
      fprintf(out, "      state.HL = n;\n");
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    if (strcmp(sym, "_out") == 0) {
      fprintf(out, "      if (!out_fn) return ZPROG_TRAP_HOST_MISSING;\n");
      fprintf(out, "      if (!zprog_bounds(state.HL, state.DE)) return ZPROG_TRAP_OOB;\n");
      fprintf(out, "      if (out_fn(host_ctx, res_handle, state.mem, ZPROG_MEM_CAP, state.HL, state.DE) < 0) return ZPROG_TRAP_HOST_FAIL;\n");
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    if (strcmp(sym, "_end") == 0) {
      fprintf(out, "      if (!end_fn) return ZPROG_TRAP_HOST_MISSING;\n");
      fprintf(out, "      int32_t end_handle = state.HL >= 0 ? state.HL : res_handle;\n");
      fprintf(out, "      end_fn(host_ctx, end_handle);\n");
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    if (strcmp(sym, "_log") == 0) {
      fprintf(out, "      if (!log_fn) return ZPROG_TRAP_HOST_MISSING;\n");
      fprintf(out, "      if (!zprog_bounds(state.HL, state.DE)) return ZPROG_TRAP_OOB;\n");
      fprintf(out, "      if (!zprog_bounds(state.BC, state.IX)) return ZPROG_TRAP_OOB;\n");
      fprintf(out, "      log_fn(host_ctx, state.mem, ZPROG_MEM_CAP, state.HL, state.DE, state.BC, state.IX);\n");
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    if (strcmp(sym, "_ctl") == 0) {
      fprintf(out, "      if (!ctl_fn) return ZPROG_TRAP_HOST_MISSING;\n");
      fprintf(out, "      if (!zprog_bounds(state.HL, state.DE)) return ZPROG_TRAP_OOB;\n");
      fprintf(out, "      if (!zprog_bounds(state.BC, state.IX)) return ZPROG_TRAP_OOB;\n");
      fprintf(out, "      int32_t ctl_written = ctl_fn(host_ctx, ZCAP_CTL, state.mem, ZPROG_MEM_CAP, state.HL, state.DE, state.BC, state.IX, state.A);\n");
      fprintf(out, "      if (ctl_written < 0) return ZPROG_TRAP_HOST_FAIL;\n");
      fprintf(out, "      state.HL = ctl_written;\n");
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    if (strcmp(sym, "_alloc") == 0) {
      fprintf(out, "      if (!sys || !sys->alloc_fn) return ZPROG_TRAP_ALLOC;\n");
      fprintf(out, "      int32_t ptr = sys->alloc_fn(sys->ctx, state.mem, ZPROG_MEM_CAP, state.HL);\n");
      fprintf(out, "      if (ptr < 0) return ZPROG_TRAP_ALLOC;\n");
      fprintf(out, "      state.HL = ptr;\n");
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    if (strcmp(sym, "_free") == 0) {
      fprintf(out, "      if (!sys || !sys->free_fn) return ZPROG_TRAP_ALLOC;\n");
      fprintf(out, "      sys->free_fn(sys->ctx, state.mem, ZPROG_MEM_CAP, state.HL);\n");
      fprintf(out, "      pc = %zu;\n      break;\n    }\n", next_pc);
      return 0;
    }
    size_t pc_target = label_pc_or_die(labels, sym, next_pc);
    fprintf(out, "      if (sp >= ZPROG_RET_STACK_CAP) return ZPROG_TRAP_CALL_DEPTH;\n");
    fprintf(out, "      ret_stack[sp++] = %zu;\n", next_pc);
    fprintf(out, "      pc = %zu;\n      break;\n    }\n", pc_target);
    return 0;
  }
  if (strcmp(m, "RET") == 0) {
    fprintf(out, "      if (sp == 0) return 0;\n");
    fprintf(out, "      pc = ret_stack[--sp];\n      break;\n    }\n");
    return 0;
  }
  fprintf(stderr, "zcc: unsupported instruction %s (line %d)\n", m, r->line);
  return 1;
}

int emit_c_module(const recvec_t* recs, unsigned heap_slack, FILE* out) {
  datavec_t data;
  gsymtab_t g;
  if (build_data_and_globals(recs, &data, &g) != 0) {
    datavec_free(&data);
    gsymtab_free(&g);
    return 1;
  }

  labelvec_t labels;
  labelvec_init(&labels);
  size_t ninstr = 0;
  for (size_t i = 0; i < recs->n; i++) {
    const record_t* r = &recs->v[i];
    if (r->k == JREC_LABEL && r->label) {
      labelvec_put(&labels, r->label, ninstr);
    }
    if (r->k == JREC_INSTR) {
      ninstr++;
    }
  }
  instrvec_t instrs;
  instrs.n = ninstr;
  instrs.v = (instr_t*)xalloc(ninstr * sizeof(instr_t));
  size_t idx = 0;
  for (size_t i = 0; i < recs->n; i++) {
    const record_t* r = &recs->v[i];
    if (r->k == JREC_INSTR) {
      instrs.v[idx].rec = r;
      instrs.v[idx].rec_index = i;
      idx++;
    }
  }

  uint32_t mem_cap = data.next_off + heap_slack;
  if (mem_cap == 0) mem_cap = heap_slack;

  fprintf(out, "/* Autogenerated by zcc. Do not edit. */\n");
  fprintf(out, "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n#include \"zprog_rt.h\"\n\n");
  fprintf(out, "#define ZPROG_MEM_CAP %u\n", mem_cap);
  fprintf(out, "#define ZPROG_RET_STACK_CAP 256\n");
  fprintf(out, "enum {\n  ZPROG_TRAP_OOB = 1,\n  ZPROG_TRAP_CALL_DEPTH = 2,\n  ZPROG_TRAP_HOST_MISSING = 3,\n  ZPROG_TRAP_HOST_FAIL = 4,\n  ZPROG_TRAP_ALLOC = 5\n};\n\n");
  fprintf(out, "static inline int zprog_bounds(int32_t addr, int32_t len) {\n");
  fprintf(out, "  if (addr < 0 || len < 0) return 0;\n");
  fprintf(out, "  size_t end = (size_t)addr + (size_t)len;\n");
  fprintf(out, "  return end <= ZPROG_MEM_CAP;\n}\n\n");
  fprintf(out, "enum { ZPROG_HEAP_BASE = %u };\n\n", data.next_off);
  fprintf(out, "static const uint32_t ZPROG_HEAP_BASE_CONST = ZPROG_HEAP_BASE;\n");
  fprintf(out, "uint32_t zprog_heap_base_value(void) { return ZPROG_HEAP_BASE_CONST; }\n\n");
  fprintf(out, "struct zprog_state {\n  int32_t HL;\n  int32_t DE;\n  int32_t A;\n  int32_t BC;\n  int32_t IX;\n  int32_t cmp;\n  uint8_t mem[ZPROG_MEM_CAP];\n};\n\n");
  emit_data_segments(&data, out);
  emit_mem_init(&data, out);
  namemap_t symmap;
  namemap_init(&symmap);
  emit_symbol_enum(&g, &symmap, out);

  fprintf(out, "int lembeh_handle(int32_t req_handle,\n                  int32_t res_handle,\n                  zprog_in_fn in_fn,\n                  zprog_out_fn out_fn,\n                  zprog_end_fn end_fn,\n                  zprog_log_fn log_fn,\n                  zprog_ctl_fn ctl_fn,\n                  void* host_ctx,\n                  const struct zprog_sys* sys) {\n");
  fprintf(out, "  (void)out_fn; /* may be unused */\n");
  fprintf(out, "  (void)end_fn;\n");
  fprintf(out, "  (void)log_fn;\n");
  fprintf(out, "  (void)ctl_fn;\n");
  fprintf(out, "  struct zprog_state state;\n  zprog_state_init(&state);\n");
  fprintf(out, "  int32_t pc = 0;\n  int32_t ret_stack[ZPROG_RET_STACK_CAP];\n  int32_t sp = 0;\n  for (;;) {\n    switch (pc) {\n");

  for (size_t i = 0; i < instrs.n; i++) {
    size_t next_pc = (i + 1 < instrs.n) ? i + 1 : instrs.n;
    if (emit_instruction(instrs.v[i].rec, i, next_pc, &labels, &g, &symmap, out) != 0) {
      labelvec_free(&labels);
      datavec_free(&data);
      gsymtab_free(&g);
      namemap_free(&symmap);
      free(instrs.v);
      return 1;
    }
  }

  fprintf(out, "      default: return 0;\n    }\n  }\n}\n");

  labelvec_free(&labels);
  datavec_free(&data);
  gsymtab_free(&g);
  namemap_free(&symmap);
  free(instrs.v);
  return 0;
}
