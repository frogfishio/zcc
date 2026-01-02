/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "emit_c.h"
#include "jsonl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE* out) {
  fprintf(out, "usage: zcc [--version] [--heap-slack=N] [--output=file.c]\n");
}

int main(int argc, char** argv) {
  unsigned heap_slack = 65536u;
  const char* output_file = NULL;
  for (int i = 1; i < argc; i++) {
    const char* arg = argv[i];
    if (strcmp(arg, "--version") == 0) {
      printf("zcc 1.0.0\n");
      return 0;
    }
    if (strcmp(arg, "--output") == 0) {
      if (i + 1 >= argc) {
        usage(stderr);
        return 2;
      }
      output_file = argv[++i];
      continue;
    }
    if (strncmp(arg, "--output=", 9) == 0) {
      output_file = arg + 9;
      continue;
    }
    if (strncmp(arg, "--heap-slack=", 13) == 0) {
      const char* val = arg + 13;
      char* end = NULL;
      long v = strtol(val, &end, 10);
      if (!val[0] || *end || v < 0) {
        fprintf(stderr, "zcc: invalid heap slack: %s\n", val);
        return 2;
      }
      heap_slack = (unsigned)v;
      continue;
    }
    usage(stderr);
    return 2;
  }

  recvec_t recs;
  recvec_init(&recs);

  char* line = NULL;
  size_t cap = 0;
  ssize_t nread;

  while ((nread = getline(&line, &cap, stdin)) != -1) {
    char* p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;
    record_t r;
    int rc = parse_jsonl_record(p, &r);
    if (rc != 0) {
      fprintf(stderr, "zcc: JSONL parse error (%d): %s\n", rc, p);
      free(line);
      recvec_free(&recs);
      return 2;
    }
    recvec_push(&recs, r);
  }
  free(line);

  FILE* out = stdout;
  if (output_file) {
    out = fopen(output_file, "w");
    if (!out) {
      perror("zcc: fopen");
      recvec_free(&recs);
      return 2;
    }
  }

  int rc = emit_c_module(&recs, heap_slack, out);
  recvec_free(&recs);
  if (out != stdout) fclose(out);
  return rc;
}
