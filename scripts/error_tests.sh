#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

fail() {
  echo "error_tests: $1" >&2
  exit 1
}

expect_fail_contains() {
  name=$1
  file=$2
  needle=$3
  if "$root/bin/zcc" --output "$root/build/$name.c" < "$file" > "$root/build/$name.out" 2> "$root/build/$name.err"; then
    fail "$name unexpectedly succeeded"
  fi
  if ! grep -q "$needle" "$root/build/$name.err"; then
    echo "--- $name stderr ---" >&2
    cat "$root/build/$name.err" >&2
    fail "$name missing expected error: $needle"
  fi
}

expect_trap() {
  name=$1
  file=$2
  expected=$3
  "$root/bin/zcc" --output "$root/build/$name.c" < "$file" > /dev/null 2>&1 || fail "$name zcc failed"
  cc -I"$root/include" -I"$root/normative" -c "$root/build/$name.c" -o "$root/build/$name.o" || fail "$name compile failed"
  cc -I"$root/include" -I"$root/normative" -c "$root/examples/error_test_host.c" -o "$root/build/$name.host.o" || fail "$name host compile failed"
  cc "$root/build/$name.o" "$root/build/$name.host.o" -o "$root/build/$name.bin" || fail "$name link failed"
  out=$("$root/build/$name.bin" 2>&1 || true)
  if [ "$out" != "$expected" ]; then
    echo "--- $name output ---" >&2
    echo "$out" >&2
    fail "$name expected '$expected'"
  fi
}

expect_fail_contains unknown_label "$root/examples/error_unknown_label.jsonl" "unknown label"
expect_fail_contains unknown_symbol "$root/examples/error_unknown_symbol.jsonl" "unknown symbol"
expect_fail_contains bad_operands "$root/examples/error_bad_operands.jsonl" "supports only HL destination"
expect_fail_contains bad_ir "$root/examples/error_bad_ir.jsonl" "parse error"

expect_trap trap_oob "$root/examples/error_oob.jsonl" "TRAP:1"
expect_trap trap_div0 "$root/examples/error_div0.jsonl" "TRAP:6"
