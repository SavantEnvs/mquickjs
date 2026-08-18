#!/usr/bin/env bash
#
# mayhem/test.sh -- RUN mquickjs's own built-in test suite (tests/*.js, 419
# assert() calls total, built by mayhem/build.sh via upstream's real
# Makefile, normal flags) through the CLEAN oracle `mqjs` binary, PLUS
# direct KAT probes against the same binary's stdout, and emit one CTRF
# summary. exit 0 iff nothing failed.
#
# ── Why there are TWO layers, and why layer 2 is the LOAD-BEARING one ────
#
# verify-repo's anti-reward-hack check LD_PRELOADs a shim whose constructor
# `_exit(0)`s every executable NOT under a system path -- our built
# ./mqjs (repo root, i.e. /mayhem/mqjs in the image) is NOT spared, so a
# neutered mqjs exits at process start, before main() runs, before a
# single assert() executes, before it prints anything.
#
#  1) `mqjs -I <test1.js> -I <test2.js> ... -e 'print(MARKER)'`: chains all
#     of mquickjs's own tests/*.js suites via -I (mqjs.c: each -I is
#     eval_file()'d in order, ABORTING with a nonzero exit on the FIRST
#     uncaught exception -- and every failed assert() in these files throws
#     -- before any later -I or the trailing -e ever runs), then, only if
#     ALL 419 assert() calls across test_closure/test_language/test_loop/
#     test_builtin.js passed, evaluates -e to print a fixed marker string.
#     A GENUINELY NEUTERED mqjs produces ZERO stdout (killed before print()
#     ever runs) -- so this is already sabotage-proof on its own merits
#     (unlike a bare exit-code check: sabotage exits 0, and legitimate
#     "all tests passed" ALSO exits 0, so exit code alone cannot
#     distinguish them -- SS4 of the port brief. Requiring the marker STRING
#     in stdout is what actually distinguishes them).
#
#  2) Direct KAT probes: four independent `mqjs -e '...'` invocations, each
#     printing one exactly-known value (arithmetic + Number.toString,
#     String.prototype.repeat, JSON.stringify, and a RegExp capture group
#     via String.prototype.match) -- grep -qxF'd against the literal
#     expected string. A neutered mqjs prints nothing, so every one of
#     these is an UNCONDITIONAL, hard failure (never a `[ -f ... ]`-guarded
#     skip) under sabotage. These touch four different engine subsystems
#     (arithmetic/number-formatting, string builtins, JSON, RegExp) so a
#     narrower form of "test.sh always passes" (e.g. only the marker
#     check surviving via some other side channel) cannot slip through
#     unnoticed either.
#
# This script only RUNS things; mayhem/build.sh did the building.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

MQJS_BIN="$SRC/mqjs"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$MQJS_BIN" ]; then
  echo "missing $MQJS_BIN -- run mayhem/build.sh first" >&2
  emit_ctrf "mqjs-selftest+kat" 0 1 0
  exit 2
fi

PASSED=0
FAILED=0

# ── 1) mquickjs's own built-in suite, chained, + a marker printed only on full success ──
MARKER="MQUICKJS_ALL_TESTS_PASSED_$$"
echo "=== running: mqjs -I tests/test_closure.js -I tests/test_language.js -I tests/test_loop.js -I tests/test_builtin.js -e print(MARKER) ==="
OUT="$("$MQJS_BIN" -I tests/test_closure.js -I tests/test_language.js -I tests/test_loop.js -I tests/test_builtin.js -e "print('$MARKER')" 2>&1)"
rc=$?
printf '%s\n' "$OUT" | tail -20

# Count the real assert() calls in the four suites we just ran, so a partial
# CTRF count reflects reality even though mqjs stops at the FIRST failure
# (upstream's assert() throws, aborting eval_file() immediately -- there is
# no "run everything, tally failures" mode to hook into).
N_ASSERTS=$(( $(grep -c 'assert(' tests/test_closure.js tests/test_language.js tests/test_loop.js tests/test_builtin.js | awk -F: '{s+=$2} END{print s}') ))

if printf '%s\n' "$OUT" | grep -qxF "$MARKER"; then
  echo "mqjs built-in suite: all $N_ASSERTS assert() calls across test_closure/test_language/test_loop/test_builtin.js passed, rc=$rc"
  PASSED=$(( PASSED + N_ASSERTS ))
else
  echo "FAIL: 'mqjs -I ... -e print(MARKER)' did not print the completion marker (neutered, crashed, or a real assertion failed) -- rc=$rc" >&2
  FAILED=$(( FAILED + 1 ))
fi

# ── 2) Direct KAT probes against the SAME oracle binary (load-bearing; see header) ──
kat_probe() {
  # kat_probe <label> <js-expr-passed-to-print()> <expected-stdout-line>
  local label="$1" expr="$2" want="$3" got
  got="$("$MQJS_BIN" -e "print($expr)" 2>/dev/null)"
  if printf '%s\n' "$got" | grep -qxF "$want"; then
    echo "KAT PASS: $label -- print($expr) == '$want'"
    PASSED=$(( PASSED + 1 ))
  else
    echo "KAT FAIL: $label -- print($expr) expected '$want', got '$got'" >&2
    FAILED=$(( FAILED + 1 ))
  fi
}

kat_probe "arithmetic"     "(1+2)*3"                                          "9"
kat_probe "string-repeat"  "'ab'.repeat(3)"                                   "ababab"
kat_probe "json-stringify" "JSON.stringify({a:1,b:[2,3]})"                    '{"a":1,"b":[2,3]}'
kat_probe "regexp-capture" "'xxabbbcxx'.match(/a(b+)c/)[1]"                   "bbb"

echo "=== results: $PASSED passed, $FAILED failed ==="
emit_ctrf "mqjs-selftest+kat" "$PASSED" "$FAILED"
