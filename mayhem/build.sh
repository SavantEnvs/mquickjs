#!/usr/bin/env bash
#
# mayhem/build.sh -- build two libFuzzer harnesses over mquickjs (Micro
# QuickJS)'s JS engine (+ standalone reproducers), AND a SEPARATE, normal-
# flags build of upstream's own `mqjs` CLI for mayhem/test.sh to run its
# real tests/*.js suite (419 assert() calls) + direct KAT probes against.
#
#   fuzz_parse -- JS_Parse() only: lexer + recursive-descent parser +
#                 bytecode-compiler stack-size pass, WITHOUT ever running
#                 the compiled bytecode.
#   fuzz_eval  -- JS_Eval() == JS_Parse() + JS_Run(): the deep target,
#                 driving the bytecode VM, GC, and the whole stdlib
#                 (Object/Array/String/Number/Math/JSON/RegExp/Date/
#                 TypedArray/...).
#
# Both harnesses (mayhem/harnesses/fuzz_{parse,eval}.c) share
# mayhem/harnesses/mayhem_stdlib.c, which supplies neutered (no I/O, no
# filesystem, no real event loop) host-glue for the 8 external C symbols
# mquickjs's generated stdlib table references by name (js_print, js_gc,
# js_load, js_setTimeout, js_clearTimeout, js_performance_now, js_date_now,
# js_date_constructor -- see that file's header comment for how this was
# determined empirically), and the interrupt-handler + hard-watchdog
# bounding helpers documented in mayhem/harnesses/mayhem_common.h.
#
# ---- mquickjs's two-stage build (why step 1 runs first) ----
# Upstream's own Makefile builds `mqjs_stdlib` -- a HOST tool compiled from
# mqjs_stdlib.c + mquickjs_build.c -- and RUNS it (twice: plain, and with
# -a) to *generate* mqjs_stdlib.h and mquickjs_atom.h, which mqjs.c and
# mquickjs.c respectively #include. There is no way to get those generated
# headers other than running that tool. `make mqjs` below does the whole
# chain for us AND is exactly upstream's own unmodified, dependency-free,
# non-sanitized build -- so it doubles as this integration's CLEAN oracle
# build (mayhem/test.sh runs the resulting ./mqjs) while incidentally
# producing the two generated headers our SANITIZED build (step 2) reuses
# via -I"$SRC". `make` writes its own objects (mqjs.o, mquickjs.o, ...) and
# the `mqjs`/`mqjs_stdlib` binaries directly at the repo root ($SRC) --
# that coexists fine with the sanitized build's separate mayhem-build/
# directory (same idea as xdelta3's/qcbor's dual-build pattern), and `make`
# is naturally idempotent (mtime-based), which is what makes the air-gapped
# re-run (SPEC SS6.5) trivial for this half.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"

# mquickjs's tagged-JSValue representation intentionally left-shifts signed
# ints to build the tagged 31-bit integer encoding (JS_NewShortInt() in
# mquickjs.c: `JS_TAG_INT + (val << 1)`), which fires -fsanitize=shift-base
# ("left shift of negative value") on literally every negative JS integer
# value the engine ever creates -- confirmed empirically: a 20s fuzz-smoke
# of fuzz_eval aborted on essentially the FIRST real input with this check
# alone enabled, exploring almost nothing. Separately, JS_NewObjectProtoClass1's
# `offsetof(JSObject, u)` computation (mquickjs.c) fires -fsanitize=null
# ("member access within null pointer") on every single object allocation
# -- i.e. on every run, including the empty-input case -- again with zero
# real coverage gained. Both are classic benign compiler-checker artifacts
# of intentional low-level bit/pointer tricks (see
# docs/netnew-worker-prompt.md SS6b), not real bugs: relax ONLY these two
# specific checks (verified via minimal repro + re-running fuzz-smoke
# clean afterwards for 60s/8860 execs with zero further aborts and healthy
# coverage growth on both targets). ASan and the rest of UBSan (real
# null-pointer DEREFERENCE i.e. -fsanitize=null only guarded the offsetof
# idiom above -- once relaxed, an *actual* wild pointer deref is still
# caught by ASan; integer overflow, OOB, use-after-free, etc.) stay halting.
case "$SANITIZER_FLAGS" in
  *shift-base*) ;;  # already relaxed/mentioned by caller
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=shift-base" ;;
esac
case "$SANITIZER_FLAGS" in
  *"sanitize=null"*) ;;  # already relaxed/mentioned by caller
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=null" ;;
esac
# Always ensure the LIBRARY gets SanitizerCoverage instrumentation, regardless of the base
# image's default or an empty override -- without this, an explicit no-sanitizer build would
# silently produce 0 edges from the engine even though the harness TU itself is instrumented
# via $LIB_FUZZING_ENGINE at the final link.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;  # already present
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
# DWARF <= 3 (SPEC 6.2 item 10): clang-19's plain -g emits DWARF-5; be explicit.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS
: "${SRC:=/mayhem}"
cd "$SRC"

# Flags mquickjs's own Makefile always passes (matched here for the sanitized build too, so FP
# semantics/codegen stay as close as possible to the oracle build -- dtoa.c/libm.c are precise
# float<->string routines where that parity matters).
COMMON_DEFS="-D_GNU_SOURCE -fno-math-errno -fno-trapping-math"

HARNESS_DIR="$SRC/mayhem/harnesses"
BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# ── 1) CLEAN oracle build: upstream's OWN Makefile, NORMAL (non-sanitized, non -gdwarf-3) ──
# flags. Also generates mqjs_stdlib.h + mquickjs_atom.h at $SRC root, reused by step 2.
make -C "$SRC" CC="$CC" HOST_CC="$CC" mqjs -j"$MAYHEM_JOBS"
MQJS_BIN="$SRC/mqjs"
[ -x "$MQJS_BIN" ] || { echo "FATAL: $MQJS_BIN was not produced by 'make mqjs'" >&2; exit 1; }
[ -f "$SRC/mqjs_stdlib.h" ] || { echo "FATAL: mqjs_stdlib.h was not generated by 'make mqjs'" >&2; exit 1; }
[ -f "$SRC/mquickjs_atom.h" ] || { echo "FATAL: mquickjs_atom.h was not generated by 'make mqjs'" >&2; exit 1; }
# mqjs MUST be dynamically linked so verify-repo's LD_PRELOAD sabotage shim can neuter it -- a
# statically-linked oracle binary would survive sabotage and make mayhem/test.sh
# reward-hackable (SPEC SS6.3). Plain clang/gcc link dynamically by default; assert it so a
# toolchain change can't silently flip this and weaken the oracle.
if ! file "$MQJS_BIN" | grep -q 'dynamically linked'; then
  echo "FATAL: $MQJS_BIN is not dynamically linked -- the sabotage check could not neuter it," >&2
  echo "       which would make mayhem/test.sh a reward-hackable oracle." >&2
  file "$MQJS_BIN" >&2
  exit 1
fi
echo "built mqjs (dynamically linked CLI, oracle build)"

# ── 2) SANITIZED build of the engine (mquickjs.c + dtoa.c/libm.c/cutils.c) + harnesses ──
for f in mquickjs dtoa libm cutils; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $COMMON_DEFS -I"$SRC" -c "$SRC/$f.c" -o "$BUILD/${f}_fuzz.o"
done

# Host-glue + js_stdlib table (defined via the generated mqjs_stdlib.h from step 1).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC" -I"$HARNESS_DIR" -c "$HARNESS_DIR/mayhem_stdlib.c" \
    -o "$BUILD/mayhem_stdlib.o"

LIBOBJS="$BUILD/mquickjs_fuzz.o $BUILD/dtoa_fuzz.o $BUILD/libm_fuzz.o $BUILD/cutils_fuzz.o $BUILD/mayhem_stdlib.o"

# Standalone driver object, built once, linked into every harness's -standalone binary.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# ── 3) Build each harness TWICE: libFuzzer target -> /mayhem/<name>, standalone -> /mayhem/<name>-standalone ──
for h in fuzz_parse fuzz_eval; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC" -I"$HARNESS_DIR" \
      "$HARNESS_DIR/$h.c" $LIB_FUZZING_ENGINE $LIBOBJS -lm \
      -o "/mayhem/$h"

  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC" -I"$HARNESS_DIR" \
      "$HARNESS_DIR/$h.c" "$BUILD/standalone_main.o" $LIBOBJS -lm \
      -o "/mayhem/$h-standalone"

  echo "built $h (+ standalone)"
done

echo "build.sh complete:"
ls -la /mayhem/fuzz_parse /mayhem/fuzz_eval \
       /mayhem/fuzz_parse-standalone /mayhem/fuzz_eval-standalone \
       "$MQJS_BIN" 2>&1 || true
