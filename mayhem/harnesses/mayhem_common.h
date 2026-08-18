/*
 * mayhem/harnesses/mayhem_common.h -- shared bounding infrastructure for the
 * mquickjs fuzz harnesses (fuzz_parse.c, fuzz_eval.c).
 *
 * mquickjs is a full JS lexer+parser+bytecode-compiler+interpreter+GC fed
 * directly with untrusted bytes. This integration bounds each input with
 * TWO deterministic, work-counting limits -- no timers, alarms, signals or
 * wall-clock/CPU-time checks anywhere in the harness (hangs are the
 * runner's job: libFuzzer's -timeout / Mayhem's per-test timeout):
 *
 *   1. A FIXED-SIZE memory arena (MAYHEM_MEM_SIZE, passed as JS_NewContext's
 *      mem_size). Unlike a GC'd heap that grows until the OS kills the
 *      process, mquickjs's allocator is a two-ended bump arena inside this
 *      one fixed buffer -- every allocation (including native builtins that
 *      materialize a huge string/array, e.g. String.prototype.repeat,
 *      Array.prototype.join) that would exceed it throws a catchable
 *      JS_ThrowOutOfMemory() *immediately*, not after doing the work. This
 *      is also mquickjs's only memory-bounding knob -- there is no separate
 *      JS_SetMemoryLimit() in this API (unlike full QuickJS/QuickJS-NG).
 *      The arena also limits how much data a single native builtin call
 *      (which (2) cannot interrupt mid-call) can work on.
 *
 *   2. A deterministic STEP budget via mquickjs's own interrupt hook,
 *      JS_SetInterruptHandler(). The engine decrements ctx->interrupt_counter
 *      at every interpreter poll point -- function calls, backward/
 *      conditional jumps in the bytecode VM, and RegExp backtracking steps
 *      (mquickjs.c: POLL_INTERRUPT / LRE_POLL_INTERRUPT) -- and calls the
 *      handler once every JS_INTERRUPT_COUNTER_INIT (10000) polls. The
 *      handler below simply COUNTS those invocations and asks the engine to
 *      stop once MAYHEM_INTERRUPT_BUDGET is exceeded; the engine then throws
 *      its normal (uncatchable) "InternalError: interrupted" exception and
 *      JS_Eval returns JS_EXCEPTION. This bounds while(1){}, runaway loops
 *      and ReDoS backtracking by an amount of WORK, so the verdict for a
 *      given input is the same on every machine and under any load.
 *
 * NO HOST ACCESS: mayhem_stdlib.c's glue functions (js_print, js_load, ...)
 * are deliberately neutered no-ops -- no stdout writes, no filesystem reads,
 * no require()-equivalent. See its header comment for the full rationale.
 */
#ifndef MAYHEM_COMMON_H
#define MAYHEM_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include "mquickjs.h"

/* The stdlib table is generated at build time (mqjs_stdlib -> mqjs_stdlib.h)
   and instantiated once, in mayhem_stdlib.c; every harness TU links against
   this single definition. */
extern const JSSTDLibraryDef js_stdlib;

/* ---- bounding parameters (deterministic; see header above) ---- */
#define MAYHEM_MEM_SIZE          ((size_t)64 << 20)  /* 64 MB fixed arena */
/* Max interrupt-handler invocations per input; each one is
   JS_INTERRUPT_COUNTER_INIT (10000) interpreter poll points, so this is
   500k calls/jumps/backtracking steps: twice what the most demanding
   shipped seed / server-side corpus input needs (24, mandelbrot.js, which
   does ~10 ms of work per unit under ASan+UBSan). while(1){} uses it up in
   ~25 ms. */
#define MAYHEM_INTERRUPT_BUDGET  50

/* Resets the per-input step budget; call immediately before
   JS_Parse/JS_Run/JS_Eval. */
void mayhem_reset_budget(void);

/* JSInterruptHandler passed to JS_SetInterruptHandler(): counts its own
   invocations and returns non-zero (abort execution with the engine's
   normal "interrupted" exception) once more than MAYHEM_INTERRUPT_BUDGET
   have happened since the last mayhem_reset_budget() call. */
int mayhem_interrupt_handler(JSContext *ctx, void *opaque);

#endif /* MAYHEM_COMMON_H */
