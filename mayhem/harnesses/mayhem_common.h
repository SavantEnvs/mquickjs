/*
 * mayhem/harnesses/mayhem_common.h -- shared bounding infrastructure for the
 * mquickjs fuzz harnesses (fuzz_parse.c, fuzz_eval.c).
 *
 * mquickjs is a full JS lexer+parser+bytecode-compiler+interpreter+GC fed
 * directly with untrusted bytes. Per docs/netnew-worker-prompt.md SS6b (a
 * language-level interrupt does NOT bound native code -- proven on goja),
 * this integration layers THREE independent bounds, verified empirically
 * against this exact engine (see mayhem_stdlib.c's header comment for the
 * numbers):
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
 *
 *   2. JS_SetInterruptHandler(), checked between bytecode instructions
 *      (confirmed by reading mquickjs.c: ctx->interrupt_counter is
 *      decremented in the opcode dispatch loop). This bounds any JS-level
 *      loop -- while(1){}, a for-loop doing string concatenation, even
 *      RegExp backtracking (verified: js_regexp_exec's matcher is itself
 *      interruptible) -- to the soft deadline below.
 *
 *   3. A HARD, process-level watchdog built on a POSIX per-process
 *      timer_create(CLOCK_MONOTONIC) delivering a REAL-TIME signal
 *      (SIGRTMIN+5) -> _exit(70). Per SS6b, (2) is NOT sufficient on its
 *      own: a SINGLE native-builtin call (e.g. a large-but-arena-fitting
 *      String.prototype.repeat()) runs to completion as one uninterruptible
 *      C function -- interrupt_counter is never consulted mid-call.
 *      Empirically, a 50MB repeat() (fits under a 64MB arena) took ~700ms
 *      of *uninterrupted* wall time before the next opcode-boundary check
 *      could even fire. The watchdog is armed BEFORE calling into
 *      JS_Parse/JS_Run/JS_Eval and disarmed immediately after, so a wedged
 *      call converts into a fast, bounded, libFuzzer-catchable process exit
 *      instead of stalling the whole campaign.
 *
 *      It deliberately does NOT use alarm()/setitimer(ITIMER_REAL)/SIGALRM:
 *      libFuzzer OWNS those for its own -timeout enforcement, so a harness
 *      alarm() is silently swallowed AND permanently disables libFuzzer's
 *      own timeout detection (docs/netnew-worker-prompt.md SS6b). An
 *      independent CLOCK_MONOTONIC timer on a real-time signal collides with
 *      neither: our per-input hard bound fires AND libFuzzer's own timeout
 *      reporting stays intact.
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

/* ---- bounding parameters (empirically justified, see header above) ---- */
#define MAYHEM_MEM_SIZE          ((size_t)64 << 20)  /* 64 MB fixed arena */
#define MAYHEM_SOFT_DEADLINE_MS  500                 /* JS interrupt handler */
#define MAYHEM_HARD_DEADLINE_S   3                    /* alarm() hard exit */

/* Installs the SIGALRM handler once (call from LLVMFuzzerInitialize). */
void mayhem_install_watchdog(void);

/* Arms the hard deadline and resets the soft-deadline clock; call
   immediately before JS_Parse/JS_Run/JS_Eval. */
void mayhem_arm_deadline(void);

/* Cancels the pending alarm(); call immediately after the call returns. */
void mayhem_disarm_deadline(void);

/* JSInterruptHandler passed to JS_SetInterruptHandler(): returns non-zero
   (abort execution) once MAYHEM_SOFT_DEADLINE_MS has elapsed since the last
   mayhem_arm_deadline() call. */
int mayhem_interrupt_handler(JSContext *ctx, void *opaque);

#endif /* MAYHEM_COMMON_H */
