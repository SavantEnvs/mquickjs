/*
 * mayhem/harnesses/fuzz_eval.c -- fuzz mquickjs's full pipeline: parse
 * AND run untrusted JS source through JS_Eval() (== JS_Parse + JS_Run).
 * This is the DEEP target -- it drives the bytecode VM, GC, and the whole
 * built-in standard library (Object/Array/String/Number/Math/JSON/RegExp/
 * Date/TypedArray/...), not just the front end (see fuzz_parse.c for that
 * shallower target).
 *
 * ---- bounding (the load-bearing part of this harness; see
 *      mayhem_common.h for the full design + citations) ----
 *
 * Three independent, empirically-verified bounds, all engaged every call:
 *
 *   1. A fresh, fixed MAYHEM_MEM_SIZE (64MB) arena backs the JSContext --
 *      mquickjs's ONLY memory-limit knob. Verified: "a".repeat(1e9) throws
 *      JS_ThrowOutOfMemory() in <1ms rather than materializing a huge
 *      string, because the allocator can't grow past this fixed buffer.
 *
 *   2. JS_SetInterruptHandler(mayhem_interrupt_handler) -- checked between
 *      bytecode instructions. Verified: while(1){} is interrupted at
 *      ~300ms; a quadratic `for(...) s += 'x'` loop of 2,000,000
 *      iterations (which hangs past 5s with NO interrupt handler
 *      installed, confirmed independently) is likewise interrupted at
 *      ~317ms once the handler IS installed, because the loop body itself
 *      is bytecode the VM dispatches (and therefore checks) every
 *      iteration; even RegExp backtracking (`/^(a+)+$/.test(...)` against
 *      a classic ReDoS string) is interrupted the same way.
 *
 *   3. A HARD process-level watchdog (timer_create(CLOCK_MONOTONIC) on a
 *      real-time signal SIGRTMIN+5 -> _exit(70), armed immediately around
 *      the JS_Eval call; NOT alarm()/SIGALRM, which libFuzzer owns -- see
 *      mayhem_common.h). This exists because (2) is
 *      NOT sufficient by itself, exactly as goja's integration documented
 *      for a different engine (docs/netnew-worker-prompt.md SS6b): a
 *      SINGLE native-builtin call is not interrupted mid-call.
 *      Empirically isolated here: 'a'.repeat(50000000) -- 50MB, comfortably
 *      inside the 64MB arena, so no OOM -- ran for ~700ms of *uninterrupted*
 *      wall-clock time as one C function call before the next opcode-
 *      boundary check could even run. That is bounded (mquickjs's fixed
 *      arena caps how large a single such call's output can be, hence how
 *      long it can possibly run), but "bounded by arena size" is a much
 *      weaker guarantee than "bounded by an explicit deadline" -- so the
 *      watchdog is kept as the actual enforced bound, with wide margin
 *      (3s hard vs. the ~0.7s worst case measured).
 *
 * No host bindings: this is a bare js_stdlib context (see
 * mayhem_stdlib.c) -- print()/console.log() are no-ops, load() always
 * throws, setTimeout() never actually schedules anything. A fuzzed script
 * has no path to the host filesystem/network/stdout through this harness.
 *
 * A fresh JSContext (and its backing arena) is created and freed every
 * call, so GC/heap state never accumulates across inputs.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mayhem_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    mayhem_install_watchdog();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* JS_Eval (like JS_Parse) requires input[input_len] == '\0'. */
    char *buf = malloc(size + 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    uint8_t *mem = malloc(MAYHEM_MEM_SIZE);
    if (!mem) {
        free(buf);
        return 0;
    }

    JSContext *ctx = JS_NewContext(mem, MAYHEM_MEM_SIZE, &js_stdlib);
    JS_SetInterruptHandler(ctx, mayhem_interrupt_handler);

    mayhem_arm_deadline();
    JSValue val = JS_Eval(ctx, buf, size, "fuzz.js", 0);
    mayhem_disarm_deadline();

    /* A thrown exception (syntax error, runtime TypeError, interrupted,
       out-of-memory, ...) is an expected outcome for untrusted script and
       is not itself a finding -- ASan/UBSan report real memory-safety and
       UB violations independently of this return value. */
    (void)val;

    JS_FreeContext(ctx);
    free(mem);
    free(buf);
    return 0;
}
