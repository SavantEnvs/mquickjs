/*
 * mayhem/harnesses/fuzz_eval.c -- fuzz mquickjs's full pipeline: parse
 * AND run untrusted JS source through JS_Eval() (== JS_Parse + JS_Run).
 * This is the DEEP target -- it drives the bytecode VM, GC, and the whole
 * built-in standard library (Object/Array/String/Number/Math/JSON/RegExp/
 * Date/TypedArray/...), not just the front end (see fuzz_parse.c for that
 * shallower target).
 *
 * ---- bounding (see mayhem_common.h for the full design) ----
 *
 * Two deterministic bounds, both engaged every call -- no timer, alarm or
 * signal handler (a hang is a finding, bounded by libFuzzer's -timeout /
 * Mayhem's per-test timeout like any other):
 *
 *   1. A fresh, fixed MAYHEM_MEM_SIZE (64MB) arena backs the JSContext --
 *      mquickjs's ONLY memory-limit knob. "a".repeat(1e9) throws
 *      JS_ThrowOutOfMemory() at once rather than materializing a huge
 *      string, because the allocator can't grow past this fixed buffer. It
 *      also limits how much data any single native builtin call (which the
 *      step budget below cannot interrupt mid-call) can work on; a builtin
 *      that is still too slow is a hang finding for the runner's timeout.
 *
 *   2. JS_SetInterruptHandler(mayhem_interrupt_handler) -- a STEP budget.
 *      The engine polls at every call, bytecode jump and RegExp
 *      backtracking step and invokes the handler every 10000 polls; the
 *      handler counts invocations and stops the script with the engine's
 *      normal "interrupted" exception after MAYHEM_INTERRUPT_BUDGET of
 *      them. while(1){}, runaway recursion/loops and `/^(a+)+$/` ReDoS
 *      backtracking all end this way, after the same amount of work on
 *      every run. Native work done between two polls is not counted (e.g.
 *      a loop of `s += 'x'` over a multi-MB string copies the string on
 *      every iteration); such an input is simply slow, and like any other
 *      hang it is the runner's timeout's job.
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

    mayhem_reset_budget();
    JSValue val = JS_Eval(ctx, buf, size, "fuzz.js", 0);

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
