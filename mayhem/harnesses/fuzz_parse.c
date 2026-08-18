/*
 * mayhem/harnesses/fuzz_parse.c -- fuzz mquickjs's lexer + recursive-descent
 * parser + bytecode compiler (JS_Parse) WITHOUT ever executing the result.
 *
 * This is the shallow half of the two-target split (see fuzz_eval.c for the
 * deep, execute-too target): it drives the front end only -- tokenizer,
 * expression/statement grammar, bytecode-compiler stack-size computation
 * (compute_stack_size() in mquickjs.c) -- over arbitrary untrusted byte
 * strings, without ever entering the VM's opcode dispatch loop.
 *
 * A fresh JSContext (fixed MAYHEM_MEM_SIZE arena, see mayhem_common.h) is
 * created and destroyed every call so no state accumulates across inputs.
 * JS_Parse alone has no interrupt-handler checkpoints (interrupt_counter is
 * only consulted by the bytecode VM and the RegExp matcher, per mquickjs.c);
 * the step-budget handler is installed anyway so the bound stays in place
 * if the engine ever polls during compilation. mquickjs's recursive-descent
 * parser guards against runaway nesting itself (a 200000-deep
 * "(((...1...)))" input returns a clean "SyntaxError: stack overflow" --
 * ~2 s in this ASan+UBSan build, 40 ms in the plain mqjs build -- not a
 * hang or a native stack-overflow crash). There is no timer or
 * watchdog: any other slow input is bounded by libFuzzer's -timeout /
 * Mayhem's per-test timeout, and a hang is a finding.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mayhem_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* JS_Parse (like JS_Eval) requires input[input_len] == '\0'. */
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
    JSValue val = JS_Parse(ctx, buf, size, "fuzz.js", 0);

    /* A syntax/stack-overflow error is an expected, uninteresting outcome
       for untrusted text -- nothing further to do with the exception
       value. */
    (void)val;

    JS_FreeContext(ctx);
    free(mem);
    free(buf);
    return 0;
}
