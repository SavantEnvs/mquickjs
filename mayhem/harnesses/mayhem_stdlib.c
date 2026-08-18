/*
 * mayhem/harnesses/mayhem_stdlib.c -- host-glue + the `js_stdlib` standard
 * library table for the mquickjs fuzz harnesses, and the shared
 * step-budget interrupt handler declared in mayhem_common.h.
 *
 * ---- why this file exists ----
 *
 * mquickjs's own `js_stdlib` table (the JSSTDLibraryDef every JSContext is
 * built with) is generated at BUILD TIME by running a small host tool
 * (`mqjs_stdlib`, built from the upstream mqjs_stdlib.c + mquickjs_build.c)
 * which prints a self-contained C header (`mqjs_stdlib.h`) that #includes
 * "mquickjs_priv.h" and defines `const JSSTDLibraryDef js_stdlib`. That
 * generated header's tables reference EIGHT external C symbols BY NAME --
 * confirmed by generating it and grepping: js_print, js_gc, js_load,
 * js_setTimeout, js_clearTimeout, js_performance_now, js_date_now, and
 * js_date_constructor. Upstream defines all eight in mqjs.c (the REPL/CLI),
 * where js_print writes to stdout, js_load fopen()s an arbitrary path named
 * by the script, and the timers integrate with a real event loop -- exactly
 * the host/filesystem access the fuzz harness must NOT expose (per the
 * integration brief's "NO HOST ACCESS" rule: no std/os modules, no print,
 * no file I/O, no require()). mqjs.c itself is upstream's CLI (it has its
 * own main()) and is never compiled into the fuzz harness.
 *
 * So this file provides the SAME eight symbols as safe no-ops/stubs, then
 * #includes the generated mqjs_stdlib.h (built.sh places it on the include
 * path) to get the real `js_stdlib` -- the actual ECMAScript standard
 * library (Object/Array/String/Number/Math/JSON/RegExp/Date/TypedArray/...,
 * confirmed by inspecting the generated table; there is no separate
 * std/os/require module in this API to begin with). This is the ONLY
 * translation unit that includes mqjs_stdlib.h (it defines a non-static
 * `js_stdlib` global); fuzz_parse.c/fuzz_eval.c reference it via the
 * `extern` declaration in mayhem_common.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* same feature macros as upstream's -D_GNU_SOURCE build */
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mayhem_common.h"

/* ---- neutered host glue (no stdout, no filesystem, no real timers) ---- */

/* console.log()/print(): discard all output. A real fuzz target must not
   perform I/O keyed on untrusted data. */
static JSValue js_print(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    return JS_UNDEFINED;
}

/* gc(): in-engine only (JS_GC just walks/compacts this context's own
   arena) -- not host access. */
static JSValue js_gc(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    JS_GC(ctx);
    return JS_UNDEFINED;
}

/* load(<path>): upstream's version fopen()s an attacker-named path and
   JS_Eval()s its contents. Deny it outright -- the harness must take bytes
   only from the fuzzer. */
static JSValue js_load(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    return JS_ThrowError(ctx, JS_CLASS_ERROR, "load() is disabled in the fuzz harness");
}

/* setTimeout()/clearTimeout(): the harness never pumps an event loop (no
   run_timers() call), so a registered callback would simply never fire.
   Validate arguments the same way upstream does (so malformed calls still
   exercise real error paths) but do not retain any reference to the
   callback -- nothing to leak, nothing to run later. */
static JSValue js_setTimeout(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    int delay;
    if (!JS_IsFunction(ctx, argv[0]))
        return JS_ThrowTypeError(ctx, "not a function");
    if (JS_ToInt32(ctx, &delay, argv[1]))
        return JS_EXCEPTION;
    return JS_NewInt32(ctx, 0);
}

static JSValue js_clearTimeout(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    return JS_UNDEFINED;
}

/* Date.now()/performance.now()/`new Date()`: reading the monotonic/wall
   clock is not "host access" in the sense the brief cares about (it can't
   read/write anything the fuzzer doesn't already control, and every run
   observes a real, if non-deterministic, timestamp -- exactly like
   upstream's own mqjs.c). */
static int64_t mayhem_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static JSValue js_performance_now(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    return JS_NewInt64(ctx, mayhem_time_ms());
}

static JSValue js_date_now(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    return JS_NewInt64(ctx, mayhem_time_ms());
}

/* `new Date(...)` / `Date(...)`: mirrors upstream's js_date_constructor
   (mqjs.c) exactly, using our own clock helper instead of gettimeofday(). */
JSValue js_date_constructor(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv)
{
    double val;
    argc &= ~FRAME_CF_CTOR;
    if (argc == 0) {
        val = (double)mayhem_time_ms();
    } else if (argc == 1 && JS_IsNumber(ctx, argv[0])) {
        if (JS_ToNumber(ctx, &val, argv[0]))
            return JS_EXCEPTION;
    } else {
        return JS_ThrowTypeError(ctx, "unsupported Date() parameter");
    }
    return JS_NewDate(ctx, val);
}

/* Generated at build time by mayhem/build.sh (running the upstream
   mqjs_stdlib host tool) and placed on the include path. Defines the real
   `const JSSTDLibraryDef js_stdlib` using the eight symbols above. */
#include "mqjs_stdlib.h"

/* ---------------------------------------------------------------------- */
/* Bounding: deterministic step budget (see mayhem_common.h).              */
/*                                                                         */
/* The engine calls this handler once every JS_INTERRUPT_COUNTER_INIT      */
/* interpreter poll points (calls, jumps, RegExp backtracking steps), so   */
/* counting invocations counts work. No clock is read here: the same input */
/* is stopped at the same point on every run, regardless of machine load.  */
/* ---------------------------------------------------------------------- */

static unsigned mayhem_interrupt_calls;

void mayhem_reset_budget(void)
{
    mayhem_interrupt_calls = 0;
}

int mayhem_interrupt_handler(JSContext *ctx, void *opaque)
{
    (void)ctx;
    (void)opaque;
    /* Saturate rather than wrap, so an exhausted budget stays exhausted
       (the engine keeps polling while unwinding, e.g. through finally). */
    if (mayhem_interrupt_calls <= MAYHEM_INTERRUPT_BUDGET)
        mayhem_interrupt_calls++;
    return mayhem_interrupt_calls > MAYHEM_INTERRUPT_BUDGET;
}
