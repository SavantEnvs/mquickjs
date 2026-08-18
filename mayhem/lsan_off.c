/*
 * mayhem/lsan_off.c -- build-time LeakSanitizer off-switch.
 *
 * Compiled with $SANITIZER_FLAGS and linked by mayhem/build.sh into every
 * ASan-instrumented binary it builds: /mayhem/fuzz_parse, /mayhem/fuzz_eval
 * and their -standalone reproducers. -fsanitize=address always bundles
 * LeakSanitizer, and no compiler flag keeps ASan while dropping only leak
 * detection. The LSan runtime calls this hook before each leak check and
 * skips the check when it returns non-zero. Leaks are not the defect class
 * this environment fuzzes for.
 *
 * Only leak detection is affected: AddressSanitizer's memory-error checks and
 * every enabled UBSan check stay on and halting, and no runtime sanitizer
 * option is set anywhere. The clean oracle build (`mqjs`, built by upstream's
 * own Makefile without sanitizers) does not link this file.
 */
int __lsan_is_turned_off(void) { return 1; }
