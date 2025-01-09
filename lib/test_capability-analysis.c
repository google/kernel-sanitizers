// SPDX-License-Identifier: GPL-2.0-only
/*
 * Compile-only tests for common patterns that should not generate false
 * positive errors when compiled with Clang's capability analysis.
 */

#include <linux/build_bug.h>

/*
 * Test that helper macros work as expected.
 */
static void __used test_common_helpers(void)
{
	BUILD_BUG_ON(capability_unsafe(3) != 3); /* plain expression */
	BUILD_BUG_ON(capability_unsafe((void)2; 3;) != 3); /* does not swallow semi-colon */
	BUILD_BUG_ON(capability_unsafe((void)2, 3) != 3); /* does not swallow commas */
	capability_unsafe(do { } while (0)); /* works with void statements */
}
