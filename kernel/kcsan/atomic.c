// SPDX-License-Identifier: GPL-2.0

#include <linux/jiffies.h>

#include "kcsan.h"

/*
 * List all volatile globals that have been observed in races, to suppress
 * data-race reports between accesses to these variables.
 *
 * For now, we assume that volatile accesses of globals are as strong as atomic
 * accesses (READ_ONCE, WRITE_ONCE cast to volatile). The situation is still not
 * entirely clear, as on some architectures (Alpha) READ_ONCE/WRITE_ONCE do more
 * than cast to volatile. Eventually, we hope to be able to remove this
 * function.
 */
bool kcsan_is_atomic(const volatile void *ptr)
{
	/* only jiffies for now */
	return ptr == &jiffies;
}
