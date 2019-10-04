/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/jiffies.h>

#include "kcsan.h"

/*
 * List all volatile globals that have been observed in races. For now we assume
 * that volatile accesses of globals are as strong as atomic accesses --
 * however, this should be clarified by the LKMM!
 */
bool kcsan_is_atomic(const volatile void *ptr)
{
	return ptr == &jiffies;
}
