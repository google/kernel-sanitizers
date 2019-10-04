/* SPDX-License-Identifier: GPL-2.0 */

/*
 * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
 * see Documentation/dev-tools/kcsan.rst.
 */

#include <linux/export.h>

#include "kcsan.h"

/*
 * Concurrency Sanitizer uses the same instrumentation as Thread Sanitizer.
 */

#define DEFINE_TSAN_READ_WRITE(size)                                           \
	void __tsan_read##size(void *ptr)                                      \
	{                                                                      \
		__kcsan_check_access(ptr, size, false);                        \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_read##size);                                      \
	void __tsan_write##size(void *ptr)                                     \
	{                                                                      \
		__kcsan_check_access(ptr, size, true);                         \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_write##size)

DEFINE_TSAN_READ_WRITE(1);
DEFINE_TSAN_READ_WRITE(2);
DEFINE_TSAN_READ_WRITE(4);
DEFINE_TSAN_READ_WRITE(8);
DEFINE_TSAN_READ_WRITE(16);

void __tsan_read_range(void *ptr, size_t size)
{
	__kcsan_check_access(ptr, size, false);
}
EXPORT_SYMBOL(__tsan_read_range);

void __tsan_write_range(void *ptr, size_t size)
{
	__kcsan_check_access(ptr, size, true);
}
EXPORT_SYMBOL(__tsan_write_range);

/* Unused by KCSAN. */
void __tsan_func_entry(void *call_pc)
{
}
EXPORT_SYMBOL(__tsan_func_entry);

/* Unused by KCSAN. */
void __tsan_func_exit(void)
{
}
EXPORT_SYMBOL(__tsan_func_exit);

/* Unused by KCSAN. */
void __tsan_init(void)
{
}
EXPORT_SYMBOL(__tsan_init);
