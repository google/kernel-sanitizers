// SPDX-License-Identifier: GPL-2.0

/*
 * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
 * see Documentation/dev-tools/kcsan.rst.
 */

#include <linux/export.h>

#include "kcsan.h"

/*
 * KCSAN uses the same instrumentation that is emitted by supported compilers
 * for Thread Sanitizer (TSAN).
 *
 * When enabled, the compiler emits instrumentation calls (the functions
 * prefixed with "__tsan" below) for all loads and stores that it generated;
 * inline asm is not instrumented.
 */

#define DEFINE_TSAN_READ_WRITE(size)                                           \
	void __tsan_read##size(void *ptr)                                      \
	{                                                                      \
		__kcsan_check_read(ptr, size);                                 \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_read##size);                                      \
	void __tsan_write##size(void *ptr)                                     \
	{                                                                      \
		__kcsan_check_write(ptr, size);                                \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_write##size)

DEFINE_TSAN_READ_WRITE(1);
DEFINE_TSAN_READ_WRITE(2);
DEFINE_TSAN_READ_WRITE(4);
DEFINE_TSAN_READ_WRITE(8);
DEFINE_TSAN_READ_WRITE(16);

/*
 * Not all supported compiler versions distinguish aligned/unaligned accesses,
 * but e.g. recent versions of Clang do.
 */
#define DEFINE_TSAN_UNALIGNED_READ_WRITE(size)                                 \
	void __tsan_unaligned_read##size(void *ptr)                            \
	{                                                                      \
		__kcsan_check_read(ptr, size);                                 \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
	void __tsan_unaligned_write##size(void *ptr)                           \
	{                                                                      \
		__kcsan_check_write(ptr, size);                                \
	}                                                                      \
	EXPORT_SYMBOL(__tsan_unaligned_write##size)

DEFINE_TSAN_UNALIGNED_READ_WRITE(2);
DEFINE_TSAN_UNALIGNED_READ_WRITE(4);
DEFINE_TSAN_UNALIGNED_READ_WRITE(8);
DEFINE_TSAN_UNALIGNED_READ_WRITE(16);

void __tsan_read_range(void *ptr, size_t size)
{
	__kcsan_check_read(ptr, size);
}
EXPORT_SYMBOL(__tsan_read_range);

void __tsan_write_range(void *ptr, size_t size)
{
	__kcsan_check_write(ptr, size);
}
EXPORT_SYMBOL(__tsan_write_range);

/*
 * The below are not required KCSAN, but can still be emitted by the compiler.
 */
void __tsan_func_entry(void *call_pc)
{
}
EXPORT_SYMBOL(__tsan_func_entry);
void __tsan_func_exit(void)
{
}
EXPORT_SYMBOL(__tsan_func_exit);
void __tsan_init(void)
{
}
EXPORT_SYMBOL(__tsan_init);
