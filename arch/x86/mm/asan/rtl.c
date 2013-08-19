#include <linux/asan.h>
#include <linux/export.h>

#define TSAN_REPORT(type, size)				\
void __tsan_##type##size(unsigned long addr)		\
{							\
	asan_check_region((void *)addr, (size));	\
}							\
EXPORT_SYMBOL(__tsan_##type##size);

TSAN_REPORT(read, 1)
TSAN_REPORT(read, 2)
TSAN_REPORT(read, 4)
TSAN_REPORT(read, 8)
TSAN_REPORT(read, 16)

TSAN_REPORT(write, 1)
TSAN_REPORT(write, 2)
TSAN_REPORT(write, 4)
TSAN_REPORT(write, 8)
TSAN_REPORT(write, 16)

void __tsan_init(void)
{
}
EXPORT_SYMBOL(__tsan_init);

void __tsan_func_entry(unsigned long addr)
{
}
EXPORT_SYMBOL(__tsan_func_entry);

void __tsan_func_exit(unsigned long addr)
{
}
EXPORT_SYMBOL(__tsan_func_exit);
