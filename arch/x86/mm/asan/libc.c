#include <linux/export.h>
#include <linux/types.h>

#include <linux/asan.h>

void *asan_memcpy(void *dst, const void *src, size_t len)
{
	char *d = (char *)dst;
	char *s = (char *)src;
	size_t i;

	asan_check_region(dst, len);
	asan_check_region(src, len);

	for (i = 0; i < len; i++)
		d[i] = s[i];
	return dst;
}
EXPORT_SYMBOL_GPL(asan_memcpy);
