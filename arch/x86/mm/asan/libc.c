#include <linux/export.h>
#include <linux/types.h>

#include <linux/asan.h>

void *asan_memcpy(void *dst, const void *src, size_t len)
{
	char *d = (char *)dst;
	const char *s = (const char *)src;
	size_t i;

	asan_check_region(dst, len);
	asan_check_region(src, len);

	for (i = 0; i < len; i++)
		d[i] = s[i];
	return dst;
}
EXPORT_SYMBOL(asan_memcpy);

void *asan_memset(void *ptr, int val, size_t len)
{
	char *p = (char *)ptr;
	size_t i;

	asan_check_region(ptr, len);

	for (i = 0; i < len; i++)
		p[i] = val;
	return ptr;
}
EXPORT_SYMBOL(asan_memset);

void *asan_memmove(void *dst, const void *src, size_t len)
{
	char *d = (char *)dst;
	const char *s = (const char *)src;
	size_t i;

	//asan_check_region(dst, len);
	//asan_check_region(src, len);

	if (d < s) {
		for (i = 0; i < len; i++)
			d[i] = s[i];
	} else {
		if (d > s && len > 0)
			for (i = len - 1; i >= 0; i--)
				d[i] = s[i];
	}
	return dst;
}
EXPORT_SYMBOL(asan_memmove);
