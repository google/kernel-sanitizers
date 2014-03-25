#ifndef _LINUX_KASAN_H
#define _LINUX_KASAN_H

#include <linux/types.h>

struct kmem_cache;
struct page;

#ifdef CONFIG_KASAN
#include <asm/kasan.h>
#include <linux/sched.h>

#define KASAN_SHADOW_SCALE_SHIFT 3

static inline unsigned long kasan_mem_to_shadow(unsigned long addr)
{
	return ((addr - KASAN_SHADOW_START) >> KASAN_SHADOW_SCALE_SHIFT)
		+ KASAN_SHADOW_START;
}

static inline void kasan_enable_local(void)
{
	current->kasan_depth++;
}

static inline void kasan_disable_local(void)
{
	current->kasan_depth--;
}

void unpoison_shadow(const void *address, size_t size);

#else /* CONFIG_KASAN */

static inline void unpoison_shadow(const void *address, size_t size) {}

static inline void kasan_enable_local(void) {}
static inline void kasan_disable_local(void) {}

#endif /* CONFIG_KASAN */

#endif /* LINUX_KASAN_H */
