#ifndef _LINUX_KASAN_H
#define _LINUX_KASAN_H

#include <linux/types.h>

struct kmem_cache;
struct page;

#ifdef CONFIG_KASAN
#include <asm/kasan.h>
#include <linux/sched.h>

#define KASAN_SHADOW_SCALE_SHIFT 3
#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)

static inline unsigned long kasan_mem_to_shadow(unsigned long addr)
{
	return (addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET;
}

static inline void kasan_enable_local(void)
{
	current->kasan_depth++;
}

static inline void kasan_disable_local(void)
{
	current->kasan_depth--;
}

void kasan_unpoison_shadow(const void *address, size_t size);

void kasan_alloc_pages(struct page *page, unsigned int order);
void kasan_free_pages(struct page *page, unsigned int order);
void kasan_mark_slab_padding(struct kmem_cache *s, void *object,
			struct page *page);

void kasan_kmalloc_large(const void *ptr, size_t size);
void kasan_kfree_large(const void *ptr);
void kasan_kmalloc(struct kmem_cache *s, const void *object, size_t size);
void kasan_krealloc(const void *object, size_t new_size);

void kasan_slab_alloc(struct kmem_cache *s, void *object);
void kasan_slab_free(struct kmem_cache *s, void *object);

#else /* CONFIG_KASAN */

static inline void kasan_unpoison_shadow(const void *address, size_t size) {}

static inline void kasan_enable_local(void) {}
static inline void kasan_disable_local(void) {}

static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
static inline void kasan_free_pages(struct page *page, unsigned int order) {}
static inline void kasan_mark_slab_padding(struct kmem_cache *s, void *object,
					struct page *page) {}

static inline void kasan_kmalloc_large(void *ptr, size_t size) {}
static inline void kasan_kfree_large(const void *ptr) {}
static inline void kasan_kmalloc(struct kmem_cache *s, const void *object,
				size_t size) {}
static inline void kasan_krealloc(const void *object, size_t new_size) {}

static inline void kasan_slab_alloc(struct kmem_cache *s, void *object) {}
static inline void kasan_slab_free(struct kmem_cache *s, void *object) {}

#endif /* CONFIG_KASAN */

#endif /* LINUX_KASAN_H */
