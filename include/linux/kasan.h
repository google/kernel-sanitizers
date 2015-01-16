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

#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
#define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
#define KASAN_SHADOW_GAP        0xF9  /* address belongs to shadow memory */

/* Stack redzones (Those are compiler's ABI, don't touch them) */
#define KASAN_STACK_LEFT        0xF1
#define KASAN_STACK_MID         0xF2
#define KASAN_STACK_RIGHT       0xF3
#define KASAN_STACK_PARTIAL     0xF4

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

void kasan_poison_slab(struct page *page);
void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
void kasan_poison_object_data(struct kmem_cache *cache, void *object);

void kasan_kmalloc_large(const void *ptr, size_t size);
void kasan_kfree_large(const void *ptr);
void kasan_kmalloc(struct kmem_cache *s, const void *object, size_t size);
void kasan_krealloc(const void *object, size_t new_size);

void kasan_slab_alloc(struct kmem_cache *s, void *object);
void kasan_slab_free(struct kmem_cache *s, void *object);

#define MODULE_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)

int kasan_module_alloc(void *addr, size_t size);
void kasan_module_free(void *addr);

#else /* CONFIG_KASAN */

static inline void kasan_unpoison_shadow(const void *address, size_t size) {}

static inline void kasan_enable_local(void) {}
static inline void kasan_disable_local(void) {}

static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
static inline void kasan_free_pages(struct page *page, unsigned int order) {}

static inline void kasan_poison_slab(struct page *page) {}
static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
					void *object) {}
static inline void kasan_poison_object_data(struct kmem_cache *cache,
					void *object) {}


static inline void kasan_kmalloc_large(void *ptr, size_t size) {}
static inline void kasan_kfree_large(const void *ptr) {}
static inline void kasan_kmalloc(struct kmem_cache *s, const void *object,
				size_t size) {}
static inline void kasan_krealloc(const void *object, size_t new_size) {}

static inline void kasan_slab_alloc(struct kmem_cache *s, void *object) {}
static inline void kasan_slab_free(struct kmem_cache *s, void *object) {}

#define MODULE_ALIGN 1

static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
static inline void kasan_module_free(void *addr) {}

#endif /* CONFIG_KASAN */

#endif /* LINUX_KASAN_H */
