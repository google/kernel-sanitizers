/*
 * AddressSanitizer (ASAN) is a tool that finds use-after-free and
 * out-of-bounds bugs. See Documentation/asan.txt for details.
 */

#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

#include <linux/types.h>

struct kmem_cache;

#ifdef CONFIG_ASAN

/* Reserves shadow memory. */
void asan_init_shadow(void);

/* Hooks for kmalloc/slab. */
void asan_slab_create(struct kmem_cache *cache, void *slab);
void asan_slab_destroy(struct kmem_cache *cache, void *slab);
void asan_slab_alloc(struct kmem_cache *cache, void *object);
bool asan_slab_free(struct kmem_cache *cache, void *object);

void asan_add_redzone(struct kmem_cache *cache, size_t *cache_size);
void asan_cache_destroy(struct kmem_cache *cache);

void asan_kmalloc(struct kmem_cache *cache, void *object, unsigned long size);
void asan_krealloc(void *object, unsigned long new_size);

/* Calls some tests when the kernel is initialized. */
void asan_on_kernel_init(void);

#else /* CONFIG_ASAN */

/* When disabled ASAN is no-op. */

static inline void asan_init_shadow(void) {}

static inline void asan_slab_create(struct kmem_cache *cache, void *slab) {}
static inline void asan_slab_destroy(struct kmem_cache *cache, void *slab) {}
static inline void asan_slab_alloc(struct kmem_cache *cache, void *object) {}
static inline bool asan_slab_free(struct kmem_cache *cache, void *object)
{
	return true;
}

static inline void asan_add_redzone(struct kmem_cache *cache,
				    size_t *cache_size) {}
static inline void asan_cache_destroy(struct kmem_cache *cache) {}

static inline void asan_kmalloc(struct kmem_cache *cache, void *object,
				unsigned long size) {}
static inline void asan_krealloc(void *object, unsigned long new_size) {}

static inline void asan_on_kernel_init(void) {}

/*
 * No need to make asan_memcpy, asan_memset and asan_memmove no-ops, since
 * they are defined under CONFIG_ASAN (arch/x86/include/asm/string_64.h).
 */

#endif /* CONFIG_ASAN */

#endif /* LINUX_ASAN_H */
