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
void asan_cache_create(struct kmem_cache *cache, size_t *size);
void asan_cache_destroy(struct kmem_cache *cache);

void asan_slab_create(struct kmem_cache *cache, void *slab);
void asan_slab_destroy(struct kmem_cache *cache, void *slab);
void asan_slab_alloc(struct kmem_cache *cache, void *object);
void asan_slab_free(struct kmem_cache *cache, void *object);

void asan_kmalloc(struct kmem_cache *cache, void *object, size_t size);
void asan_krealloc(void *object, size_t new_size);
size_t asan_ksize(const void *ptr);

/* Calls some tests when the kernel is initialized. */
void asan_on_kernel_init(void);

#else /* CONFIG_ASAN */

/* When disabled ASAN is no-op. */

static inline void asan_init_shadow(void) {}

static inline void asan_slab_create(struct kmem_cache *cache, void *slab) {}
static inline void asan_slab_destroy(struct kmem_cache *cache, void *slab) {}
static inline void asan_slab_alloc(struct kmem_cache *cache, void *object) {}
static inline void asan_slab_free(struct kmem_cache *cache, void *object) {}

static inline void asan_cache_create(struct kmem_cache *cache, size_t *size) {}
static inline void asan_cache_destroy(struct kmem_cache *cache) {}

static inline void asan_kmalloc(struct kmem_cache *cc, void *ob, size_t sz) {}
static inline void asan_krealloc(void *object, size_t size) {}

static inline void asan_on_kernel_init(void) {}

/*
 * No need to make asan_memcpy, asan_memset and asan_memmove no-ops, since
 * they are defined under CONFIG_ASAN (arch/x86/include/asm/string_64.h).
 */

#endif /* CONFIG_ASAN */

#endif /* LINUX_ASAN_H */
