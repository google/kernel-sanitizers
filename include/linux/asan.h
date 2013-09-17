#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

#include <linux/types.h>

struct kmem_cache;

/* Reserves shadow memory. */
void asan_init_shadow(void);

/* FIXME: write comments. */
void asan_slab_create(struct kmem_cache *cache, void *slab);
void asan_slab_destroy(struct kmem_cache *cache, void *slab);
void asan_slab_alloc(struct kmem_cache *cache, void *object);
bool asan_slab_free(struct kmem_cache *cache, void *object);

void asan_cache_destroy(struct kmem_cache *cache);

void asan_kmalloc(struct kmem_cache *cache, void *object, unsigned long size);
void asan_krealloc(void *object, unsigned long new_size);

void asan_add_redzone(struct kmem_cache *cache, size_t *cache_size);

/* Called when the kernel is initialized. */
void asan_on_kernel_init(void);

#endif /* LINUX_ASAN_H */
