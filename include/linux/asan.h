#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

#include <linux/types.h>

struct kmem_cache;

#define ASAN_HEAP_REDZONE 0xFA
#define ASAN_HEAP_FREE 0xFD

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x36600000
#define SHADOW_GRANULARITY (1 << SHADOW_SCALE)

/* Redzone should be sizeof(unsigned long) aligned. */
#define ASAN_REDZONE_SIZE 256
#define ASAN_QUARANTINE_SIZE (16 << 20)

/* XXX: move to internal header? */
#define ASAN_STACK_TRACE_SIZE (ASAN_REDZONE_SIZE / 2)
#define ASAN_FRAMES_IN_STACK_TRACE \
	(ASAN_STACK_TRACE_SIZE / sizeof(unsigned long))

/* XXX: move to internal header? */
extern int asan_enabled;

/*
 * Reserves shadow memory.
 */
void asan_init_shadow(void);

/*
 * Checks region for poisoned bytes.
 * Reports poisoned bytes if found.
 */
void asan_check_region(const void *addr, unsigned long size);

/*
 * Used in mm/slab.c
 */
void asan_slab_create(struct kmem_cache *cache, void *slab);
void asan_slab_destroy(struct kmem_cache *cache, void *slab);
void asan_slab_alloc(struct kmem_cache *cache, void *object);
bool asan_slab_free(struct kmem_cache *cache, void *object);

void asan_kmalloc(struct kmem_cache *cache, const void *object,
		  unsigned long size);
void asan_krealloc(const void *object, unsigned long new_size);

void asan_add_redzone(struct kmem_cache *cache, size_t *cache_size);

/*
 * Called when the kernel is initialized.
 */
void asan_on_kernel_init(void);

#endif /* LINUX_ASAN_H */
