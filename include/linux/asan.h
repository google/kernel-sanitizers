#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

/* FIXME: use include insted of forward declaration. */
struct kmem_cache;
/* #include <linux/slab.h> */
#include <linux/types.h>

#define ASAN_USER_POISONED_MEMORY 0xF7
#define ASAN_HEAP_REDZONE 0xFA
#define ASAN_HEAP_FREE 0xFD

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x36600000
#define SHADOW_GRANULARITY (1 << SHADOW_SCALE)

#define ASAN_REDZONE_SIZE 64

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
void asan_slab_create(const struct kmem_cache *cache, const void *slab);
void asan_slab_destroy(const struct kmem_cache *cache, const void *slab);
void asan_slab_alloc(const struct kmem_cache *cache, const void *ptr);
void asan_slab_free(const struct kmem_cache *cache, const void *ptr);

void asan_on_kernel_init(void);

void asan_on_memcpy(const void *to, const void *from, unsigned long n);

#endif /* LINUX_ASAN_H */
