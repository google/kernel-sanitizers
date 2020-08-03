/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_KFENCE_H
#define _LINUX_KFENCE_H

#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/static_key.h>
#include <linux/types.h>

struct kmem_cache;

#ifdef CONFIG_KFENCE

/*
 * We allocate an even number of pages, as it simplifies calculations to map
 * address to metadata indices; effectively, the very first page serves as an
 * extended guard page, but otherwise has no special purpose.
 */
#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
extern char __kfence_pool[KFENCE_POOL_SIZE];

extern struct static_key_false kfence_allocation_key;

/**
 * is_kfence_address() - check if an address belongs to KFENCE pool.
 * @addr: address to check.
 *
 * Return: true or false depending on whether the address is within the KFENCE object range.
 *
 * KFENCE objects live in a separate page range and are not to be intermixed with regular heap
 * objects (e.g. KFENCE objects must never be added to SL[AU]B freelists). Failing to do so may
 * and will result in heap corruptions, therefore is_kfence_address() must be used to check whether
 * an object requires specific handling.
 */
static __always_inline bool is_kfence_address(const void *addr)
{
	return unlikely((char *)addr >= __kfence_pool &&
			(char *)addr < __kfence_pool + KFENCE_POOL_SIZE);
}

/**
 * kfence_init() - perform KFENCE initialization at boot time.
 */
void kfence_init(void);

/**
 * kfence_shutdown_cache() - handle shutdown_cache() for KFENCE objects.
 * @s: cache being shut down.
 *
 * Return: true on success, false if any leftover objects persist.
 *
 * Before shutting down a cache, one must ensure there are no remaining objects allocated from it.
 * KFENCE objects are not referenced from the cache, so kfence_shutdown_cache() takes care of them.
 */
bool __must_check kfence_shutdown_cache(struct kmem_cache *s);


/**
 * __kfence_alloc() - allocate a KFENCE object.
 * @s:     struct kmem_cache with object requirements.
 * @size:  exact size of the object to allocate (can be less than @s->size e.g. for kmalloc caches).
 * @flags: GFP flags.
 *
 * Return: pointer to a KFENCE object, if available, NULL otherwise.
 *
 * __kfence_alloc() performs a deterministic allocation from the KFENCE pool using the requested
 * parameters.
 */
void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);

/**
 * kfence_alloc() - allocate a KFENCE object with a low probability.
 * @s:     struct kmem_cache with object requirements.
 * @size:  exact size of the object to allocate (can be less than @s->size e.g. for kmalloc caches).
 * @flags: GFP flags.
 *
 * Return:
 * * NULL     - must proceed with allocating from SL[AU]B as usual.
 * * non-NULL - pointer to a KFENCE object.
 *
 * kfence_alloc() should be inserted into the SL[AU]B allocation fast path, allowing it to
 * transparently return KFENCE-allocated objects with a low probability using a static branch
 * (the probability is controlled by the kfence.sample_interval boot parameter).
 */
static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
	return static_branch_unlikely(&kfence_allocation_key) ? __kfence_alloc(s, size, flags) :
								      NULL;
}

/**
 * kfence_ksize() - get the actual amount of memory allocated for a KFENCE object.
 * @addr: pointer to a heap object.
 *
 * Return:
 * * 0     - not a KFENCE object, must call __ksize() instead.
 * * non-0 - this many bytes can be accessed without causing a memory error.
 *
 * ksize() returns the number of bytes past the end of a SL[AU]B object that can be safely used
 * (e.g. because of a generous alignment). kfence_ksize() mimics this behavior for KFENCE objects.
 */
size_t kfence_ksize(const void *addr);

/**
 * kfence_object_start() - find the beginning of a KFENCE object.
 * @addr - address within a KFENCE-allocated object.
 *
 * Return: address of the beginning of the object.
 *
 * SL[AU]B-allocated objects are laid out within a page one by one, so it is easy to calculate the
 * beginning of an object given a pointer inside it and the object size. The same is not true for
 * KFENCE, which places a single object at either end of the page. This helper function is used to
 * find the beginning of a KFENCE-allocated object.
 */
void *kfence_object_start(const void *addr);

/**
 * __kfence_free() - release a KFENCE-allocated object to KFENCE pool.
 * @addr: object to be released.
 *
 * This function must only be called for pointers returned by __kfence_alloc().
 */
void __kfence_free(void *addr);

/**
 * kfence_free() - try to release an arbitrary heap object to KFENCE pool.
 * @addr: object to be freed.
 *
 * Return:
 * * false - object doesn't belong to KFENCE pool and was ignored.
 * * true  - object was released to KFENCE pool.
 *
 * Because KFENCE objects are sometimes transparently returned by SL[AU]B, kfence_free() must be
 * called before deleting every heap object that fits into a single page.
 */
static __always_inline __must_check bool kfence_free(void *addr)
{
	if (!is_kfence_address(addr))
		return false;
	__kfence_free(addr);
	return true;
}

/**
 * kfence_handle_page_fault() - perform page fault handling for KFENCE pages.
 * @addr: faulting address.
 *
 * Return:
 * * false - address outside KFENCE pool.
 * * true  - page fault handled by KFENCE, no additional handling required.
 *
 * A page fault inside KFENCE pool indicates a memory corruption, such as out-of-bounds access,
 * a use-after-free or a wild memory access. In these cases KFENCE prints an error message and
 * marks the offending page as present, so that the kernel can proceed.
 */
bool __must_check kfence_handle_page_fault(unsigned long addr);

#else /* CONFIG_KFENCE */

// TODO: remove for v1
// clang-format off

static inline bool is_kfence_address(const void *addr) { return false; }
static inline void kfence_init(void) { }
static inline bool __must_check kfence_shutdown_cache(struct kmem_cache *s) { return true; }
static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
static inline size_t kfence_ksize(const void *addr) { return 0; }
static inline void *kfence_object_start(const void *addr) { return NULL; }
static inline bool __must_check kfence_free(void *addr) { return false; }
static inline bool __must_check kfence_handle_page_fault(unsigned long addr) { return false; }

// TODO: remove for v1
// clang-format on

#endif

#endif /* _LINUX_KFENCE_H */
