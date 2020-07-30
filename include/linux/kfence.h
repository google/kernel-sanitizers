/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_KFENCE_H
#define _LINUX_KFENCE_H

#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/static_key.h>
#include <linux/types.h>

struct kmem_cache;

#ifdef CONFIG_KFENCE
/* TODO: API documentation */

/*
 * We allocate an even number of pages, as it simplifies calculations to map
 * address to metadata indices; effectively, the very first page serves as an
 * extended guard page, but otherwise has no special purpose.
 */
#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
extern char __kfence_pool[KFENCE_POOL_SIZE];

extern struct static_key_false kfence_allocation_key;

static __always_inline bool is_kfence_address(const void *addr)
{
	return unlikely((char *)addr >= __kfence_pool &&
			(char *)addr < __kfence_pool + KFENCE_POOL_SIZE);
}

void kfence_init(void);

bool __must_check kfence_shutdown_cache(struct kmem_cache *s);

void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);

// TODO(elver): Add API doc.
static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
	return static_branch_unlikely(&kfence_allocation_key) ? __kfence_alloc(s, size, flags) :
								      NULL;
}

size_t kfence_ksize(const void *addr);

void *kfence_object_start(const void *addr);

void __kfence_free(void *addr);

static __always_inline __must_check bool kfence_free(void *addr)
{
	if (!is_kfence_address(addr))
		return false;
	__kfence_free(addr);
	return true;
}

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
