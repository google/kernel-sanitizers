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

#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
extern char __kfence_pool[KFENCE_POOL_SIZE];

extern struct static_key_false kfence_allocation_key;

static __always_inline bool is_kfence_addr(void *addr)
{
	return unlikely((char *)addr >= __kfence_pool &&
			(char *)addr < __kfence_pool + KFENCE_POOL_SIZE);
}

void kfence_init(void);

bool kfence_discard_slab(struct kmem_cache *s, struct page *page);

bool kfence_shutdown_cache(struct kmem_cache *s);

void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);

// TODO(elver): Add API doc.
static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
	return static_branch_unlikely(&kfence_allocation_key) ? __kfence_alloc(s, size, flags) :
								      NULL;
}

size_t kfence_ksize(const void *addr);

bool __kfence_free(void *addr);

static __always_inline bool kfence_free(void *addr)
{
	if (!is_kfence_addr(addr))
		return false;
	return __kfence_free(addr);
}

bool kfence_handle_page_fault(unsigned long addr);

#else /* CONFIG_KFENCE */

// TODO: remove for v1
// clang-format off

static inline bool is_kfence_addr(void *addr) { return false; }
static inline void kfence_init(void) { }
static inline bool kfence_discard_slab(struct kmem_cache *s, struct page *page) { return false; }
static inline bool kfence_shutdown_cache(struct kmem_cache *s) { return true; }
static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
static inline size_t kfence_ksize(void *addr) { return 0; }
static inline bool kfence_free(void *addr) { return false; }
static inline bool kfence_handle_page_fault(unsigned long addr) { return false; }

// TODO: remove for v1
// clang-format on

#endif

#endif /* _LINUX_KFENCE_H */
