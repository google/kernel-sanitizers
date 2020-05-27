/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KFENCE_H
#define _LINUX_KFENCE_H

#include <linux/types.h>

struct kmem_cache;
struct page;

#ifdef CONFIG_KFENCE
/* TODO: API documentation */

void kfence_init(void);

bool kfence_free(struct kmem_cache *s, struct page *page, void *head,
		 void *tail, int cnt, unsigned long addr);

bool kfence_discard_slab(struct kmem_cache *s, struct page *page);

bool kfence_handle_page_fault(unsigned long addr);

bool is_kfence_addr(void *addr);

#else /* CONFIG_KFENCE */

// TODO: remove for v1
// clang-format off

static inline void kfence_init(void) { }
static inline bool kfence_free(struct kmem_cache *s, struct page *page,
			       void *head, void *tail, int cnt,
			       unsigned long addr) { return false; }
static inline bool kfence_discard_slab(struct kmem_cache *s, struct page *page) { return false; }
static inline bool kfence_handle_page_fault(unsigned long addr) { return false; }
static inline bool is_kfence_addr(void *addr) { return false; }

// TODO: remove for v1
// clang-format on

#endif /* CONFIG_KFENCE */

#ifdef CONFIG_KFENCE_STEAL
void *kfence_alloc_and_fix_freelist(struct kmem_cache *s, gfp_t gfp);

void kfence_cache_register(struct kmem_cache *s);

void kfence_cache_unregister(struct kmem_cache *s);

void kfence_observe_memcg_cache(struct kmem_cache *memcg_cache);
#else

// TODO: remove for v1
// clang-format off

static inline void *kfence_alloc_and_fix_freelist(struct kmem_cache *s, gfp_t gfp) { return NULL; }
static inline void kfence_cache_register(struct kmem_cache *s)   { }
static inline void kfence_cache_unregister(struct kmem_cache *s) { }
static inline void kfence_observe_memcg_cache(struct kmem_cache *memcg_cache) { }

// TODO: remove for v1
// clang-format on

#endif /* CONFIG_KFENCE_STEAL */

#ifdef CONFIG_KFENCE_NAIVE

void *kfence_alloc_with_size(struct kmem_cache *s, size_t size, gfp_t flags);

#else

// TODO: remove for v1
// clang-format off

static inline void *kfence_alloc_with_size(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }

// TODO: remove for v1
// clang-format on

#endif /* CONFIG_KFENCE_NAIVE */

#endif /* _LINUX_KFENCE_H */
