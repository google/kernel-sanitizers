// SPDX-License-Identifier: GPL-2.0

#ifndef MM_KFENCE_KFENCE_H
#define MM_KFENCE_KFENCE_H

#include <linux/slub_def.h>
#include <linux/types.h>

/*
 * KFENCE_WARN_ON() disables KFENCE on the first warning, to avoid potential
 * further errors if KFENCE is enabled in a non-test environment.
 */
#define KFENCE_WARN_ON(cond)                                                   \
	({                                                                     \
		bool __cond = WARN_ON(cond);                                   \
		if (unlikely(__cond))                                          \
			kfence_disable();                                      \
		__cond;                                                        \
	})

extern bool kfence_enabled;
extern unsigned long kfence_sample_rate;

static inline bool kfence_is_enabled(void)
{
	return READ_ONCE(kfence_enabled);
}

void kfence_disable(void);

void *kfence_guarded_alloc(struct kmem_cache *cache, size_t override_size,
			   gfp_t gfp);
void kfence_guarded_free(void *addr);

struct alloc_metadata;

enum kfence_error_kind {
	KFENCE_ERROR_OOB,
	KFENCE_ERROR_UAF,
	KFENCE_ERROR_CORRUPTION
};

void kfence_report_error(unsigned long address, int obj_index,
			 struct alloc_metadata *object,
			 enum kfence_error_kind kind);

/* Should be provided by the sampling algorithm implementation. */
void kfence_impl_init(void);

#endif /* MM_KFENCE_H */
