// SPDX-License-Identifier: GPL-2.0

#ifndef MM_KFENCE_KFENCE_H
#define MM_KFENCE_KFENCE_H

#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/types.h>

#include "../slab.h"

/*
 * KFENCE_WARN_ON() disables KFENCE on the first warning, to avoid potential
 * further errors if KFENCE is enabled in a non-test environment.
 */
#define KFENCE_WARN_ON(cond)                                                                       \
	({                                                                                         \
		bool __cond = WARN_ON(cond);                                                       \
		if (unlikely(__cond))                                                              \
			kfence_disable();                                                          \
		__cond;                                                                            \
	})

enum kfence_object_state { KFENCE_OBJECT_UNUSED, KFENCE_OBJECT_ALLOCATED, KFENCE_OBJECT_FREED };

#define KFENCE_STACK_DEPTH 64
struct kfence_alloc_metadata {
	struct kmem_cache *cache;
	/*
	 * Size may be read without a lock in ksize(). We assume that ksize() is
	 * only called for valid (allocated) pointers.
	 * size>0 means left alignment, size<0 - right alignment.
	 */
	int size;
	/*
	 * Actual object address. Cannot be calculated from size, because of
	 * alignment requirements.
	 */
	unsigned long addr;
	enum kfence_object_state state;
	unsigned long nr_alloc, nr_free;
	unsigned long stack_alloc[KFENCE_STACK_DEPTH];
	unsigned long stack_free[KFENCE_STACK_DEPTH];
};

extern unsigned long kfence_sample_rate;
extern bool kfence_enabled;
extern struct kfence_alloc_metadata *kfence_metadata;

static inline bool kfence_is_enabled(void)
{
	return READ_ONCE(kfence_enabled);
}

void kfence_disable(void);

enum kfence_error_type { KFENCE_ERROR_OOB, KFENCE_ERROR_UAF, KFENCE_ERROR_CORRUPTION };

void kfence_report_error(unsigned long address, int obj_index,
			 struct kfence_alloc_metadata *metadata, enum kfence_error_type type);

void kfence_dump_object(struct seq_file *seq, int obj_index, struct kfence_alloc_metadata *obj);

#endif /* MM_KFENCE_H */
