// SPDX-License-Identifier: GPL-2.0

#ifndef MM_KFENCE_KFENCE_H
#define MM_KFENCE_KFENCE_H

#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/types.h>

#include "../slab.h" /* for struct kmem_cache */

/* Helper to get the canary byte pattern for @addr. */
#define KFENCE_CANARY_PATTERN(addr) (((u8[]){ 0xaa, 0xab, 0xaa, 0xad })[(size_t)addr % 4])

/* Maximum stack depth for reports. */
#define KFENCE_STACK_DEPTH 64

/* KFENCE object states. */
enum kfence_object_state {
	KFENCE_OBJECT_UNUSED, /* KFENCE object is unused. */
	KFENCE_OBJECT_ALLOCATED, /* KFENCE object is currently allocated. */
	KFENCE_OBJECT_FREED, /* KFENCE object was allocated, and then freed. */
};

/* KFENCE metadata per guarded allocation. */
struct kfence_metadata {
	struct list_head list; /* Freelist node. */

	/*
	 * Allocated object address; cannot be calculated from size, because of
	 * alignment requirements.
	 *
	 * Invariant: ALIGN_DOWN(addr, PAGE_SIZE) is constant.
	 */
	unsigned long addr;

	/* The current state of the object; see above. */
	enum kfence_object_state state;

	/*
	 * The kmem_cache cache of the last allocation; NULL if never allocated
	 * or the cache has already been destroyed.
	 */
	struct kmem_cache *cache;

	/*
	 * The size of the original allocation.
	 *
	 * size > 0: left page alignment.
	 * size < 0: right page alignment.
	 */
	int size;

	/* In case of an invalid access, the page that was unprotected. */
	unsigned long unprotected_page;

	/* Allocation and free stack information. */
	unsigned long nr_alloc, nr_free;
	unsigned long stack_alloc[KFENCE_STACK_DEPTH];
	unsigned long stack_free[KFENCE_STACK_DEPTH];
};

extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];

/* KFENCE error types for report generation. */
enum kfence_error_type {
	KFENCE_ERROR_OOB, /* KFENCE detected a out-of-bounds access. */
	KFENCE_ERROR_UAF, /* KFENCE detected a use-after-free access. */
	KFENCE_ERROR_CORRUPTION, /* KFENCE detected a memory corruption on free. */
};

void kfence_report_error(unsigned long address, const struct kfence_metadata *metadata,
			 enum kfence_error_type type);

void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *metadata);

#endif /* MM_KFENCE_KFENCE_H */
