// SPDX-License-Identifier: GPL-2.0
//

#include <linux/mm.h>
#include <linux/percpu-refcount.h> // required by slab.h
#include <linux/random.h>

#include "kfence_core.h"
#include "../slab.h"

void *kfence_alloc_with_size(struct kmem_cache *s, size_t size, gfp_t flags)
{
	u32 rnd;

	if (!READ_ONCE(kfence_enabled))
		return NULL;
	if (size > PAGE_SIZE)
		return NULL;
	if ((s->size > PAGE_SIZE) || s->ctor ||
	    (s->flags & SLAB_TYPESAFE_BY_RCU))
		return NULL;

	/*
	 * TODO: this is an arbitrarily chosen multiplier that lets us use the
	 * same sample rate for different KFENCE implementations.
	 */
	rnd = prandom_u32_max(kfence_sample_rate * 5000);
	if (rnd)
		return NULL;
	return guarded_alloc(s, size, flags);
}

void __init kfence_init(void)
{
	if (!kfence_sample_rate)
		/* The tool is disabled. */
		return;

	if (kfence_allocate_pool()) {
		WRITE_ONCE(kfence_enabled, true);
		pr_info("kfence_init done\n");
	} else {
		pr_err("kfence_init failed\n");
	}
}
