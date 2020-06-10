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
	void *ret;
	unsigned long aligned_ret;

	if (!READ_ONCE(kfence_enabled))
		return NULL;
	if ((size > PAGE_SIZE) || (s->size > PAGE_SIZE))
		return NULL;
	if (s->ctor || (s->flags & SLAB_TYPESAFE_BY_RCU))
		return NULL;

	rnd = prandom_u32_max(kfence_sample_rate);
	if (rnd)
		return NULL;
	ret = kfence_guarded_alloc(s, size, flags);

	/* TODO: account for init_on_alloc=1 as well. */
	if (ret && (flags & __GFP_ZERO)) {
		aligned_ret = ALIGN_DOWN((unsigned long)ret, PAGE_SIZE);
		memset((void *)aligned_ret, 0, PAGE_SIZE);
	}
	return ret;
}

void kfence_impl_init(void)
{
	/* Nothing here. */
}
