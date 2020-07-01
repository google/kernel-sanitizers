// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/percpu.h>

#include "kfence.h"
#include "../slab.h"

DEFINE_PER_CPU(int, kfence_sample_cnt);

/*
 * TODO: inline this function so that we only do a decrement and a branch on the
 * fast path.
 */
void *kfence_alloc_with_size(struct kmem_cache *s, size_t size, gfp_t flags)
{
	int cnt;
	void *ret;


	if (!kfence_is_enabled())
		return NULL;

	if ((size > PAGE_SIZE) || (s->size > PAGE_SIZE))
		return NULL;
	if (s->ctor || (s->flags & SLAB_TYPESAFE_BY_RCU))
		return NULL;

	ret = kfence_guarded_alloc(s, size, flags);

	return ret;
}
EXPORT_SYMBOL(kfence_alloc_with_size);

/*
 * TODO: naive implementation doesn't strictly require waiting for RNG anymore.
 */
void kfence_impl_init(void)
{
	int i;
	/*
	 * TODO: a better idea would be to use a normal distribution around
	 * kfence_sample_rate.
	 */
	for_each_possible_cpu(i)
		per_cpu(kfence_sample_cnt, i) = kfence_sample_rate;
}
