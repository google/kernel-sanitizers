// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/static_key.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "kfence.h"
#include "../slab.h"

/* The static key to set up a KFENCE allocation. */
DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);

/* Gates the allocation, ensuring only one succeeds in a given period. */
static atomic_t allocation_gate = ATOMIC_INIT(1);
/* Wait queue to wake up heartbeat timer task. */
static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);

void *kfence_alloc_with_size(struct kmem_cache *s, size_t size, gfp_t flags)
{
	void *ret;

	/*
	 * allocation_gate only needs to become non-zero, so it doesn't make
	 * sense to continue writing to it and pay the associated contention
	 * cost, in case we have a large number of concurrent allocations.
	 */
	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) > 1)
		return NULL;
	wake_up(&allocation_wait);

	if (!kfence_is_enabled())
		return NULL;

	// TODO(elver): Remove one of the comparisons, which is redundant.
	if ((size > PAGE_SIZE) || (s->size > PAGE_SIZE))
		return NULL;
	if (s->flags & SLAB_TYPESAFE_BY_RCU)
		return NULL;

	ret = kfence_guarded_alloc(s, size, flags);

	return ret;
}

/*
 * Set up delayed work, which will enable and disable the static key. We need to
 * use a work queue (rather than a simple timer), since enabling and disabling a
 * static key cannot be done from an interrupt.
 */
static struct delayed_work kfence_timer;
static void kfence_heartbeat(struct work_struct *work)
{
	if (!kfence_is_enabled())
		return;

	/* Enable static key, and await allocation to happen. */
	atomic_set(&allocation_gate, 0);
	static_branch_enable(&kfence_allocation_key);
	wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);

	/* Disable static key and reset timer. */
	static_branch_disable(&kfence_allocation_key);
	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_rate));
}
static DECLARE_DELAYED_WORK(kfence_timer, kfence_heartbeat);

/*
 * TODO: naive implementation doesn't strictly require waiting for RNG anymore.
 */
void kfence_impl_init(void)
{
	schedule_delayed_work(&kfence_timer, 0);
}
