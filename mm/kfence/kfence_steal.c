// SPDX-License-Identifier: GPL-2.0
//

#include <linux/mm.h>
#include <linux/percpu-defs.h>
#include <linux/percpu-refcount.h> // required by slab.h
#include <linux/random.h>
#include <linux/spinlock_types.h>

#include "kfence_core.h"
#include "../slab.h"

/*
 * TODO: need to return a freelist back to the cache if it hasn't been used for
 * a while, otherwise we may quickly run out of pages.
 */
#define MAX_STORED_FREELISTS 256
struct stored_freelist {
	struct kmem_cache *cache;
	void *freelist;
	int cpu;
};

#define KFENCE_MAX_CACHES 256
/*
 * Currently there is less than 100 caches in the running kernel that we need
 * to track. Caches are stored in an array, so that a random cache can be
 * quickly picked.
 */
static struct kmem_cache *kfence_registered_caches[KFENCE_MAX_CACHES];
static int kfence_num_caches;

/* Protects stolen freelists */
static DEFINE_SPINLOCK(kfence_caches_lock);
static struct stored_freelist stored_freelists[MAX_STORED_FREELISTS];
static int num_stored_freelists;

static struct stored_freelist *find_freelist(struct kmem_cache *c)
{
	int i;

	for (i = 0; i < MAX_STORED_FREELISTS; i++) {
		if (stored_freelists[i].cache == c)
			return &stored_freelists[i];
	}
	return NULL;
}

static int find_cache(struct kmem_cache *c)
{
	int i;

	for (i = 0; i < kfence_num_caches; i++) {
		if (kfence_registered_caches[i] == c)
			return i;
	}
	return -1;
}

/* Requires kfence_caches_lock. */
bool kfence_fix_freelist(struct kmem_cache *s)
{
	struct kmem_cache_cpu *c;
	struct stored_freelist *fl;
	void *freelist;

	fl = find_freelist(s);
	if (fl == NULL)
		return false;
	freelist = fl->freelist;
	c = per_cpu_ptr(s->cpu_slab, fl->cpu);
	/* Nobody else is writing to c->freelist at this point. */
	WRITE_ONCE(c->freelist, freelist);
	fl->cache = NULL;
	num_stored_freelists--;
	return true;
}

void *kfence_alloc_and_fix_freelist(struct kmem_cache *s, gfp_t gfp)
{
	unsigned long flags;
	void *ret = NULL;

	if (!READ_ONCE(kfence_enabled))
		return NULL;
	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (!kfence_fix_freelist(s))
		goto leave;
	/*
	 * TODO: pass correct override_size for kmalloc.
	 * See https://github.com/google/kasan/issues/73 for details.
	 */
	ret = kfence_guarded_alloc(s, 0, gfp);
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
	pr_debug("kfence_alloc_and_fix_freelist returns %px\n", ret);
	return ret;
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
	return NULL;
}

void kfence_cache_register(struct kmem_cache *s)
{
	unsigned long flags;
	int index;
	const char *name;
#ifdef CONFIG_MEMCG
	struct kmem_cache *root;
#endif

	if (!s)
		return;

	if (!s->name)
		name = "ANON";
	else
		name = s->name;

#ifdef CONFIG_MEMCG
	/*
	 * There are too many memcg child caches, tracking them would require
	 * too many resources and would reduce the probability of stealing a
	 * freelist from an "interesting" cache.
	 * See kfence_observe_memcg_cache() for details about memcg cache
	 * handling.
	 */
	root = s->memcg_params.root_cache;
	if (root) {
		pr_debug("skipping memcg cache %s\n", s->name);
		return;
	}
#endif

	if (s->size > PAGE_SIZE) {
		pr_debug("skipping cache %s because of size: %d\n", name,
			 s->size);
		return;
	}
	if (s->ctor) {
		pr_debug("skipping cache %s because of ctor\n", name);
		return;
	}
	if (s->flags & SLAB_TYPESAFE_BY_RCU) {
		pr_debug("skipping cache %s because of RCU\n", name);
		return;
	}
	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (kfence_num_caches == KFENCE_MAX_CACHES)
		goto leave;
	index = find_cache(s);
	if (index == -1) {
		kfence_registered_caches[kfence_num_caches] = s;
		kfence_num_caches++;
	}
	pr_debug("registered cache %s as #%d\n", name, kfence_num_caches - 1);
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}
EXPORT_SYMBOL(kfence_cache_register);

void kfence_cache_unregister(struct kmem_cache *s)
{
	unsigned long flags;
	int index;

	if (!s)
		return;

	pr_debug("unregistering cache %s\n", s->name);
	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (kfence_num_caches == 0)
		goto leave;
	index = find_cache(s);
	if (index == -1)
		goto leave;
	kfence_fix_freelist(s);
	if (index != kfence_num_caches - 1)
		kfence_registered_caches[index] =
			kfence_registered_caches[kfence_num_caches - 1];
	kfence_num_caches--;
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}
EXPORT_SYMBOL(kfence_cache_unregister);

static struct kmem_cache *kfence_pick_cache(void)
{
	int index, wrap = kfence_num_caches;
	struct kmem_cache *cache;

	if (!kfence_num_caches)
		return NULL;
	index = prandom_u32_max(kfence_num_caches);
	do {
		cache = kfence_registered_caches[index];
		index = (index + 1) % kfence_num_caches;
		wrap--;
	} while (!cache && wrap);

	return cache;
}

/* Requires kfence_caches_lock. */
static void kfence_steal_freelist(struct kmem_cache *cache, int cpu)
{
	struct stored_freelist *fl;
	struct kmem_cache_cpu *c;

	if (num_stored_freelists == MAX_STORED_FREELISTS)
		return;
	if (find_freelist(cache))
		return;
	fl = find_freelist(NULL);
	c = per_cpu_ptr(cache->cpu_slab, cpu);
	if (KFENCE_WARN_ON(!c))
		return;
	num_stored_freelists++;
	fl->cache = cache;
	fl->cpu = cpu;
	/*
	 * We need to atomically read the old value from c->freelist and write
	 * NULL to it, but SLUB may allocate from this CPU cache and replace
	 * c->freelist in the meantime. Use cmpxchg loop to ensure fl->freelist
	 * contains the latest value.
	 */
	do {
		fl->freelist = READ_ONCE(c->freelist);
	} while (cmpxchg(&c->freelist, fl->freelist, NULL) != fl->freelist);
	pr_debug("stole freelist from cache %s on CPU%d!\n", cache->name, cpu);
}

#ifdef CONFIG_MEMCG
/*
 * Tracking all caches created by memory cgroups may be hard, as there are lots
 * of them. Instead, we only track root (non-memcg) caches. If an allocation is
 * done from a memcg cache, we check if we stole the freelist from its root. In
 * that case we restore the freelist of the root cache and steal the freelist of
 * the memcg cache.
 *
 * TODO: this function is called for every memcg allocation, need to speed it
 * up. Memcg allocations aren't popular in the kernel though.
 * */
void kfence_observe_memcg_cache(struct kmem_cache *memcg_cache)
{
	unsigned long flags;
	struct kmem_cache *root;
	char *name;
	int cpu = raw_smp_processor_id();

	if (!memcg_cache)
		return;

	if (memcg_cache->name)
		name = (char *)memcg_cache->name;
	else
		name = "ANON";

	root = memcg_cache->memcg_params.root_cache;

	if (!root)
		/* This is not a valid memcg child cache. */
		return;

	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (kfence_fix_freelist(root)) {
		kfence_steal_freelist(memcg_cache, cpu);
		pr_debug("stole freelist from memcg cache %s on CPU%d\n",
			 memcg_cache->name, cpu);
	}
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}
EXPORT_SYMBOL(kfence_observe_memcg_cache);
#endif

static void steal_random_freelist(void)
{
	struct kmem_cache *cache;
	int cpu;
	unsigned long flags;

	spin_lock_irqsave(&kfence_caches_lock, flags);
	cache = kfence_pick_cache();
	cpu = prandom_u32_max(total_cpus);
	if (!cache)
		goto leave;
	kfence_steal_freelist(cache, cpu);
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}

static void kfence_heartbeat(struct timer_list *timer)
{
	if (!READ_ONCE(kfence_enabled))
		return;

	steal_random_freelist();
	mod_timer(timer, jiffies + msecs_to_jiffies(kfence_sample_rate));
}
static DEFINE_TIMER(kfence_timer, kfence_heartbeat);

void __init kfence_impl_init(void)
{
	mod_timer(&kfence_timer, jiffies + 1);
}
