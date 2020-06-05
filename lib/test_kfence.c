// SPDX-License-Identifier: GPL-2.0
/*
 * Test cases for KFENCE memory safety error detector.
 * TODO: switch to KUnit.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/kfence.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
/*
 * For struct kmem_cache. We cannot include <linux/sl[au]b_def.h>, because it
 * does not define struct memcg_cache_params used by kmem_cache.
 */
#include "../mm/slab.h"

/*
 * TODO: the more caches we support, the fewer is the probability of allocating
 * an object from a particular cache. This can be fixed by a test-only hook that
 * forces KFENCE to narrow down the set of tracked caches.
 */
#define MAX_DELAY_MSEC 1000

/* Cache used by tests. If empty, allocate from kmalloc instead. */
static struct kmem_cache *current_cache;

static bool setup_cache(size_t size)
{
	/*
	 * Use SLAB_NOLEAKTRACE to prevent merging this cache with existing
	 * caches. Any other flag from SLAB_NEVER_MERGE except
	 * SLAB_TYPESAFE_BY_RCU (which disables KFENCE for a cache) would also
	 * work.
	 * Use SLAB_ACCOUNT to allocate via memcg, if enabled.
	 */
	current_cache = kmem_cache_create(
		"test_cache", size, 1, SLAB_NOLEAKTRACE | SLAB_ACCOUNT, NULL);
	if (!current_cache)
		return false;
	return true;
}

static void teardown_cache(void)
{
	kmem_cache_destroy(current_cache);
	current_cache = NULL;
}

static void free_to_kfence(void *ptr)
{
	if (!current_cache)
		kfree(ptr);
	else
		kmem_cache_free(current_cache, ptr);
}

/*
 * Allocate using either kmalloc or the currently used memory cache till we get
 * an object from KFENCE pool or hit the maximum number of attempts.
 */
static void *alloc_from_kfence(size_t size, gfp_t gfp, const char *caller)
{
	void *res;
	unsigned long stop_at;

	stop_at = jiffies + msecs_to_jiffies(MAX_DELAY_MSEC);
	do {
		if (!current_cache)
			res = kmalloc(size, gfp);
		else
			res = kmem_cache_alloc(current_cache, gfp);
		if (is_kfence_addr(res))
			return res;
		free_to_kfence(res);
	} while (jiffies < stop_at);
	pr_err("alloc_from_kfence() failed in %s\n", caller);
	return NULL;
}

static int do_test_oob(size_t size, bool use_cache)
{
	void *buffer;
	char *c;
	int res = 0;

	if (use_cache)
		if (!setup_cache(size))
			return 1;
	buffer = alloc_from_kfence(size, GFP_KERNEL, __func__);
	if (buffer) {
		/* We will hit KFENCE redzone at one of the buffer's ends. */
		c = ((char *)buffer) + size + 1;
		READ_ONCE(*c);
		c = ((char *)buffer) - 1;
		READ_ONCE(*c);
		free_to_kfence(buffer);
	} else {
		res = 1;
	}
	if (use_cache)
		teardown_cache();
	return res;
}

static int do_test_uaf(size_t size, bool use_cache)
{
	void *buffer;
	char *c;
	int res = 0;

	if (use_cache)
		if (!setup_cache(size))
			return 1;
	buffer = alloc_from_kfence(size, GFP_KERNEL, __func__);
	if (buffer) {
		c = (char *)buffer;
		free_to_kfence(buffer);
		READ_ONCE(*c);
	} else {
		res = 1;
	}
	if (use_cache)
		teardown_cache();
	return res;
}

/* Test cache creation, shrinking and destroying with KFENCE. */
static int do_test_shrink(int size)
{
	void *buffer;
	int res = 0;

	if (!setup_cache(size))
		return 1;
	buffer = alloc_from_kfence(size, GFP_KERNEL, __func__);
	if (buffer) {
		kmem_cache_shrink(current_cache);
		free_to_kfence(buffer);
	} else {
		res = 1;
	}
	teardown_cache();
	return res;
}

static int __init test_kfence_init(void)
{
	int failures = 0;

	failures += do_test_oob(32, false);
	failures += do_test_oob(32, true);
	failures += do_test_uaf(32, false);
	failures += do_test_uaf(32, true);
	failures += do_test_shrink(32);

	if (failures == 0)
		pr_info("all tests passed!\n");
	else
		pr_info("failures: %d\n", failures);

	return failures ? -EINVAL : 0;
}
module_init(test_kfence_init);

MODULE_LICENSE("GPL");
