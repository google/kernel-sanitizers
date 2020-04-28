// SPDX-License-Identifier: GPL-2.0
/*
 * Test cases for KFENCE memory safety error detector.
 * TODO: switch to KUnit.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/slab_def.h>

static bool is_kfence_allocation(void *ptr)
{
	struct page *page = virt_to_page(ptr);

	if (!page || !PageSlab(page))
		return false;
	if (page->slab_cache && page->slab_cache->name)
		return !strcmp(page->slab_cache->name, "kfence_slab_cache");
	return false;
}

/*
 * TODO: the more caches we support, the fewer is the probability of allocating
 * an object from a particular cache. This can be fixed by a test-only hook that
 * forces KFENCE to narrow down the set of tracked caches.
 */
#define MAX_ITER 2000

/*
 * Allocate using either kmalloc or the given memory cache till we get an object
 * from KFENCE pool or hit the maximum number of attempts.
 */
static void *alloc_from_kfence(struct kmem_cache *s, size_t size, gfp_t gfp, const char *caller)
{
	void *res;
	int i;

	for (i = 0; i < MAX_ITER; i++) {
		if (!s)
			res = kmalloc(size, gfp);
		else
			res = kmem_cache_alloc(s, gfp);
		if (is_kfence_allocation(res))
			return res;
		if (!s)
			kfree(res);
		else
			kmem_cache_free(s, res);
		/* TODO: sleep time depends on heartbeat period. */
		msleep(100);
	}
	pr_err("alloc_from_kfence() failed in %s\n", caller);
	return NULL;
}

static int do_test_oob(size_t size)
{
	void *buffer;
	char *c;

	buffer = alloc_from_kfence(NULL, size, GFP_KERNEL, __func__);
	if (!buffer)
		return 1;
	/* We will hit KFENCE redzone at one of the buffer's ends. */
	c = ((char *)buffer) + size + 1;
	READ_ONCE(*c);
	c = ((char *)buffer) - 1;
	READ_ONCE(*c);
	kfree(buffer);
	return 0;
}

static int do_test_uaf(size_t size)
{
	void *buffer;
	char *c;

	buffer = alloc_from_kfence(NULL, size, GFP_KERNEL, __func__);
	if (!buffer)
		return 1;
	c = (char *)buffer;
	kfree(buffer);
	READ_ONCE(*c);
	return 0;
}

/* Test cache creation, shrinking and destroying with KFENCE. */
static int do_test_shrink(int size)
{
	struct kmem_cache *c;
	void *buffer;

	/*
	 * Use SLAB_NOLEAKTRACE to prevent merging this cache with existing
	 * caches. Any other flag from SLAB_NEVER_MERGE except
	 * SLAB_TYPESAFE_BY_RCU (which disables KFENCE for a cache) would also
	 * work.
	 */
	c = kmem_cache_create("test_cache", size, 1, SLAB_NOLEAKTRACE, NULL);
	buffer = alloc_from_kfence(NULL, size, GFP_KERNEL, __func__);
	if (!buffer)
		return 1;
	kmem_cache_shrink(c);
	kmem_cache_free(c, buffer);
	kmem_cache_destroy(c);
	return 0;
}

static int __init test_kfence_init(void)
{
	int failures = 0;

	failures += do_test_oob(32);
	failures += do_test_uaf(32);
	failures += do_test_shrink(32);

	if (failures == 0)
		pr_info("all tests passed!\n");
	else
		pr_info("failures: %d\n", failures);

	return failures ? -EINVAL : 0;
}
module_init(test_kfence_init);

MODULE_LICENSE("GPL");
