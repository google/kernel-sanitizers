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

#define SIDE_LEFT 1
#define SIDE_RIGHT 2
#define SIDE_BOTH (SIDE_LEFT | SIDE_RIGHT)

/*
 * Allocate using either kmalloc or the currently used memory cache till we get
 * an object from KFENCE pool or hit the maximum number of attempts.
 */
static void *alloc_from_kfence(size_t size, gfp_t gfp, int side,
			       const char *caller)
{
	void *res;
	unsigned long stop_at;
	unsigned long rem;

	if (!side)
		return NULL;

	stop_at = jiffies + msecs_to_jiffies(MAX_DELAY_MSEC);
	do {
		if (!current_cache)
			res = kmalloc(size, gfp);
		else
			res = kmem_cache_alloc(current_cache, gfp);
		if (is_kfence_addr(res)) {
			rem = (unsigned long)res % PAGE_SIZE;
			if (((side & SIDE_LEFT) && (!rem)) ||
			    ((side & SIDE_RIGHT) && rem))
				return res;
		}
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
	buffer = alloc_from_kfence(size, GFP_KERNEL, SIDE_BOTH, __func__);
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

/*
 * In the following situation:
 *   char *p = kmalloc(73, GFP_KERNEL);
 *   READ_ONCE(p[73]);
 * @p is aligned on 8 (alignment of kmalloc-96), therefore the allocated object
 * does not adhere to either of the page boundaries. Therefore an immediate
 * buffer overflow won't trigger a page fault.
 *
 * This test checks that KFENCE is unable to detect such OOBs, but is able to
 * detect an OOB that touches the next 8 bytes past the object.
 */
static int do_test_kmalloc_aligned_oob_read(void)
{
	void *buffer;
	char *c;
	const size_t size = 73;

	buffer = alloc_from_kfence(size, GFP_KERNEL, SIDE_RIGHT, __func__);
	if (!buffer)
		return 1;
	/*
		 * The object is offset to the right, so there won't be OOBs to
		 * the left of it.
		 */
	c = ((char *)buffer) - 1;
	READ_ONCE(*c);

	/*
		 * @buffer must be aligned on 8, therefore buffer + size + 1
		 * belongs to the same page - no immediate OOB.
		 */
	c = ((char *)buffer) + size + 1;
	READ_ONCE(*c);

	/* Overflowing the buffer by 8 bytes will result in an OOB. */
	c = ((char *)buffer) + size + 8;
	READ_ONCE(*c);

	free_to_kfence(buffer);
	return 0;
}

static int do_test_kmalloc_aligned_oob_write(void)
{
	void *buffer;
	unsigned char *c, value;
	const size_t size = 73;

	buffer = alloc_from_kfence(size, GFP_KERNEL, SIDE_RIGHT, __func__);
	if (!buffer)
		return 1;

	/*
		 * The object is offset to the right, so we won't get a page
		 * fault immediately after it.
		 */
	c = ((char *)buffer) + size + 1;
	value = READ_ONCE(*c);
	WRITE_ONCE(*c, value + 1);

	free_to_kfence(buffer);
	return 0;
}

static int do_test_uaf(size_t size, bool use_cache)
{
	void *buffer;
	char *c;
	int res = 0;

	if (use_cache)
		if (!setup_cache(size))
			return 1;
	buffer = alloc_from_kfence(size, GFP_KERNEL, SIDE_BOTH, __func__);
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
	buffer = alloc_from_kfence(size, GFP_KERNEL, SIDE_BOTH, __func__);
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
	failures += do_test_kmalloc_aligned_oob_read();
	failures += do_test_kmalloc_aligned_oob_write();
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
