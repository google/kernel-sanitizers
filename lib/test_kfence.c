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

#define MAX_ITER 100
static void *alloc_from_kfence(size_t size, gfp_t gfp)
{
	void *res;
	int i;

	for (i = 0; i < MAX_ITER; i++) {
		res = kmalloc(size, gfp);
		if (is_kfence_allocation(res))
			return res;
		kfree(res);
		/* TODO: sleep time depends on heartbeat period. */
		msleep(100);
	}
	return NULL;
}

static int do_test_oob(size_t size)
{
	void *buffer;
	char *c;

	buffer = alloc_from_kfence(size, GFP_KERNEL);
	if (!buffer)
		return 1;
	c = ((char *)buffer) + size + 1;
	READ_ONCE(*c);
	kfree(buffer);
	return 0;
}

static int do_test_uaf(size_t size)
{
	void *buffer;
	char *c;

	buffer = alloc_from_kfence(size, GFP_KERNEL);
	if (!buffer)
		return 1;
	c = (char *)buffer;
	kfree(buffer);
	READ_ONCE(*c);
	return 0;
}

static int __init test_kfence_init(void)
{
	int failures = 0;

	failures += do_test_oob(32);
	failures += do_test_uaf(32);

	if (failures == 0)
		pr_info("all tests passed!\n");
	else
		pr_info("failures: %d\n", failures);

	return failures ? -EINVAL : 0;
}
module_init(test_kfence_init);

MODULE_LICENSE("GPL");
