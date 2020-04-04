// SPDX-License-Identifier: GPL-2.0
/*
 * Test cases for SL[AOU]B/page initialization at alloc/free time.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/slab.h>

#define MAX_ITER 1000
int do_test(size_t size)
{
	int i;
	volatile char *c;
	void **buffers;

	buffers = kmalloc_array(MAX_ITER, sizeof(void *), GFP_KERNEL);
	for (i = 0; i < MAX_ITER; i++) {
		buffers[i] = kmalloc(size, GFP_KERNEL);
		c = ((char *)buffers[i]) + size + 1;
		(void)*c;
		/* TODO: sleep time depends on heartbeat period. */
		msleep(100);
	}
	for (i = 0; i < MAX_ITER; i++) {
		kfree(buffers[i]);
	}
	kfree(buffers);
	return 0;
}

static int __init test_kfence_init(void)
{
	int failures = 0;

	failures += do_test(32);

	if (failures == 0)
		pr_info("all tests passed!\n");
	else
		pr_info("failures: %d\n", failures);

	return failures ? -EINVAL : 0;
}
module_init(test_kfence_init);

MODULE_LICENSE("GPL");
