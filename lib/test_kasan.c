/*
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define RUN_TEST(test_func) \
	pr_info("##### TEST_START " #test_func  "\n"); \
	test_func(); \
	pr_info("##### TEST_END " #test_func "\n"); \
	while(0)

#define FAIL(message) \
	pr_err("##### FAIL %s\n", message)

#define ASSERT(fmt) \
	pr_info("##### ASSERT '" fmt "'\n");

#define ASSERT_FMT(fmt, ...) \
	pr_info("##### ASSERT '" fmt "'\n", __VA_ARGS__);

#define ASSERT_OOB(ptr) \
	ASSERT_FMT("BUG: AddressSanitizer: out of bounds access in %s.* " \
			"at addr %p", __func__, (ptr))

#define ASSERT_UAF(ptr) \
	ASSERT_FMT("BUG: AddressSanitizer: use after free in %s.* at addr %p",\
			__func__, (ptr))

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>

static noinline void __init kmalloc_oob_right(void)
{
	char *ptr;
	size_t size = 123;

	ptr = kmalloc(size , GFP_KERNEL);
	if (!ptr) {
		FAIL("Allocation failed\n");
		return;
	}

	ptr[size] = 'x';
	kfree(ptr);

	ASSERT_OOB(ptr + size);

}

static noinline void __init kmalloc_oob_left(void)
{
	char *ptr;
	size_t size = 15;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		FAIL("Allocation failed\n");
		return;
	}

	*ptr = *(ptr - 1);
	kfree(ptr);
	ASSERT_OOB(ptr - 1);  // TODO: fix - displays UAF
}

static noinline void __init kmalloc_node_oob_right(void)
{
	char *ptr;
	size_t size = 4096;

	ptr = kmalloc_node(size, GFP_KERNEL, 0);
	if (!ptr) {
		FAIL("Allocation failed\n");
		return;
	}

	ptr[size] = 0;
	kfree(ptr);

	ASSERT_OOB(ptr + size); // TODO: fix - no output
}

static noinline void __init kmalloc_large_oob_rigth(void)
{
	char *ptr;
	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;

	ptr = kmalloc(size , GFP_KERNEL);
	if (!ptr) {
		FAIL("Allocation failed\n");
		return;
	}
	ptr[size] = 0;
	kfree(ptr);

	ASSERT_OOB(ptr + size);
}

static noinline void __init kmalloc_oob_krealloc_more(void)
{
	char *ptr1, *ptr2;
	size_t size1 = 17;
	size_t size2 = 19;

	ptr1 = kmalloc(size1, GFP_KERNEL);
	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
	if (!ptr1 || !ptr2) {
		FAIL("Allocation failed\n");
		kfree(ptr1);
		return;
	}

	ptr2[size2] = 'x';
	kfree(ptr2);

	ASSERT_OOB(ptr2 + size2);
}

static noinline void __init kmalloc_oob_krealloc_less(void)
{
	char *ptr1, *ptr2;
	size_t size1 = 17;
	size_t size2 = 15;

	ptr1 = kmalloc(size1, GFP_KERNEL);
	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
	if (!ptr1 || !ptr2) {
		FAIL("Allocation failed\n");
		kfree(ptr1);
		return;
	}
	ptr2[size1] = 'x';
	kfree(ptr2);

	ASSERT_OOB(ptr2 + size1);
}

static noinline void __init kmalloc_oob_16(void)
{
	struct {
		u64 words[2];
	} *ptr1, *ptr2;

	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
	if (!ptr1 || !ptr2) {
		FAIL("Allocation failed\n");
		kfree(ptr1);
		kfree(ptr2);
		return;
	}
	*ptr1 = *ptr2;
	kfree(ptr1);
	kfree(ptr2);

	ASSERT_OOB(ptr1);
}

static noinline void __init kmalloc_oob_in_memset(void)
{
	char *ptr;
	size_t size = 666;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		FAIL("Allocation failed\n");
		return;
	}

	memset(ptr, 0, size+5);
	kfree(ptr);

	ASSERT_OOB(ptr);
}

static noinline void __init kmalloc_uaf(void)
{
	char *ptr;
	size_t size = 10;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		FAIL("Allocation failed\n");
		return;
	}

	kfree(ptr);
	*(ptr + 8) = 'x';

	ASSERT_UAF(ptr + 8);
}

static noinline void __init kmalloc_uaf_memset(void)
{
	char *ptr;
	size_t size = 33;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		FAIL("Allocation failed\n");
		return;
	}

	kfree(ptr);
	memset(ptr, 0, size);

	ASSERT_UAF(ptr);
}

static noinline void __init kmalloc_uaf2(void)
{
	char *ptr1, *ptr2;
	size_t size = 43;

	ptr1 = kmalloc(size, GFP_KERNEL);
	if (!ptr1) {
		FAIL("Allocation failed\n");
		return;
	}

	kfree(ptr1);
	ptr2 = kmalloc(size, GFP_KERNEL);
	if (!ptr2) {
		FAIL("Allocation failed\n");
		return;
	}

	ptr1[40] = 'x';
	kfree(ptr2);

	ASSERT_UAF(ptr1 + 40); // TODO: fix - no output
}

static noinline void __init kmem_cache_oob(void)
{
	char *p;
	size_t size = 200;
	struct kmem_cache *cache = kmem_cache_create("test_cache",
						size, 0,
						0, NULL);
	if (!cache) {
		FAIL("Cache allocation failed\n");
		return;
	}
	p = kmem_cache_alloc(cache, GFP_KERNEL);
	if (!p) {
		FAIL("Allocation failed\n");
		kmem_cache_destroy(cache);
		return;
	}

	*p = p[size];
	kmem_cache_free(cache, p);
	kmem_cache_destroy(cache);

	ASSERT_OOB(p + size); // TODO: fix - UAF displayed instead
}

int __init kmalloc_tests_init(void)
{
	RUN_TEST(kmalloc_oob_right);
	RUN_TEST(kmalloc_oob_left);
	RUN_TEST(kmalloc_node_oob_right);
	RUN_TEST(kmalloc_large_oob_rigth);
	RUN_TEST(kmalloc_oob_krealloc_more);
	RUN_TEST(kmalloc_oob_krealloc_less);
	RUN_TEST(kmalloc_oob_16);
	RUN_TEST(kmalloc_oob_in_memset);
	RUN_TEST(kmalloc_uaf);
	RUN_TEST(kmalloc_uaf_memset);
	RUN_TEST(kmalloc_uaf2);
	RUN_TEST(kmem_cache_oob);
	return -EAGAIN;
}

module_init(kmalloc_tests_init);
MODULE_LICENSE("GPL");
