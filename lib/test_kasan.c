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
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>

static inline void run_test(void (*test_func) (void), const char *name)
{
	pr_info("##### TEST_START %s\n", name);
	(*test_func) ();
	pr_info("##### TEST_END %s\n", name);
}

static inline void fail(const char *message)
{
	pr_err("##### fail %s\n", message);
}

static inline void assert_oob(void *ptr, const char *function)
{
	pr_info("##### ASSERT 'BUG: AddressSanitizer: out of bounds access in %s.*"
			"at addr %p'\n", function, ptr);
}

static inline void assert_uaf(void *ptr, const char *function)
{
	pr_info("##### ASSERT 'BUG: AddressSanitizer: use after free in %s.* at addr %p'\n",
			function, ptr);
}

static noinline void __init kmalloc_oob_right(void)
{
	char *ptr;
	size_t size = 123;
	volatile char x;

	ptr = kmalloc(size , GFP_KERNEL);
	if (!ptr) {
		fail("Allocation failed");
		return;
	}

	x = ptr[size];
	kfree(ptr);

	assert_oob(ptr + size, "kmalloc_oob_right");
}

static noinline void __init kmalloc_oob_left(void)
{
	char *ptr;
	size_t size = 15;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		fail("Allocation failed");
		return;
	}

	*ptr = *(ptr - 1);
	kfree(ptr);

	assert_oob(ptr - 1, "kmalloc_oob_left");
}

static noinline void __init kmalloc_node_oob_right(void)
{
	char *ptr;
	size_t size = 4096;
	volatile char x;

	ptr = kmalloc_node(size, GFP_KERNEL, 0);
	if (!ptr) {
		fail("Allocation failed");
		return;
	}

	x = ptr[size];
	kfree(ptr);

	assert_oob(ptr + size, "kmalloc_node_oob_right");
}

static noinline void __init kmalloc_large_oob_rigth(void)
{
	char *ptr;
	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
	volatile char x;

	ptr = kmalloc(size , GFP_KERNEL);
	if (!ptr) {
		fail("Allocation failed");
		return;
	}
	x = ptr[size];
	kfree(ptr);

	assert_oob(ptr + size, "kmalloc_large_oob_rigth");
}

static noinline void __init kmalloc_oob_krealloc_more(void)
{
	char *ptr1, *ptr2;
	size_t size1 = 17;
	size_t size2 = 19;
	volatile char x;

	ptr1 = kmalloc(size1, GFP_KERNEL);
	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
	if (!ptr1 || !ptr2) {
		fail("Allocation failed");
		kfree(ptr1);
		return;
	}

	x = ptr2[size2];
	kfree(ptr2);

	assert_oob(ptr2 + size2, "kmalloc_oob_krealloc_more");
}

static noinline void __init kmalloc_oob_krealloc_less(void)
{
	char *ptr1, *ptr2;
	size_t size1 = 17;
	size_t size2 = 15;
	volatile char x;

	ptr1 = kmalloc(size1, GFP_KERNEL);
	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
	if (!ptr1 || !ptr2) {
		fail("Allocation failed");
		kfree(ptr1);
		return;
	}
	x = ptr2[size1];
	kfree(ptr2);

	assert_oob(ptr2 + size1, "kmalloc_oob_krealloc_less");
}

static noinline void __init kmalloc_oob_16(void)
{
	struct {
		u64 words[2];
	} *ptr1, *ptr2;

	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
	if (!ptr1 || !ptr2) {
		fail("Allocation failed");
		kfree(ptr1);
		kfree(ptr2);
		return;
	}
	*ptr2 = *ptr1;
	kfree(ptr1);
	kfree(ptr2);

	assert_oob(ptr1, "kmalloc_oob_16");
}

static noinline void __init kmalloc_oob_in_memset(void)
{
	char *ptr;
	size_t size = 666;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		fail("Allocation failed");
		return;
	}

	memset(ptr, 0, size+5);
	kfree(ptr);

	assert_oob(ptr, "memset");
}

static noinline void __init kmalloc_uaf(void)
{
	char *ptr;
	size_t size = 10;
	volatile char x;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		fail("Allocation failed");
		return;
	}

	kfree(ptr);
	x = *(ptr + 8);

	assert_uaf(ptr + 8, "kmalloc_uaf");
}

static noinline void __init kmalloc_uaf_memset(void)
{
	char *ptr;
	size_t size = 33;

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		fail("Allocation failed");
		return;
	}

	kfree(ptr);
	memset(ptr, 0, size);

	assert_uaf(ptr, "memset");
}

static noinline void __init kmalloc_uaf2(void)
{
	char *ptr1, *ptr2;
	size_t size = 43;
	volatile char x;

	ptr1 = kmalloc(size, GFP_KERNEL);
	if (!ptr1) {
		fail("Allocation failed");
		return;
	}

	kfree(ptr1);
	ptr2 = kmalloc(size, GFP_KERNEL);
	if (!ptr2) {
		fail("Allocation failed");
		return;
	}

	x = ptr1[40];
	kfree(ptr2);
	assert_uaf(ptr1 + 40, "kmalloc_uaf2");
}

static noinline void __init kmem_cache_oob(void)
{
	char *p;
	size_t size = 200;
	struct kmem_cache *cache = kmem_cache_create("test_cache",
						size, 0,
						0, NULL);
	if (!cache) {
		fail("Cache allocation failed");
		return;
	}
	p = kmem_cache_alloc(cache, GFP_KERNEL);
	if (!p) {
		fail("Allocation failed");
		kmem_cache_destroy(cache);
		return;
	}

	*p = p[size];
	kmem_cache_free(cache, p);
	kmem_cache_destroy(cache);

	/* TODO: fix - UAF displayed instead */
	assert_oob(p + size, "kmem_cache_oob");
}

char global_array[10];

static noinline void __init kasan_global_oob(void)
{
	volatile int i = 3;
	char *p = &global_array[ARRAY_SIZE(global_array) + i];

	*(volatile char *)p;
	assert_oob(p, __func__);
}

static noinline void __init kasan_stack_oob(void)
{
	char stack_array[10];
	volatile int i = 0;
	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];

	*(volatile char *)p;
	assert_oob(p, __func__);
}

int __init kmalloc_tests_init(void)
{
	run_test(kmalloc_oob_right, "kmalloc_oob_right");
	run_test(kmalloc_oob_left, "kmalloc_oob_left");
	run_test(kmalloc_node_oob_right, "kmalloc_node_oob_right");
	run_test(kmalloc_large_oob_rigth, "kmalloc_large_oob_rigth");
	run_test(kmalloc_oob_krealloc_more, "kmalloc_oob_krealloc_more");
	run_test(kmalloc_oob_krealloc_less, "kmalloc_oob_krealloc_less");
	run_test(kmalloc_oob_16, "kmalloc_oob_16");
	run_test(kmalloc_oob_in_memset, "kmalloc_oob_in_memset");
	run_test(kmalloc_uaf, "kmalloc_uaf");
	run_test(kmalloc_uaf_memset, "kmalloc_uaf_memset");
	run_test(kmalloc_uaf2, "kmalloc_uaf2");
	run_test(kmem_cache_oob, "kmem_cache_oob");
	run_test(kasan_global_oob, "kasan_global_oob");
	run_test(kasan_stack_oob, "kasan_stack_oob");
	return -EAGAIN;
}

module_init(kmalloc_tests_init);
MODULE_LICENSE("GPL");
