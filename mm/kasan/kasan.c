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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define DISABLE_BRANCH_PROFILING

#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/kasan.h>
#include <linux/memcontrol.h>

#include "kasan.h"
#include "../slab.h"

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 */
static void kasan_poison_shadow(const void *address, size_t size, u8 value)
{
	unsigned long shadow_start, shadow_end;
	unsigned long addr = (unsigned long)address;

	shadow_start = kasan_mem_to_shadow(addr);
	shadow_end = kasan_mem_to_shadow(addr + size);

	memset((void *)shadow_start, value, shadow_end - shadow_start);
}

void kasan_unpoison_shadow(const void *address, size_t size)
{
	kasan_poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow((unsigned long)address
						+ size);
		*shadow = size & KASAN_SHADOW_MASK;
	}
}

static __always_inline bool memory_is_poisoned_1(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);

	if (unlikely(shadow_value)) {
		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
		return unlikely(last_accessible_byte >= shadow_value);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_2(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow(addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 1))
			return true;

		if (likely(((addr + 1) & KASAN_SHADOW_MASK) != 0))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_4(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow(addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 3))
			return true;

		if (likely(((addr + 3) & KASAN_SHADOW_MASK) >= 3))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_8(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow(addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 7))
			return true;

		if (likely(((addr + 7) & KASAN_SHADOW_MASK) >= 7))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_16(unsigned long addr)
{
	u32 *shadow_addr = (u32 *)kasan_mem_to_shadow(addr);

	if (unlikely(*shadow_addr)) {
		u16 shadow_first_bytes = *(u16 *)shadow_addr;
		s8 last_byte = (addr + 15) & KASAN_SHADOW_MASK;

		if (unlikely(shadow_first_bytes))
			return true;

		if (likely(!last_byte))
			return false;

		return memory_is_poisoned_1(addr + 15);
	}

	return false;
}

static __always_inline unsigned long bytes_is_zero(unsigned long start,
					size_t size)
{
	while (size) {
		if (unlikely(*(u8 *)start))
			return start;
		start++;
		size--;
	}

	return 0;
}

static __always_inline unsigned long memory_is_zero(unsigned long start,
						unsigned long end)
{
	unsigned int prefix = start % 8;
	unsigned int words;
	unsigned long ret;

	if (end - start <= 16)
		return bytes_is_zero(start, end - start);

	if (prefix) {
		prefix = 8 - prefix;
		ret = bytes_is_zero(start, prefix);
		if (unlikely(ret))
			return ret;
		start += prefix;
	}

	words = (end - start) / 8;
	while (words) {
		if (unlikely(*(u64 *)start))
			return bytes_is_zero(start, 8);
		start += 8;
		words--;
	}

	return bytes_is_zero(start, (end - start) % 8);
}

static __always_inline bool memory_is_poisoned_n(unsigned long addr,
						size_t size)
{
	unsigned long ret;

	ret = memory_is_zero(kasan_mem_to_shadow(addr),
			kasan_mem_to_shadow(addr + size - 1) + 1);

	if (unlikely(ret)) {
		unsigned long last_byte = addr + size - 1;
		s8 *last_shadow = (s8 *)kasan_mem_to_shadow(last_byte);

		if (unlikely(ret != (unsigned long)last_shadow ||
			((last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
			return true;
	}
	return false;
}

static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
{
	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			return memory_is_poisoned_1(addr);
		case 2:
			return memory_is_poisoned_2(addr);
		case 4:
			return memory_is_poisoned_4(addr);
		case 8:
			return memory_is_poisoned_8(addr);
		case 16:
			return memory_is_poisoned_16(addr);
		default:
			BUILD_BUG();
		}
	}

	return memory_is_poisoned_n(addr, size);
}


static __always_inline void check_memory_region(unsigned long addr,
						size_t size, bool write)
{
	struct access_info info;

	if (unlikely(size == 0))
		return;

	if (unlikely(addr < kasan_shadow_to_mem(KASAN_SHADOW_START))) {
		info.access_addr = addr;
		info.access_size = size;
		info.is_write = write;
		info.ip = _RET_IP_;
		kasan_report_user_access(&info);
		return;
	}

	if (likely(!memory_is_poisoned(addr, size)))
		return;

	kasan_report(addr, size, write);
}

void kasan_alloc_pages(struct page *page, unsigned int order)
{
	if (likely(!PageHighMem(page)))
		kasan_unpoison_shadow(page_address(page), PAGE_SIZE << order);
}

void kasan_free_pages(struct page *page, unsigned int order)
{
	if (likely(!PageHighMem(page)))
		kasan_poison_shadow(page_address(page),
				PAGE_SIZE << order,
				KASAN_FREE_PAGE);
}

void kasan_mark_slab_padding(struct kmem_cache *s, void *object,
			struct page *page)
{
	unsigned long object_end = (unsigned long)object + s->size;
	unsigned long padding_start = round_up(object_end,
					KASAN_SHADOW_SCALE_SIZE);
	unsigned long padding_end = (unsigned long)page_address(page) +
					(PAGE_SIZE << compound_order(page));
	size_t size = padding_end - padding_start;

	kasan_poison_shadow((void *)padding_start, size, KASAN_SLAB_PADDING);
}

void kasan_slab_alloc(struct kmem_cache *cache, void *object)
{
	kasan_kmalloc(cache, object, cache->object_size);
}

void kasan_slab_free(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->size;
	unsigned long rounded_up_size = round_up(size, KASAN_SHADOW_SCALE_SIZE);

	/* RCU slabs could be legally used after free within the RCU period */
	if (unlikely(cache->flags & SLAB_DESTROY_BY_RCU))
		return;

	kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
}

void kasan_kmalloc(struct kmem_cache *cache, const void *object, size_t size)
{
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (unlikely(object == NULL))
		return;

	redzone_start = round_up((unsigned long)(object + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (unsigned long)object + cache->size;

	kasan_unpoison_shadow(object, size);
	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
		KASAN_KMALLOC_REDZONE);

}
EXPORT_SYMBOL(kasan_kmalloc);

void kasan_kmalloc_large(const void *ptr, size_t size)
{
	struct page *page;
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (unlikely(ptr == NULL))
		return;

	page = virt_to_page(ptr);
	redzone_start = round_up((unsigned long)(ptr + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (unsigned long)ptr + (PAGE_SIZE << compound_order(page));

	kasan_unpoison_shadow(ptr, size);
	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
		KASAN_PAGE_REDZONE);
}

void kasan_krealloc(const void *object, size_t size)
{
	struct page *page;

	if (unlikely(object == ZERO_SIZE_PTR))
		return;

	page = virt_to_head_page(object);

	if (unlikely(!PageSlab(page)))
		kasan_kmalloc_large(object, size);
	else
		kasan_kmalloc(page->slab_cache, object, size);
}

void kasan_kfree_large(const void *ptr)
{
	struct page *page = virt_to_page(ptr);

	kasan_poison_shadow(ptr, PAGE_SIZE << compound_order(page),
			KASAN_FREE_PAGE);
}

void __asan_load1(unsigned long addr)
{
	check_memory_region(addr, 1, false);
}
EXPORT_SYMBOL(__asan_load1);

void __asan_load2(unsigned long addr)
{
	check_memory_region(addr, 2, false);
}
EXPORT_SYMBOL(__asan_load2);

void __asan_load4(unsigned long addr)
{
	check_memory_region(addr, 4, false);
}
EXPORT_SYMBOL(__asan_load4);

void __asan_load8(unsigned long addr)
{
	check_memory_region(addr, 8, false);
}
EXPORT_SYMBOL(__asan_load8);

void __asan_load16(unsigned long addr)
{
	check_memory_region(addr, 16, false);
}
EXPORT_SYMBOL(__asan_load16);

void __asan_loadN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, false);
}
EXPORT_SYMBOL(__asan_loadN);

void __asan_store1(unsigned long addr)
{
	check_memory_region(addr, 1, true);
}
EXPORT_SYMBOL(__asan_store1);

void __asan_store2(unsigned long addr)
{
	check_memory_region(addr, 2, true);
}
EXPORT_SYMBOL(__asan_store2);

void __asan_store4(unsigned long addr)
{
	check_memory_region(addr, 4, true);
}
EXPORT_SYMBOL(__asan_store4);

void __asan_store8(unsigned long addr)
{
	check_memory_region(addr, 8, true);
}
EXPORT_SYMBOL(__asan_store8);

void __asan_store16(unsigned long addr)
{
	check_memory_region(addr, 16, true);
}
EXPORT_SYMBOL(__asan_store16);

void __asan_storeN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, true);
}
EXPORT_SYMBOL(__asan_storeN);

/* to shut up compiler complaints */
void __asan_handle_no_return(void) {}
EXPORT_SYMBOL(__asan_handle_no_return);
