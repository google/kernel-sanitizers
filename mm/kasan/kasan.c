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
void poison_shadow(const void *address, size_t size, u8 value)
{
	unsigned long shadow_start, shadow_end;
	unsigned long addr = (unsigned long)address;

	shadow_start = kasan_mem_to_shadow(addr);
	shadow_end = kasan_mem_to_shadow(addr + size);

	memset((void *)shadow_start, value, shadow_end - shadow_start);
}

void unpoison_shadow(const void *address, size_t size)
{
	poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow((unsigned long)address
						+ size);
		*shadow = size & KASAN_SHADOW_MASK;
	}
}

static __always_inline bool address_is_poisoned(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);

	if (shadow_value != 0) {
		s8 last_byte = addr & KASAN_SHADOW_MASK;
		return last_byte >= shadow_value;
	}
	return false;
}

static __always_inline unsigned long memory_is_poisoned(unsigned long addr,
							size_t size)
{
	unsigned long end = addr + size;
	for (; addr < end; addr++)
		if (unlikely(address_is_poisoned(addr)))
			return addr;
	return 0;
}

static __always_inline void check_memory_region(unsigned long addr,
						size_t size, bool write)
{
	unsigned long access_addr;
	struct access_info info;

	if (unlikely(size == 0))
		return;

	if (unlikely(addr < PAGE_OFFSET)) {
		info.access_addr = addr;
		info.access_size = size;
		info.is_write = write;
		info.ip = _RET_IP_;
		kasan_report_user_access(&info);
		return;
	}

	access_addr = memory_is_poisoned(addr, size);
	if (likely(access_addr == 0))
		return;

	info.access_addr = access_addr;
	info.access_size = size;
	info.is_write = write;
	info.ip = _RET_IP_;
	kasan_report_error(&info);
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

/* to shut up compiler complains */
void __asan_init_v3(void) {}
EXPORT_SYMBOL(__asan_init_v3);
void __asan_handle_no_return(void) {}
EXPORT_SYMBOL(__asan_handle_no_return);
