/*
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
 *
 * Some of code borrowed from https://github.com/xairy/linux by
 *        Andrey Konovalov <andreyknvl@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kasan.h>
#include <linux/memcontrol.h> /* for ../slab.h */

#include "kasan.h"
#include "../slab.h"

/* Shadow layout customization. */
#define SHADOW_BYTES_PER_BLOCK 1
#define SHADOW_BLOCKS_PER_ROW 16
#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_BLOCK)
#define SHADOW_ROWS_AROUND_ADDR 5

static unsigned long find_first_bad_addr(unsigned long addr, size_t size)
{
	u8 shadow_val = *(u8 *)kasan_mem_to_shadow(addr);
	unsigned long first_bad_addr = addr;

	while (!shadow_val && first_bad_addr < addr + size) {
		first_bad_addr += KASAN_SHADOW_SCALE_SIZE;
		shadow_val = *(u8 *)kasan_mem_to_shadow(first_bad_addr);
	}
	return first_bad_addr;
}

static void print_error_description(struct access_info *info)
{
	const char *bug_type = "unknown crash";
	u8 shadow_val;

	info->first_bad_addr = find_first_bad_addr(info->access_addr,
						info->access_size);

	shadow_val = *(u8 *)kasan_mem_to_shadow(info->first_bad_addr);

	switch (shadow_val) {
	case KASAN_PAGE_REDZONE:
	case KASAN_KMALLOC_REDZONE:
	case KASAN_GLOBAL_REDZONE:
	case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
		bug_type = "out of bounds access";
		break;
	case KASAN_FREE_PAGE:
	case KASAN_KMALLOC_FREE:
		bug_type = "use after free";
		break;
	case KASAN_SHADOW_GAP:
		bug_type = "wild memory access";
		break;
	case KASAN_STACK_LEFT:
	case KASAN_STACK_MID:
	case KASAN_STACK_RIGHT:
	case KASAN_STACK_PARTIAL:
		bug_type = "out-of-bounds on stack";
		break;
	}

	pr_err("BUG: AddressSanitizer: %s in %pS at addr %p\n",
		bug_type, (void *)info->ip,
		(void *)info->access_addr);
	pr_err("%s of size %zu by task %s/%d\n",
		info->is_write ? "Write" : "Read",
		info->access_size, current->comm, task_pid_nr(current));
}

static inline bool kernel_or_module_addr(unsigned long addr)
{
	return (addr >= (unsigned long)_stext && addr < (unsigned long)_end)
		|| (addr >= MODULES_VADDR  && addr < MODULES_END);
}

static inline bool init_task_stack_addr(unsigned long addr)
{
	return addr >= (unsigned long)&init_thread_union.stack &&
		(addr <= (unsigned long)&init_thread_union.stack +
			sizeof(init_thread_union.stack));
}

static void print_address_description(struct access_info *info)
{
	struct page *page;
	unsigned long addr = info->access_addr;

	if ((addr >= PAGE_OFFSET && addr < (unsigned long)high_memory)) {
		page = virt_to_head_page((void *)addr);
		if (PageSlab(page)) {
			void *object;
			struct kmem_cache *cache = page->slab_cache;
			void *last_object;

			object = virt_to_obj(cache, page_address(page),
					(void *)info->access_addr);
			last_object = page_address(page) +
					page->objects * cache->size;

			if (unlikely(object > last_object))
				object = last_object; /* we hit into padding */

			object_err(cache, page, object, "kasan: bad access detected");
			return;
		}
		dump_page(page, "kasan: bad access detected");
		dump_stack();
		return;
	}

	if (kernel_or_module_addr(addr)) {
		if (!init_task_stack_addr(addr))
			pr_err("Address belongs to variable %pS\n",
				(void *)addr);
	}
	dump_stack();
}

static bool row_is_guilty(unsigned long row, unsigned long guilty)
{
	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
}

static int shadow_pointer_offset(unsigned long row, unsigned long shadow)
{
	/* The length of ">ff00ff00ff00ff00: " is
	 *    3 + (BITS_PER_LONG/8)*2 chars.
	 */
	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
}

static void print_shadow_for_address(unsigned long addr)
{
	int i;
	unsigned long shadow = kasan_mem_to_shadow(addr);
	unsigned long aligned_shadow = round_down(shadow, SHADOW_BYTES_PER_ROW)
		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;

	pr_err("Memory state around the buggy address:\n");

	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
		unsigned long kaddr = kasan_shadow_to_mem(aligned_shadow);
		char buffer[4 + (BITS_PER_LONG/8)*2];

		snprintf(buffer, sizeof(buffer),
			(i == 0) ? ">%lx: " : " %lx: ", kaddr);

		kasan_disable_local();
		print_hex_dump(KERN_ERR, buffer,
			DUMP_PREFIX_NONE, SHADOW_BYTES_PER_ROW, 1,
			(void *)aligned_shadow, SHADOW_BYTES_PER_ROW, 0);
		kasan_enable_local();

		if (row_is_guilty(aligned_shadow, shadow))
			pr_err("%*c\n",
				shadow_pointer_offset(aligned_shadow, shadow),
				'^');

		aligned_shadow += SHADOW_BYTES_PER_ROW;
	}
}

static DEFINE_SPINLOCK(report_lock);

void kasan_report_error(struct access_info *info)
{
	unsigned long flags;

	spin_lock_irqsave(&report_lock, flags);
	pr_err("================================="
		"=================================\n");
	print_error_description(info);
	print_address_description(info);
	print_shadow_for_address(info->first_bad_addr);
	pr_err("================================="
		"=================================\n");
	spin_unlock_irqrestore(&report_lock, flags);
}

void kasan_report_user_access(struct access_info *info)
{
	unsigned long flags;

	spin_lock_irqsave(&report_lock, flags);
	pr_err("================================="
		"=================================\n");
	pr_err("BUG: AddressSanitizer: user-memory-access on address %lx\n",
		info->access_addr);
	pr_err("%s of size %zu by thread T%d:\n",
		info->is_write ? "Write" : "Read",
		info->access_size, current->pid);
	dump_stack();
	pr_err("================================="
		"=================================\n");
	spin_unlock_irqrestore(&report_lock, flags);
}

#define DEFINE_ASAN_REPORT_LOAD(size)                     \
void __asan_report_load##size##_noabort(unsigned long addr) \
{                                                         \
	kasan_report(addr, size, false);                  \
}                                                         \
EXPORT_SYMBOL(__asan_report_load##size##_noabort)

#define DEFINE_ASAN_REPORT_STORE(size)                     \
void __asan_report_store##size##_noabort(unsigned long addr) \
{                                                          \
	kasan_report(addr, size, true);                    \
}                                                          \
EXPORT_SYMBOL(__asan_report_store##size##_noabort)

DEFINE_ASAN_REPORT_LOAD(1);
DEFINE_ASAN_REPORT_LOAD(2);
DEFINE_ASAN_REPORT_LOAD(4);
DEFINE_ASAN_REPORT_LOAD(8);
DEFINE_ASAN_REPORT_LOAD(16);
DEFINE_ASAN_REPORT_STORE(1);
DEFINE_ASAN_REPORT_STORE(2);
DEFINE_ASAN_REPORT_STORE(4);
DEFINE_ASAN_REPORT_STORE(8);
DEFINE_ASAN_REPORT_STORE(16);

void __asan_report_load_n_noabort(unsigned long addr, size_t size)
{
	kasan_report(addr, size, false);
}
EXPORT_SYMBOL(__asan_report_load_n_noabort);

void __asan_report_store_n_noabort(unsigned long addr, size_t size)
{
	kasan_report(addr, size, true);
}
EXPORT_SYMBOL(__asan_report_store_n_noabort);
