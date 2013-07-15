#include <asm/page.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/asan.h>

#include "utils.h"

extern unsigned long max_pfn;

#define SHADOW_SCALE (3)
#define SHADOW_OFFSET 0x36600000
#define SHADOW_GRANULARITY (1 << SHADOW_SCALE)

static inline int addr_is_in_mem(uptr addr)
{
	return (addr >= (uptr)(__va(0)) &&
		addr < (uptr)(__va(max_pfn << PAGE_SHIFT)));
}

static uptr mem_to_shadow(uptr addr)
{
	if (!addr_is_in_mem(addr))
		return 0;
	return ((addr - PAGE_OFFSET) >> SHADOW_SCALE)
		+ PAGE_OFFSET + SHADOW_OFFSET;
}

struct shadow_segment_endpoint {
	u8 *chunk;
	s8 offset; /* In [0, SHADOW_GRANULARITY). */
	s8 value; /* = *chunk. */
};

static void init_shadow_segment_endpoint(struct shadow_segment_endpoint *endp,
					 uptr addr)
{
	CHECK(endp != NULL);
	endp->chunk = (u8 *)mem_to_shadow(addr);
	CHECK(endp->chunk != NULL);
	endp->offset = addr & (SHADOW_GRANULARITY - 1);
	endp->value = *endp->chunk;
}

void asan_init_shadow(void)
{
	uptr shadow_size = (max_pfn << PAGE_SHIFT) >> SHADOW_SCALE;
	printk(KERN_ERR "Shadow size: %lx\n", shadow_size);

	//uptr rv = memblock_find_in_range(0, max_pfn * PAGE_SIZE,
	//	shadow_size, PAGE_SIZE);
	//printk(KERN_ERR "Found free memblock: %lx\n", rv);
	printk(KERN_ERR "Shadow offset: %u\n", SHADOW_OFFSET);
	memblock_reserve(SHADOW_OFFSET, shadow_size);
}

void asan_poison_shadow(const void *addr, uptr size, u8 value)
{
	uptr shadow_beg, shadow_end;

	// CHECK(addr_is_aligned((uptr)addr, SHADOW_GRANULARITY));
	// CHECK(addr_is_aligned((uptr)addr + size, SHADOW_GRANULARITY));
	CHECK(addr_is_in_mem((uptr)addr));
	CHECK(addr_is_in_mem((uptr)addr + size - SHADOW_GRANULARITY));

	shadow_beg = mem_to_shadow((uptr)addr);
	shadow_end = mem_to_shadow((uptr)addr + size - SHADOW_GRANULARITY) + 1;
	memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

void asan_poison_memory(const void *addr, uptr size)
{
	struct shadow_segment_endpoint beg, end;
	s8 value;

	if (size == 0)
		return;

	init_shadow_segment_endpoint(&beg, (uptr)addr);
	init_shadow_segment_endpoint(&end, (uptr)addr + size);

	if (beg.chunk == end.chunk) {
		CHECK(beg.offset < end.offset);
		CHECK(beg.value == end.value);
		value = beg.value;
		if (value > 0 && value <= end.offset) {
			if (beg.offset > 0)
				*beg.chunk = min(value, beg.offset);
			else
				*beg.chunk = ASAN_USER_POISONED_MEMORY;
		}
		return;
	}

	CHECK(beg.chunk < end.chunk);
	if (beg.offset > 0) {
		if (beg.value == 0)
			*beg.chunk = beg.offset;
		else
			*beg.chunk = min(beg.value, beg.offset);
		beg.chunk++;
	}
	memset(beg.chunk, ASAN_USER_POISONED_MEMORY, end.chunk - beg.chunk);
	if (end.value > 0 && end.value <= end.offset)
		*end.chunk = ASAN_USER_POISONED_MEMORY;
}

void asan_unpoison_memory(const void *addr, uptr size)
{
	struct shadow_segment_endpoint beg, end;
	s8 value;

	if (size == 0)
		return;

	init_shadow_segment_endpoint(&beg, (uptr)addr);
	init_shadow_segment_endpoint(&end, (uptr)addr + size);

	if (beg.chunk == end.chunk) {
		CHECK(beg.offset < end.offset);
		CHECK(beg.value == end.value);
		value = beg.value;
		if (value != 0)
			*beg.chunk = max(value, end.offset);
		return;
	}

	CHECK(beg.chunk < end.chunk);
	if (beg.offset > 0) {
		*beg.chunk = 0;
		beg.chunk++;
	}
	memset(beg.chunk, 0, end.chunk - beg.chunk);
	if (end.offset > 0 && end.value != 0)
		*end.chunk = max(end.value, end.offset);
}

static int asan_memory_is_poisoned(uptr addr)
{
	const uptr ACCESS_SIZE = 1;
	u8 *shadow_addr = (u8 *)mem_to_shadow(addr);
	s8 shadow_value = *shadow_addr;
	if (shadow_value != 0) {
		u8 last_accessed_byte = (addr & (SHADOW_GRANULARITY - 1))
					+ ACCESS_SIZE - 1;
		return (last_accessed_byte >= shadow_value) ? 1 : 0;
	}
	return 0;
}

static uptr b = 0, e = 0;

const void *asan_region_is_poisoned(const void *addr, uptr size)
{
	uptr beg, end;
	uptr aligned_beg, aligned_end;
	uptr shadow_beg, shadow_end;

	if (size == 0)
		return NULL;

	beg = (uptr)addr;
	end = beg + size;
	//CHECK(addr_is_in_mem(beg));
	//CHECK(addr_is_in_mem(end));
	if (!addr_is_in_mem(beg) || !addr_is_in_mem(end)) {
		b = beg;
		e = end;
		return NULL;
	}

	aligned_beg = round_up_to(beg, SHADOW_GRANULARITY);
	aligned_end = round_down_to(end, SHADOW_GRANULARITY);
	shadow_beg = mem_to_shadow(aligned_beg);
	shadow_end = mem_to_shadow(aligned_end);
	if (!asan_memory_is_poisoned(beg) &&
	    !asan_memory_is_poisoned(end - 1) &&
	    (shadow_end <= shadow_beg ||
	     mem_is_zero((const u8 *)shadow_beg, shadow_end - shadow_beg)))
		return NULL;
	for (; beg < end; beg++)
		if (asan_memory_is_poisoned(beg))
			return (const void *)beg;

	UNREACHABLE("mem_is_zero returned 0, but poisoned byte was not found");
	return NULL;
}

static int asan_enabled = 1;
static uptr accessed_poisoned_addr = 0;

void asan_check_region(const void *addr, uptr size)
{
	const void *rv = asan_region_is_poisoned(addr, size);
	uptr poisoned_addr = (uptr)rv;

	if (rv == NULL)
		return;

	accessed_poisoned_addr = poisoned_addr;
}

static void asan_print_errors(void)
{
	u8 *aligned_shadow;
	u8 buffer[64], i;

	if (accessed_poisoned_addr == 0) {
		printk(KERN_ERR "No errors occured.\n");
		return;
	}

	aligned_shadow = (u8 *)mem_to_shadow(accessed_poisoned_addr);
	printk(KERN_ERR "Error: address %lx is poisoned!\n",
		accessed_poisoned_addr);
	printk(KERN_ERR "Shadow bytes around the buggy address:\n");
	for (i = 0; i < 0x10; i++)
		sprintf(buffer + i * 3, "%02x ", *(aligned_shadow + i));
	printk(KERN_ERR "  %lx: %s\n", (uptr)aligned_shadow, buffer);
}

static void run_tests(void)
{
	uptr i;

	printk(KERN_ERR "Running tests...\n");

	//asan_check_region((void *)PAGE_OFFSET, 50);
	CHECK(asan_region_is_poisoned((void *)PAGE_OFFSET, 50) == NULL);

	asan_poison_memory((void *)(PAGE_OFFSET + 5), 27);
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + 5; i++)
		CHECK(!asan_memory_is_poisoned(i));
	for (i = PAGE_OFFSET + 5;
	     i < round_down_to(PAGE_OFFSET + 5 + 27, SHADOW_GRANULARITY);
	     i++) {
		CHECK(asan_memory_is_poisoned(i));
	}
	for (i = PAGE_OFFSET + 5 + 27; i < PAGE_OFFSET + 50; i++)
		CHECK(!asan_memory_is_poisoned(i));

	CHECK(asan_region_is_poisoned((void *)PAGE_OFFSET, 50)
	      == (void *)(PAGE_OFFSET + 5));
	CHECK(asan_region_is_poisoned((void *)(PAGE_OFFSET + 10), 50)
	      == (void *)(PAGE_OFFSET + 10));

	asan_unpoison_memory((void *)(PAGE_OFFSET + 5), 27);
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + 50; i++)
		CHECK(!asan_memory_is_poisoned(i));

	CHECK(asan_region_is_poisoned((void *)PAGE_OFFSET, 50) == NULL);

	asan_poison_shadow((void *)(PAGE_OFFSET + SHADOW_GRANULARITY),
			   SHADOW_GRANULARITY * 5, ASAN_HEAP_FREE);
	CHECK(asan_region_is_poisoned((void *)PAGE_OFFSET,
				      SHADOW_GRANULARITY * 3) ==
	      (void *)(PAGE_OFFSET + SHADOW_GRANULARITY));
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + SHADOW_GRANULARITY; i++)
		CHECK(!asan_memory_is_poisoned(i));
	for (i = PAGE_OFFSET + SHADOW_GRANULARITY;
	     i < PAGE_OFFSET + SHADOW_GRANULARITY * 6; i++) {
		CHECK(asan_memory_is_poisoned(i));
	}
	for (i = PAGE_OFFSET + SHADOW_GRANULARITY * 6;
	    i < PAGE_OFFSET + SHADOW_GRANULARITY * 10; i++) {
		CHECK(!asan_memory_is_poisoned(i));
	}

	asan_poison_shadow((void *)(PAGE_OFFSET + SHADOW_GRANULARITY),
		   SHADOW_GRANULARITY * 5, 0);
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + SHADOW_GRANULARITY * 10; i++)
		CHECK(!asan_memory_is_poisoned(i));

	printk(KERN_ERR "Passed all the tests.\n");
}

void asan_on_kernel_init(void)
{
	run_tests();

	asan_enabled = 0;
	asan_print_errors();
	printk(KERN_ERR "Not in mem: %lx %lx\n", b, e);
}

void asan_on_memcpy(const void *to, const void *from, uptr n)
{
	if (asan_enabled) {
		asan_check_region(to, n);
		asan_check_region(from, n);
	}
}
EXPORT_SYMBOL_GPL(asan_on_memcpy);
