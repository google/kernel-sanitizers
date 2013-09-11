#include "poisoning.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/bug.h>

#include "internal.h"
#include "mapping.h"

void asan_poison_shadow(const void *address, unsigned long size, u8 value)
{
	unsigned long shadow_beg, shadow_end;
	unsigned long addr = (unsigned long)address;

	BUG_ON(!IS_ALIGNED(addr, SHADOW_GRANULARITY));
	BUG_ON(!IS_ALIGNED(addr + size, SHADOW_GRANULARITY));
	BUG_ON(!asan_addr_is_in_mem(addr));
	BUG_ON(!asan_addr_is_in_mem(addr + size - SHADOW_GRANULARITY));

	shadow_beg = asan_mem_to_shadow(addr);
	shadow_end = asan_mem_to_shadow(addr + size - SHADOW_GRANULARITY) + 1;
	(memset)((void *)shadow_beg, value, shadow_end - shadow_beg);
}

void asan_unpoison_shadow(const void *address, unsigned long size)
{
	asan_poison_shadow(address, size, 0);
}

static bool asan_memory_is_poisoned(unsigned long addr)
{
	const unsigned long ACCESS_SIZE = 1;
	u8 *shadow_addr = (u8 *)asan_mem_to_shadow(addr);
	s8 shadow_value = *shadow_addr;
	if (shadow_value != 0) {
		u8 last_accessed_byte = (addr & (SHADOW_GRANULARITY - 1))
					+ ACCESS_SIZE - 1;
		return last_accessed_byte >= shadow_value;
	}
	return false;
}

static bool asan_mem_is_zero(const u8 *beg, unsigned long size)
{
	const u8 *end = beg + size;
	unsigned long beg_addr = (unsigned long)beg;
	unsigned long end_addr = (unsigned long)end;
	unsigned long *aligned_beg =
		(unsigned long *)round_up(beg_addr, sizeof(unsigned long));
	unsigned long *aligned_end =
		(unsigned long *)round_down(end_addr, sizeof(unsigned long));
	unsigned long all = 0;
	const u8 *mem;
	for (mem = beg; mem < (u8 *)aligned_beg && mem < end; mem++)
		all |= *mem;
	for (; aligned_beg < aligned_end; aligned_beg++)
		all |= *aligned_beg;
	if ((u8 *)aligned_end >= beg)
		for (mem = (u8 *)aligned_end; mem < end; mem++)
			all |= *mem;
	return all == 0;
}

const void *asan_region_is_poisoned(const void *addr, unsigned long size)
{
	unsigned long beg, end;
	unsigned long aligned_beg, aligned_end;
	unsigned long shadow_beg, shadow_end;

	if (size == 0)
		return NULL;

	beg = (unsigned long)addr;
	end = beg + size;
	if (!asan_addr_is_in_mem(beg) || !asan_addr_is_in_mem(end))
		return NULL;

	aligned_beg = round_up(beg, SHADOW_GRANULARITY);
	aligned_end = round_down(end, SHADOW_GRANULARITY);
	shadow_beg = asan_mem_to_shadow(aligned_beg);
	shadow_end = asan_mem_to_shadow(aligned_end);
	if (!asan_memory_is_poisoned(beg) &&
	    !asan_memory_is_poisoned(end - 1) &&
	    (shadow_end <= shadow_beg ||
	     asan_mem_is_zero((const u8 *)shadow_beg, shadow_end - shadow_beg)))
		return NULL;
	for (; beg < end; beg++)
		if (asan_memory_is_poisoned(beg))
			return (const void *)beg;

	BUG(); /* Unreachable. */
	return NULL;
}
