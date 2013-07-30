#include "poisoning.h"

#include <asm/bug.h>
#include <linux/string.h>
#include <linux/types.h>

#include "mapping.h"
#include "utils.h"

void asan_poison_shadow(const void *address, unsigned long size, u8 value)
{
	unsigned long shadow_beg, shadow_end;
	unsigned long addr = (unsigned long)address;

	BUG_ON(!addr_is_aligned(addr, SHADOW_GRANULARITY));
	BUG_ON(!addr_is_aligned(addr + size, SHADOW_GRANULARITY));
	BUG_ON(!addr_is_in_mem(addr));
	BUG_ON(!addr_is_in_mem(addr + size - SHADOW_GRANULARITY));

	shadow_beg = mem_to_shadow(addr);
	shadow_end = mem_to_shadow(addr + size - SHADOW_GRANULARITY) + 1;
	memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

void asan_unpoison_shadow(const void *address, unsigned long size)
{
	asan_poison_shadow(address, size, 0);
}

static int asan_memory_is_poisoned(unsigned long addr)
{
	const unsigned long ACCESS_SIZE = 1;
	u8 *shadow_addr = (u8 *)mem_to_shadow(addr);
	s8 shadow_value = *shadow_addr;
	if (shadow_value != 0) {
		u8 last_accessed_byte = (addr & (SHADOW_GRANULARITY - 1))
					+ ACCESS_SIZE - 1;
		return (last_accessed_byte >= shadow_value) ? 1 : 0;
	}
	return 0;
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
	if (!addr_is_in_mem(beg) || !addr_is_in_mem(end))
		return NULL;

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

	BUG(); /* Unreachable. */
	return NULL;
}
