#include "poisoning.h"

#include <asm/bug.h>
#include <linux/string.h>
#include <linux/types.h>

#include "mapping.h"
#include "utils.h"

struct shadow_segment_endpoint {
	u8 *chunk;
	s8 offset; /* In [0, SHADOW_GRANULARITY). */
	s8 value; /* = *chunk. */
};

static void init_shadow_segment_endpoint(struct shadow_segment_endpoint *endp,
					 unsigned long addr)
{
	BUG_ON(endp == NULL);
	endp->chunk = (u8 *)mem_to_shadow(addr);
	BUG_ON(endp->chunk == NULL);
	endp->offset = addr & (SHADOW_GRANULARITY - 1);
	endp->value = *endp->chunk;
}

void asan_poison_shadow(const void *address, unsigned long size, u8 value)
{
	unsigned long shadow_beg, shadow_end;
	unsigned long addr = (unsigned long)address;

	// BUG_ON(!addr_is_aligned(addr, SHADOW_GRANULARITY));
	// BUG_ON(!addr_is_aligned(addr + size, SHADOW_GRANULARITY));
	BUG_ON(!addr_is_in_mem(addr));
	BUG_ON(!addr_is_in_mem(addr + size - SHADOW_GRANULARITY));

	shadow_beg = mem_to_shadow(addr);
	shadow_end = mem_to_shadow(addr + size - SHADOW_GRANULARITY) + 1;
	memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

void asan_unpoison_shadow(const void *addr, unsigned long size)
{
	asan_poison_shadow(addr, size, 0);
}

void asan_poison_memory(const void *addr, unsigned long size)
{
	struct shadow_segment_endpoint beg, end;
	s8 value;

	if (size == 0)
		return;

	init_shadow_segment_endpoint(&beg, (unsigned long)addr);
	init_shadow_segment_endpoint(&end, (unsigned long)addr + size);

	if (beg.chunk == end.chunk) {
		BUG_ON(beg.offset >= end.offset);
		BUG_ON(beg.value != end.value);
		value = beg.value;
		if (value > 0 && value <= end.offset) {
			if (beg.offset > 0)
				*beg.chunk = min(value, beg.offset);
			else
				*beg.chunk = ASAN_USER_POISONED_MEMORY;
		}
		return;
	}

	BUG_ON(beg.chunk >= end.chunk);
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

void asan_unpoison_memory(const void *addr, unsigned long size)
{
	struct shadow_segment_endpoint beg, end;
	s8 value;

	if (size == 0)
		return;

	init_shadow_segment_endpoint(&beg, (unsigned long)addr);
	init_shadow_segment_endpoint(&end, (unsigned long)addr + size);

	if (beg.chunk == end.chunk) {
		BUG_ON(beg.offset >= end.offset);
		BUG_ON(beg.value != end.value);
		value = beg.value;
		if (value != 0)
			*beg.chunk = max(value, end.offset);
		return;
	}

	BUG_ON(beg.chunk >= end.chunk);
	if (beg.offset > 0) {
		*beg.chunk = 0;
		beg.chunk++;
	}
	memset(beg.chunk, 0, end.chunk - beg.chunk);
	if (end.offset > 0 && end.value != 0)
		*end.chunk = max(end.value, end.offset);
}

int asan_memory_is_poisoned(unsigned long addr)
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
