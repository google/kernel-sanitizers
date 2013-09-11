#include "mapping.h"

#include <linux/types.h>

#include <asm/page.h>

#include "internal.h"

bool asan_addr_is_in_mem(unsigned long addr)
{
	return (addr >= (unsigned long)(__va(0)) &&
		addr < (unsigned long)(__va(max_pfn << PAGE_SHIFT)));
}

unsigned long asan_mem_to_shadow(unsigned long addr)
{
	if (!asan_addr_is_in_mem(addr))
		return 0;
	return ((addr - PAGE_OFFSET) >> SHADOW_SCALE)
		+ PAGE_OFFSET + SHADOW_OFFSET;
}

unsigned long asan_shadow_to_mem(unsigned long shadow_addr)
{
	return ((shadow_addr - SHADOW_OFFSET - PAGE_OFFSET) << SHADOW_SCALE) +
	       PAGE_OFFSET;
}
