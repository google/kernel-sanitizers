#include "mapping.h"

#include <asm/page.h>

#include <linux/asan.h>

int addr_is_in_mem(unsigned long addr)
{
	return (addr >= (unsigned long)(__va(0)) &&
		addr < (unsigned long)(__va(max_pfn << PAGE_SHIFT)));
}

unsigned long mem_to_shadow(unsigned long addr)
{
	if (!addr_is_in_mem(addr))
		return 0;
	return ((addr - PAGE_OFFSET) >> SHADOW_SCALE)
		+ PAGE_OFFSET + SHADOW_OFFSET;
}

unsigned long shadow_to_mem(unsigned long shadow_addr)
{
	return ((shadow_addr - SHADOW_OFFSET - PAGE_OFFSET) << SHADOW_SCALE) +
	       PAGE_OFFSET;
}
