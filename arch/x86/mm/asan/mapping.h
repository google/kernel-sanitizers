#ifndef ASAN_MAPPING_H_
#define ASAN_MAPPING_H_

#include <asm/page.h>

#include <linux/asan.h>

extern unsigned long max_pfn;

static inline int addr_is_in_mem(unsigned long addr)
{
	return (addr >= (unsigned long)(__va(0)) &&
		addr < (unsigned long)(__va(max_pfn << PAGE_SHIFT)));
}

static unsigned long mem_to_shadow(unsigned long addr)
{
	if (!addr_is_in_mem(addr))
		return 0;
	return ((addr - PAGE_OFFSET) >> SHADOW_SCALE)
		+ PAGE_OFFSET + SHADOW_OFFSET;
}

#endif
