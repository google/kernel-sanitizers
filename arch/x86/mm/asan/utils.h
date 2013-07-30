#include <linux/log2.h>
#include <linux/types.h>

static unsigned long
round_up_to(unsigned long size, unsigned long granularity)
{
	BUG_ON(!is_power_of_2(granularity));
	return (size + granularity - 1) & ~(granularity - 1);
}

static unsigned long
round_down_to(unsigned long size, unsigned long granularity)
{
	BUG_ON(!is_power_of_2(granularity));
	return size & ~(granularity - 1);
}

static int mem_is_zero(const u8 *beg, unsigned long size)
{
	/* XXX: Check size? */
	const u8 *end = beg + size;
	unsigned long beg_addr = (unsigned long)beg;
	unsigned long end_addr = (unsigned long)end;
	unsigned long *aligned_beg =
		(unsigned long *)round_up_to(beg_addr, sizeof(unsigned long));
	unsigned long *aligned_end =
		(unsigned long *)round_down_to(end_addr, sizeof(unsigned long));
	unsigned long all = 0;
	const u8 *mem;
	for (mem = beg; mem < (u8 *)aligned_beg && mem < end; mem++)
		all |= *mem;
	for (; aligned_beg < aligned_end; aligned_beg++)
		all |= *aligned_beg;
	if ((u8 *)aligned_end >= beg)
		for (mem = (u8 *)aligned_end; mem < end; mem++)
			all |= *mem;
	return all == 0 ? 1 : 0;
}

static inline int addr_is_aligned(unsigned long addr, unsigned long granularity)
{
	return (addr & (granularity - 1)) == 0;
}
