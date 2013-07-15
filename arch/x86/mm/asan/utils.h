#include <linux/log2.h>
#include <linux/types.h>

typedef unsigned long uptr;

static uptr round_up_to(uptr size, uptr granularity)
{
	BUG_ON(!is_power_of_2(granularity));
	return (size + granularity - 1) & ~(granularity - 1);
}

static uptr round_down_to(uptr size, uptr granularity)
{
	BUG_ON(!is_power_of_2(granularity));
	return size & ~(granularity - 1);
}

static int mem_is_zero(const u8 *beg, uptr size)
{
	/* XXX: Check size? */
	const u8 *end = beg + size;
	uptr *aligned_beg = (uptr *)round_up_to((uptr)beg, sizeof(uptr));
	uptr *aligned_end = (uptr *)round_down_to((uptr)end, sizeof(uptr));
	uptr all = 0;
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

static inline int addr_is_aligned(uptr addr, uptr granularity)
{
	return (addr & (granularity - 1)) == 0;
}
