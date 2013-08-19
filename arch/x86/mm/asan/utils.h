#ifndef ASAN_UTILS_H_
#define ASAN_UTILS_H_

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

static bool addr_is_aligned(unsigned long addr, unsigned long granularity)
{
	return (addr & (granularity - 1)) == 0;
}

#endif
