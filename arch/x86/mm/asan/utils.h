#include <linux/types.h>

#define CHECK(x) BUG_ON(!(x))
/* FIXME:msg is not printed. */
#define UNREACHABLE(msg) CHECK(0 && msg)

typedef unsigned long uptr;

static int is_power_of_two(uptr x)
{
	return (x & (x - 1)) == 0 ? 1 : 0;
}

static uptr round_up_to(uptr size, uptr granularity)
{
	CHECK(is_power_of_two(granularity) == 1);
	return (size + granularity - 1) & ~(granularity - 1);
}

static uptr round_down_to(uptr size, uptr granularity)
{
	/* XXX: Not in sanitizer_common.h? */
	CHECK(is_power_of_two(granularity) == 1);
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
	return (addr & (granularity - 1)) == 0 ? 1 : 0;
}

/*
 * 0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm
 * hole caused by [48:63] sign extension
 * ffff800000000000 - ffff80ffffffffff (=40 bits) guard hole
 * ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
 * ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
 * ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
 * ffffe90000000000 - ffffe9ffffffffff (=40 bits) hole
 * ffffea0000000000 - ffffeaffffffffff (=40 bits) virtual memory map (1TB)
 * ... unused hole ...
 * ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
 * ffffffffa0000000 - ffffffffff5fffff (=1525 MB) module mapping space
 * ffffffffff600000 - ffffffffffdfffff (=8 MB) vsyscalls
 * ffffffffffe00000 - ffffffffffffffff (=2 MB) unused hole
 */
