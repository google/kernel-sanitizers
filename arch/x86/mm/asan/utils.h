#include <linux/types.h>

#define CHECK(x) BUG_ON(!(x));
/* FIXME:msg is not printed. */
#define UNREACHABLE(msg) CHECK(0 && msg)

typedef unsigned long uptr;

static int is_power_of_two(uptr x)
{
	return (x & (x - 1)) == 0 ? 1 : 0;
}

static uptr round_up_to(uptr size, uptr boundary)
{
	CHECK(is_power_of_two(boundary) == 1);
	return (size + boundary - 1) & ~(boundary - 1);
}

static uptr round_down_to(uptr size, uptr boundary)
{
	/* XXX: Not in sanitizer_common.h? */
	CHECK(is_power_of_two(boundary) == 1);
	return size & ~(boundary - 1);

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
