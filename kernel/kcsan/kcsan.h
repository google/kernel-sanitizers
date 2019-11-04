/* SPDX-License-Identifier: GPL-2.0 */

/*
 * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
 * see Documentation/dev-tools/kcsan.rst.
 */

#ifndef _KERNEL_KCSAN_KCSAN_H
#define _KERNEL_KCSAN_KCSAN_H

#include <linux/kcsan.h>

/*
 * The number of adjacent watchpoints to check; the purpose is 2-fold:
 *
 *	1. the address slot is already occupied, check if any adjacent slots are
 *	   free;
 *	2. accesses that straddle a slot boundary due to size that exceeds a
 *	   slot's range may check adjacent slots if any watchpoint matches.
 *
 * Note that accesses with very large size may still miss a watchpoint; however,
 * given this should be rare, this is a reasonable trade-off to make, since this
 * will avoid:
 *
 *	1. excessive contention between watchpoint checks and setup;
 *	2. larger number of simultaneous watchpoints without sacrificing
 *	   performance.
 */
#define KCSAN_CHECK_ADJACENT 1

/*
 * Globally enable and disable KCSAN.
 */
extern bool kcsan_enabled;

/*
 * Initialize debugfs file.
 */
void kcsan_debugfs_init(void);

enum kcsan_counter_id {
	/*
	 * Number of watchpoints currently in use.
	 */
	KCSAN_COUNTER_USED_WATCHPOINTS,

	/*
	 * Total number of watchpoints set up.
	 */
	KCSAN_COUNTER_SETUP_WATCHPOINTS,

	/*
	 * Total number of data races.
	 */
	KCSAN_COUNTER_DATA_RACES,

	/*
	 * Number of times no watchpoints were available.
	 */
	KCSAN_COUNTER_NO_CAPACITY,

	/*
	 * A thread checking a watchpoint raced with another checking thread;
	 * only one will be reported.
	 */
	KCSAN_COUNTER_REPORT_RACES,

	/*
	 * Observed data value change, but writer thread unknown.
	 */
	KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN,

	/*
	 * The access cannot be encoded to a valid watchpoint.
	 */
	KCSAN_COUNTER_UNENCODABLE_ACCESSES,

	/*
	 * Watchpoint encoding caused a watchpoint to fire on mismatching
	 * accesses.
	 */
	KCSAN_COUNTER_ENCODING_FALSE_POSITIVES,

	KCSAN_COUNTER_COUNT, /* number of counters */
};

/*
 * Increment/decrement counter with given id; avoid calling these in fast-path.
 */
void kcsan_counter_inc(enum kcsan_counter_id id);
void kcsan_counter_dec(enum kcsan_counter_id id);

/*
 * Returns true if data races in the function symbol that maps to func_addr
 * (offsets are ignored) should *not* be reported.
 */
bool kcsan_skip_report(unsigned long func_addr);

enum kcsan_report_type {
	/*
	 * The thread that set up the watchpoint and briefly stalled was
	 * signalled that another thread triggered the watchpoint, and thus a
	 * race was encountered.
	 */
	KCSAN_REPORT_RACE_SETUP,

	/*
	 * A thread encountered a watchpoint for the access, therefore a race
	 * was encountered.
	 */
	KCSAN_REPORT_RACE_CHECK,

	/*
	 * A thread encountered a watchpoint for the access, but the other
	 * racing thread can no longer be signaled that a race occurred.
	 */
	KCSAN_REPORT_RACE_CHECK_RACE,

	/*
	 * No other thread was observed to race with the access, but the data
	 * value before and after the stall differs.
	 */
	KCSAN_REPORT_RACE_UNKNOWN_ORIGIN,
};
/*
 * Print a race report from thread that encountered the race.
 */
void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
		  int cpu_id, enum kcsan_report_type type);

#endif /* _KERNEL_KCSAN_KCSAN_H */
