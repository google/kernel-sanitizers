/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MM_KCSAN_KCSAN_H
#define _MM_KCSAN_KCSAN_H

#include <linux/kcsan.h>

/*
 * Total number of watchpoints. An address range maps into a specific slot as
 * specified in `encoding.h`. Although larger number of watchpoints may not even
 * be usable due to limited thread count, a larger value will improve
 * performance due to reducing cache-line contention.
 */
#define KCSAN_NUM_WATCHPOINTS 64

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
 * Helper that returns true if access to ptr should be considered as an atomic
 * access, even though it is not explicitly atomic.
 */
bool kcsan_is_atomic(const volatile void* ptr);

/*
 * Initialize proc-fs info file.
 */
void kcsan_info_init(void);

enum kcsan_counter_id {
	/*
	 * Number of watchpoints currently in use.
	 */
	kcsan_counter_used_watchpoints,

	/*
	 * Total number of watchpoints set up.
	 */
	kcsan_counter_setup_watchpoints,

	/*
	 * Total number of races.
	 */
	kcsan_counter_race,

	/*
	 * Number of times no watchpoints were available.
	 */
	kcsan_counter_no_capacity,

	/*
	 * A thread checking a watchpoint raced with another checking thread;
	 * only one will be reported.
	 */
	kcsan_counter_race_report_race,

	/*
	 * The data value changed.
	 */
	kcsan_counter_race_diff,

	/*
	 * The access cannot be encoded to a valid watchpoint.
	 */
	kcsan_counter_unencodable_access,

	/*
	 * Watchpoint encoding caused a watchpoint to fire on mismatching
	 * accesses.
	 */
	kcsan_counter_encoding_false_positive,

	kcsan_counter_count, /* number of counters */
};

/*
 * Increment/decrement counter with given id; avoid calling these in fast-path.
 */
void kcsan_counter_inc(enum kcsan_counter_id id);
void kcsan_counter_dec(enum kcsan_counter_id id);

enum kcsan_report_type {
	/*
	 * The thread that set up the watchpoint and briefly stalled was
	 * signalled that another thread triggered the watchpoint, and thus a
	 * race was encountered.
	 */
	kcsan_report_race_setup,

	/*
	 * A thread encountered a watchpoint for the access, therefore a race
	 * was encountered.
	 */
	kcsan_report_race_check,

	/*
	 * A thread encountered a watchpoint for the access, but the other
	 * racing thread can no longer be signaled that a race occurred.
	 */
	kcsan_report_race_check_race,

	/*
	 * No other thread was observed to race with the access, but the data
	 * value before and after the stall differs.
	 */
	kcsan_report_race_diff,
};
/*
 * Print a race report from thread that encountered the race.
 */
void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
		  int cpu_id, enum kcsan_report_type type);

#endif /* _MM_KCSAN_KCSAN_H */
