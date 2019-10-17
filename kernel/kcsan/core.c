// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "kcsan.h"
#include "encoding.h"

/*
 * Helper macros to iterate slots, starting from address slot itself, followed
 * by the right and left slots.
 */
#define CHECK_NUM_SLOTS (1 + 2 * KCSAN_CHECK_ADJACENT)
#define SLOT_IDX(slot, i)                                                      \
	((slot + (((i + KCSAN_CHECK_ADJACENT) % CHECK_NUM_SLOTS) -             \
		  KCSAN_CHECK_ADJACENT)) %                                     \
	 KCSAN_NUM_WATCHPOINTS)

bool kcsan_enabled;

/* Per-CPU kcsan_ctx for interrupts */
static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
	.disable = 0,
	.atomic_next = 0,
	.atomic_region = 0,
	.atomic_region_flat = 0,
};

/*
 * Watchpoints, with each entry encoded as defined in encoding.h: in order to be
 * able to safely update and access a watchpoint without introducing locking
 * overhead, we encode each watchpoint as a single atomic long. The initial
 * zero-initialized state matches INVALID_WATCHPOINT.
 */
static atomic_long_t watchpoints[KCSAN_NUM_WATCHPOINTS];

/*
 * Instructions skipped counter; see should_watch().
 */
static DEFINE_PER_CPU(unsigned long, kcsan_skip);

static inline atomic_long_t *find_watchpoint(unsigned long addr, size_t size,
					     bool expect_write,
					     long *encoded_watchpoint)
{
	const int slot = watchpoint_slot(addr);
	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
	atomic_long_t *watchpoint;
	unsigned long wp_addr_masked;
	size_t wp_size;
	bool is_write;
	int i;

	for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
		watchpoint = &watchpoints[SLOT_IDX(slot, i)];
		*encoded_watchpoint = atomic_long_read(watchpoint);
		if (!decode_watchpoint(*encoded_watchpoint, &wp_addr_masked,
				       &wp_size, &is_write))
			continue;

		if (expect_write && !is_write)
			continue;

		/* Check if the watchpoint matches the access. */
		if (matching_access(wp_addr_masked, wp_size, addr_masked, size))
			return watchpoint;
	}

	return NULL;
}

static inline atomic_long_t *insert_watchpoint(unsigned long addr, size_t size,
					       bool is_write)
{
	const int slot = watchpoint_slot(addr);
	const long encoded_watchpoint = encode_watchpoint(addr, size, is_write);
	atomic_long_t *watchpoint;
	int i;

	for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
		long expect_val = INVALID_WATCHPOINT;

		/* Try to acquire this slot. */
		watchpoint = &watchpoints[SLOT_IDX(slot, i)];
		if (atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val,
						    encoded_watchpoint))
			return watchpoint;
	}

	return NULL;
}

/*
 * Return true if watchpoint was successfully consumed, false otherwise.
 *
 * This may return false if:
 *
 *	1. another thread already consumed the watchpoint;
 *	2. the thread that set up the watchpoint already removed it;
 *	3. the watchpoint was removed and then re-used.
 */
static inline bool try_consume_watchpoint(atomic_long_t *watchpoint,
					  long encoded_watchpoint)
{
	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint,
					       CONSUMED_WATCHPOINT);
}

/*
 * Return true if watchpoint was not touched, false if consumed.
 */
static inline bool remove_watchpoint(atomic_long_t *watchpoint)
{
	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) !=
	       CONSUMED_WATCHPOINT;
}

static inline struct kcsan_ctx *get_ctx(void)
{
	/*
	 * In interrupt, use raw_cpu_ptr to avoid unnecessary checks, that would
	 * also result in calls that generate warnings in uaccess regions.
	 */
	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
}

static inline bool is_atomic(const volatile void *ptr)
{
	struct kcsan_ctx *ctx = get_ctx();

	if (unlikely(ctx->atomic_next > 0)) {
		--ctx->atomic_next;
		return true;
	}
	if (unlikely(ctx->atomic_region > 0 || ctx->atomic_region_flat))
		return true;

	return kcsan_is_atomic(ptr);
}

static inline bool should_watch(const volatile void *ptr)
{
	/*
	 * Never set up watchpoints when memory operations are atomic.
	 *
	 * We need to check this first, because: 1) atomics should not count
	 * towards skipped instructions below, and 2) to actually decrement
	 * kcsan_atomic_next for each atomic.
	 */
	if (is_atomic(ptr))
		return false;

	/*
	 * We use a per-CPU counter, to avoid excessive contention; there is
	 * still enough non-determinism for the precise instructions that end up
	 * being watched to be mostly unpredictable. Using a PRNG like
	 * prandom_u32() turned out to be too slow.
	 */
	return (this_cpu_inc_return(kcsan_skip) %
		CONFIG_KCSAN_WATCH_SKIP_INST) == 0;
}

static inline bool is_enabled(void)
{
	return READ_ONCE(kcsan_enabled) && get_ctx()->disable == 0;
}

static inline unsigned int get_delay(void)
{
	unsigned int max_delay = in_task() ? CONFIG_KCSAN_UDELAY_MAX_TASK :
					     CONFIG_KCSAN_UDELAY_MAX_INTERRUPT;
	return IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
		       ((prandom_u32() % max_delay) + 1) :
		       max_delay;
}

/* === Public interface ===================================================== */

void __init kcsan_init(void)
{
	BUG_ON(!in_task());

	kcsan_debugfs_init();
	kcsan_enable_current();
#ifdef CONFIG_KCSAN_EARLY_ENABLE
	/*
	 * We are in the init task, and no other tasks should be running.
	 */
	WRITE_ONCE(kcsan_enabled, true);
#endif
}

/* === Exported interface =================================================== */

void kcsan_disable_current(void)
{
	++get_ctx()->disable;
}
EXPORT_SYMBOL(kcsan_disable_current);

void kcsan_enable_current(void)
{
	if (get_ctx()->disable-- == 0) {
		kcsan_disable_current(); /* restore to 0 */
		kcsan_disable_current();
		WARN(1, "mismatching %s", __func__);
		kcsan_enable_current();
	}
}
EXPORT_SYMBOL(kcsan_enable_current);

void kcsan_begin_atomic(bool nest)
{
	if (nest)
		++get_ctx()->atomic_region;
	else
		get_ctx()->atomic_region_flat = true;
}
EXPORT_SYMBOL(kcsan_begin_atomic);

void kcsan_end_atomic(bool nest)
{
	if (nest) {
		if (get_ctx()->atomic_region-- == 0) {
			kcsan_begin_atomic(true); /* restore to 0 */
			kcsan_disable_current();
			WARN(1, "mismatching %s", __func__);
			kcsan_enable_current();
		}
	} else {
		get_ctx()->atomic_region_flat = false;
	}
}
EXPORT_SYMBOL(kcsan_end_atomic);

void kcsan_atomic_next(int n)
{
	get_ctx()->atomic_next = n;
}
EXPORT_SYMBOL(kcsan_atomic_next);

bool __kcsan_check_watchpoint(const volatile void *ptr, size_t size,
			      bool is_write)
{
	atomic_long_t *watchpoint;
	long encoded_watchpoint;
	unsigned long flags;
	enum kcsan_report_type report_type;

	if (unlikely(!is_enabled()))
		return false;

	/*
	 * Avoid user_access_save in fast-path here: find_watchpoint is safe
	 * without user_access_save, as the address that ptr points to is only
	 * used to check if a watchpoint exists; ptr is never dereferenced.
	 */
	watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
				     &encoded_watchpoint);
	if (watchpoint == NULL)
		return true;

	flags = user_access_save();
	if (!try_consume_watchpoint(watchpoint, encoded_watchpoint)) {
		/*
		 * The other thread may not print any diagnostics, as it has
		 * already removed the watchpoint, or another thread consumed
		 * the watchpoint before this thread.
		 */
		kcsan_counter_inc(kcsan_counter_report_races);
		report_type = kcsan_report_race_check_race;
	} else {
		report_type = kcsan_report_race_check;
	}

	/* Encountered a data-race. */
	kcsan_counter_inc(kcsan_counter_data_races);
	kcsan_report(ptr, size, is_write, raw_smp_processor_id(), report_type);

	user_access_restore(flags);
	return false;
}
EXPORT_SYMBOL(__kcsan_check_watchpoint);

void __kcsan_setup_watchpoint(const volatile void *ptr, size_t size,
			      bool is_write)
{
	atomic_long_t *watchpoint;
	union {
		u8 _1;
		u16 _2;
		u32 _4;
		u64 _8;
	} expect_value;
	bool is_expected = true;
	unsigned long ua_flags = user_access_save();
	unsigned long irq_flags;

	if (!should_watch(ptr))
		goto out;

	if (!check_encodable((unsigned long)ptr, size)) {
		kcsan_counter_inc(kcsan_counter_unencodable_accesses);
		goto out;
	}

	/*
	 * Disable interrupts & preemptions to avoid another thread on the same
	 * CPU accessing memory locations for the set up watchpoint; this is to
	 * avoid reporting races to e.g. CPU-local data.
	 *
	 * An alternative would be adding the source CPU to the watchpoint
	 * encoding, and checking that watchpoint-CPU != this-CPU. There are
	 * several problems with this:
	 *   1. we should avoid stealing more bits from the watchpoint encoding
	 *      as it would affect accuracy, as well as increase performance
	 *      overhead in the fast-path;
	 *   2. if we are preempted, but there *is* a genuine data-race, we
	 *      would *not* report it -- since this is the common case (vs.
	 *      CPU-local data accesses), it makes more sense (from a data-race
	 *      detection PoV) to simply disable preemptions to ensure as many
	 *      tasks as possible run on other CPUs.
	 */
	local_irq_save(irq_flags);

	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
	if (watchpoint == NULL) {
		/*
		 * Out of capacity: the size of `watchpoints`, and the frequency
		 * with which `should_watch()` returns true should be tweaked so
		 * that this case happens very rarely.
		 */
		kcsan_counter_inc(kcsan_counter_no_capacity);
		goto out_unlock;
	}

	kcsan_counter_inc(kcsan_counter_setup_watchpoints);
	kcsan_counter_inc(kcsan_counter_used_watchpoints);

	/*
	 * Read the current value, to later check and infer a race if the data
	 * was modified via a non-instrumented access, e.g. from a device.
	 */
	switch (size) {
	case 1:
		expect_value._1 = READ_ONCE(*(const u8 *)ptr);
		break;
	case 2:
		expect_value._2 = READ_ONCE(*(const u16 *)ptr);
		break;
	case 4:
		expect_value._4 = READ_ONCE(*(const u32 *)ptr);
		break;
	case 8:
		expect_value._8 = READ_ONCE(*(const u64 *)ptr);
		break;
	default:
		break; /* ignore; we do not diff the values */
	}

#ifdef CONFIG_KCSAN_DEBUG
	kcsan_disable_current();
	pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
	       is_write ? "write" : "read", size, ptr,
	       watchpoint_slot((unsigned long)ptr),
	       encode_watchpoint((unsigned long)ptr, size, is_write));
	kcsan_enable_current();
#endif

	/*
	 * Delay this thread, to increase probability of observing a racy
	 * conflicting access.
	 */
	udelay(get_delay());

	/*
	 * Re-read value, and check if it is as expected; if not, we infer a
	 * racy access.
	 */
	switch (size) {
	case 1:
		is_expected = expect_value._1 == READ_ONCE(*(const u8 *)ptr);
		break;
	case 2:
		is_expected = expect_value._2 == READ_ONCE(*(const u16 *)ptr);
		break;
	case 4:
		is_expected = expect_value._4 == READ_ONCE(*(const u32 *)ptr);
		break;
	case 8:
		is_expected = expect_value._8 == READ_ONCE(*(const u64 *)ptr);
		break;
	default:
		break; /* ignore; we do not diff the values */
	}

	/* Check if this access raced with another. */
	if (!remove_watchpoint(watchpoint)) {
		/*
		 * No need to increment 'race' counter, as the racing thread
		 * already did.
		 */
		kcsan_report(ptr, size, is_write, smp_processor_id(),
			     kcsan_report_race_setup);
	} else if (!is_expected) {
		/* Inferring a race, since the value should not have changed. */
		kcsan_counter_inc(kcsan_counter_races_unknown_origin);
#ifdef CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
		kcsan_report(ptr, size, is_write, smp_processor_id(),
			     kcsan_report_race_unknown_origin);
#endif
	}

	kcsan_counter_dec(kcsan_counter_used_watchpoints);
out_unlock:
	local_irq_restore(irq_flags);
out:
	user_access_restore(ua_flags);
}
EXPORT_SYMBOL(__kcsan_setup_watchpoint);
