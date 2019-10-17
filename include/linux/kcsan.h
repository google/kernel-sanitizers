/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_KCSAN_H
#define _LINUX_KCSAN_H

#include <linux/types.h>
#include <linux/kcsan-checks.h>

#ifdef CONFIG_KCSAN

/*
 * Context for each thread of execution: for tasks, this is stored in
 * task_struct, and interrupts access internal per-CPU storage.
 */
struct kcsan_ctx {
	int disable; /* disable counter */
	int atomic_next; /* number of following atomic ops */

	/*
	 * We use separate variables to store if we are in a nestable or flat
	 * atomic region. This helps make sure that an atomic region with
	 * nesting support is not suddenly aborted when a flat region is
	 * contained within. Effectively this allows supporting nesting flat
	 * atomic regions within an outer nestable atomic region. Support for
	 * this is required as there are cases where a seqlock reader critical
	 * section (flat atomic region) is contained within a seqlock writer
	 * critical section (nestable atomic region), and the "mismatching
	 * kcsan_end_atomic()" warning would trigger otherwise.
	 */
	int atomic_region;
	bool atomic_region_flat;
};

/**
 * kcsan_init - initialize KCSAN runtime
 */
void kcsan_init(void);

/**
 * kcsan_disable_current - disable KCSAN for the current context
 *
 * Supports nesting.
 */
void kcsan_disable_current(void);

/**
 * kcsan_enable_current - re-enable KCSAN for the current context
 *
 * Supports nesting.
 */
void kcsan_enable_current(void);

/**
 * kcsan_begin_atomic - use to denote an atomic region
 *
 * Accesses within the atomic region may appear to race with other accesses but
 * should be considered atomic.
 *
 * @nest true if regions may be nested, or false for flat region
 */
void kcsan_begin_atomic(bool nest);

/**
 * kcsan_end_atomic - end atomic region
 *
 * @nest must match argument to kcsan_begin_atomic().
 */
void kcsan_end_atomic(bool nest);

/**
 * kcsan_atomic_next - consider following accesses as atomic
 *
 * Force treating the next n memory accesses for the current context as atomic
 * operations.
 *
 * @n number of following memory accesses to treat as atomic.
 */
void kcsan_atomic_next(int n);

#else /* CONFIG_KCSAN */

static inline void kcsan_init(void)
{
}

static inline void kcsan_disable_current(void)
{
}

static inline void kcsan_enable_current(void)
{
}

static inline void kcsan_begin_atomic(bool nest)
{
}

static inline void kcsan_end_atomic(bool nest)
{
}

static inline void kcsan_atomic_next(int n)
{
}

#endif /* CONFIG_KCSAN */

#endif /* _LINUX_KCSAN_H */
