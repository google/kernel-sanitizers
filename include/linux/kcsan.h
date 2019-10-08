/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_KCSAN_H
#define _LINUX_KCSAN_H

#include <linux/types.h>
#include <linux/kcsan-checks.h>

#ifdef CONFIG_KCSAN

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
