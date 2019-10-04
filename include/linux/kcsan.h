/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_KCSAN_H
#define _LINUX_KCSAN_H

#include <linux/types.h>
#include <linux/kcsan-checks.h>

#ifdef CONFIG_KCSAN

void kcsan_init(void);

/*
 * Disable KCSAN for the current context; supports nesting.
 */
void kcsan_disable_current(void);

/*
 * Re-enable KCSAN for the current context; supports nesting.
 */
void kcsan_enable_current(void);

/*
 * Use to denote an atomic region: accesses within the atomic region may appear
 * to race with other accesses but should be considered atomic.
 */
void kcsan_begin_atomic(bool nest);

/*
 * End atomic region; nested regions supported if nest is set to true.
 */
void kcsan_end_atomic(bool nest);

/*
 * Force treating the next n memory accesses for the current context as atomic
 * operations.
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
