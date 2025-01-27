/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BIT_SPINLOCK_H
#define __LINUX_BIT_SPINLOCK_H

#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/atomic.h>
#include <linux/bug.h>

#include <asm/processor.h>  /* for cpu_relax() */

/*
 * For static capability analysis, we need a unique token for each possible bit
 * that can be used as a bit_spinlock. The easiest way to do that is to create a
 * fake capability that we can cast to with the __bitlock(bitnum, addr) macro
 * below, which will give us unique instances for each (bit, addr) pair that the
 * static analysis can use.
 */
struct_with_capability(__capability_bitlock) { };
#define __bitlock(bitnum, addr) (struct __capability_bitlock *)(bitnum + (addr))

/*
 *  bit-based spin_lock()
 *
 * Don't use this unless you really need to: spin_lock() and spin_unlock()
 * are significantly faster.
 */
static inline void bit_spin_lock(int bitnum, unsigned long *addr)
	__acquires(__bitlock(bitnum, addr))
{
	/*
	 * Assuming the lock is uncontended, this never enters
	 * the body of the outer loop. If it is contended, then
	 * within the inner loop a non-atomic test is used to
	 * busywait with less bus contention for a good time to
	 * attempt to acquire the lock bit.
	 */
	preempt_disable();
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	while (unlikely(test_and_set_bit_lock(bitnum, addr))) {
		preempt_enable();
		do {
			cpu_relax();
		} while (test_bit(bitnum, addr));
		preempt_disable();
	}
#endif
	__acquire(__bitlock(bitnum, addr));
}

/*
 * Return true if it was acquired
 */
static inline int bit_spin_trylock(int bitnum, unsigned long *addr)
	__cond_acquires(1, __bitlock(bitnum, addr))
{
	preempt_disable();
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	if (unlikely(test_and_set_bit_lock(bitnum, addr))) {
		preempt_enable();
		return 0;
	}
#endif
	__acquire(__bitlock(bitnum, addr));
	return 1;
}

/*
 *  bit-based spin_unlock()
 */
static inline void bit_spin_unlock(int bitnum, unsigned long *addr)
	__releases(__bitlock(bitnum, addr))
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(!test_bit(bitnum, addr));
#endif
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	clear_bit_unlock(bitnum, addr);
#endif
	preempt_enable();
	__release(__bitlock(bitnum, addr));
}

/*
 *  bit-based spin_unlock()
 *  non-atomic version, which can be used eg. if the bit lock itself is
 *  protecting the rest of the flags in the word.
 */
static inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
	__releases(__bitlock(bitnum, addr))
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(!test_bit(bitnum, addr));
#endif
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	__clear_bit_unlock(bitnum, addr);
#endif
	preempt_enable();
	__release(__bitlock(bitnum, addr));
}

/*
 * Return true if the lock is held.
 */
static inline int bit_spin_is_locked(int bitnum, unsigned long *addr)
{
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	return test_bit(bitnum, addr);
#elif defined CONFIG_PREEMPT_COUNT
	return preempt_count();
#else
	return 1;
#endif
}

#endif /* __LINUX_BIT_SPINLOCK_H */

