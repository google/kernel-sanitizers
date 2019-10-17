/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_KCSAN_CHECKS_H
#define _LINUX_KCSAN_CHECKS_H

#include <linux/types.h>

/*
 * __kcsan_*: Always available when KCSAN is enabled. This may be used
 * even in compilation units that selectively disable KCSAN, but must use KCSAN
 * to validate access to an address.   Never use these in header files!
 */
#ifdef CONFIG_KCSAN
/**
 * __kcsan_check_watchpoint - check if a watchpoint exists
 *
 * Returns true if no race was detected, and we may then proceed to set up a
 * watchpoint after. Returns false if either KCSAN is disabled or a race was
 * encountered, and we may not set up a watchpoint after.
 *
 * @ptr address of access
 * @size size of access
 * @is_write is access a write
 * @return true if no race was detected, false otherwise.
 */
bool __kcsan_check_watchpoint(const volatile void *ptr, size_t size,
			      bool is_write);

/**
 * __kcsan_setup_watchpoint - set up watchpoint and report data-races
 *
 * Sets up a watchpoint (if sampled), and if a racing access was observed,
 * reports the data-race.
 *
 * @ptr address of access
 * @size size of access
 * @is_write is access a write
 */
void __kcsan_setup_watchpoint(const volatile void *ptr, size_t size,
			      bool is_write);
#else
static inline bool __kcsan_check_watchpoint(const volatile void *ptr,
					    size_t size, bool is_write)
{
	return true;
}
static inline void __kcsan_setup_watchpoint(const volatile void *ptr,
					    size_t size, bool is_write)
{
}
#endif

/*
 * kcsan_*: Only available when the particular compilation unit has KCSAN
 * instrumentation enabled. May be used in header files.
 */
#ifdef __SANITIZE_THREAD__
#define kcsan_check_watchpoint __kcsan_check_watchpoint
#define kcsan_setup_watchpoint __kcsan_setup_watchpoint
#else
static inline bool kcsan_check_watchpoint(const volatile void *ptr, size_t size,
					  bool is_write)
{
	return true;
}
static inline void kcsan_setup_watchpoint(const volatile void *ptr, size_t size,
					  bool is_write)
{
}
#endif

/**
 * __kcsan_check_read - check regular read access for data-races
 *
 * Full read access that checks watchpoint and sets up a watchpoint if this
 * access is sampled. Note that, setting up watchpoints for plain reads is
 * required to also detect data-races with atomic accesses.
 *
 * @ptr address of access
 * @size size of access
 */
#define __kcsan_check_read(ptr, size)                                          \
	do {                                                                   \
		if (__kcsan_check_watchpoint(ptr, size, false))                \
			__kcsan_setup_watchpoint(ptr, size, false);            \
	} while (0)

/**
 * __kcsan_check_write - check regular write access for data-races
 *
 * Full write access that checks watchpoint and sets up a watchpoint if this
 * access is sampled.
 *
 * @ptr address of access
 * @size size of access
 */
#define __kcsan_check_write(ptr, size)                                         \
	do {                                                                   \
		if (__kcsan_check_watchpoint(ptr, size, true) &&               \
		    !IS_ENABLED(CONFIG_KCSAN_PLAIN_WRITE_PRETEND_ONCE))        \
			__kcsan_setup_watchpoint(ptr, size, true);             \
	} while (0)

/**
 * kcsan_check_read - check regular read access for data-races
 *
 * @ptr address of access
 * @size size of access
 */
#define kcsan_check_read(ptr, size)                                            \
	do {                                                                   \
		if (kcsan_check_watchpoint(ptr, size, false))                  \
			kcsan_setup_watchpoint(ptr, size, false);              \
	} while (0)

/**
 * kcsan_check_write - check regular write access for data-races
 *
 * @ptr address of access
 * @size size of access
 */
#define kcsan_check_write(ptr, size)                                           \
	do {                                                                   \
		if (kcsan_check_watchpoint(ptr, size, true) &&                 \
		    !IS_ENABLED(CONFIG_KCSAN_PLAIN_WRITE_PRETEND_ONCE))        \
			kcsan_setup_watchpoint(ptr, size, true);               \
	} while (0)

/*
 * Check for atomic accesses: if atomic access are not ignored, this simply
 * aliases to kcsan_check_watchpoint, otherwise becomes a no-op.
 */
#ifdef CONFIG_KCSAN_IGNORE_ATOMICS
#define kcsan_check_atomic_read(...)                                           \
	do {                                                                   \
	} while (0)
#define kcsan_check_atomic_write(...)                                          \
	do {                                                                   \
	} while (0)
#else
#define kcsan_check_atomic_read(ptr, size)                                     \
	kcsan_check_watchpoint(ptr, size, false)
#define kcsan_check_atomic_write(ptr, size)                                    \
	kcsan_check_watchpoint(ptr, size, true)
#endif

#endif /* _LINUX_KCSAN_CHECKS_H */
