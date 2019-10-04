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
bool __kcsan_check_watchpoint(const volatile void *ptr, size_t size,
			      bool is_write);
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

/*
 * Full access that checks watchpoint and sets up a watchpoint if this access is
 * chosen for sampling.
 */
#define __kcsan_check_access(ptr, size, is_write)                              \
	do {                                                                   \
		if (__kcsan_check_watchpoint(ptr, size, is_write) &&           \
		    !(IS_ENABLED(CONFIG_KCSAN_PLAIN_WRITE_PRETEND_ONCE) &&     \
		      is_write))                                               \
			__kcsan_setup_watchpoint(ptr, size, is_write);         \
	} while (0)
#define kcsan_check_access(ptr, size, is_write)                                \
	do {                                                                   \
		if (kcsan_check_watchpoint(ptr, size, is_write) &&             \
		    !(IS_ENABLED(CONFIG_KCSAN_PLAIN_WRITE_PRETEND_ONCE) &&     \
		      is_write))                                               \
			kcsan_setup_watchpoint(ptr, size, is_write);           \
	} while (0)

/*
 * Instrumentation for atomic accesses.
 */
#ifdef CONFIG_KCSAN_IGNORE_ATOMICS
#define kcsan_check_atomic(...)                                                \
	do {                                                                   \
	} while (0)
#else
#define kcsan_check_atomic kcsan_check_watchpoint
#endif

#endif /* _LINUX_KCSAN_CHECKS_H */
