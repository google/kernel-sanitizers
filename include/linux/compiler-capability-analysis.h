/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Macros and attributes for compiler-based static capability analysis.
 */

#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H

#if defined(WARN_CAPABILITY_ANALYSIS)

/*
 * The below attributes are used to define new capability types. Internal only.
 */
# define __cap_type(name)			__attribute__((capability(#name)))
# define __acquires_cap(var)			__attribute__((acquire_capability(var)))
# define __acquires_shared_cap(var)		__attribute__((acquire_shared_capability(var)))
# define __try_acquires_cap(ret, var)		__attribute__((try_acquire_capability(ret, var)))
# define __try_acquires_shared_cap(ret, var)	__attribute__((try_acquire_shared_capability(ret, var)))
# define __releases_cap(var)			__attribute__((release_capability(var)))
# define __releases_shared_cap(var)		__attribute__((release_shared_capability(var)))
# define __asserts_cap(var)			__attribute__((assert_capability(var)))
# define __asserts_shared_cap(var)		__attribute__((assert_shared_capability(var)))
# define __returns_cap(var)			__attribute__((lock_returned(var)))

/*
 * The below are used to annotate code being checked. Internal only.
 */
# define __excludes_cap(var)		__attribute__((locks_excluded(var)))
# define __requires_cap(var)		__attribute__((requires_capability(var)))
# define __requires_shared_cap(var)	__attribute__((requires_shared_capability(var)))

/**
 * __guarded_by - struct member and globals attribute, declares variable
 *                protected by capability
 * @var: the capability instance that guards the member or global
 *
 * Declares that the struct member or global variable must be guarded by the
 * given capability @var. Read operations on the data require shared access,
 * while write operations require exclusive access.
 *
 * .. code-block:: c
 *
 *	struct some_state {
 *		spinlock_t lock;
 *		long counter __guarded_by(&lock);
 *	};
 */
# define __guarded_by(var)		__attribute__((guarded_by(var)))

/**
 * __pt_guarded_by - struct member and globals attribute, declares pointed-to
 *                   data is protected by capability
 * @var: the capability instance that guards the member or global
 *
 * Declares that the data pointed to by the struct member pointer or global
 * pointer must be guarded by the given capability @var. Read operations on the
 * data require shared access, while write operations require exclusive access.
 *
 * .. code-block:: c
 *
 *	struct some_state {
 *		spinlock_t lock;
 *		long *counter __pt_guarded_by(&lock);
 *	};
 */
# define __pt_guarded_by(var)		__attribute__((pt_guarded_by(var)))

/**
 * struct_with_capability() - declare or define a capability struct
 * @name: struct name
 *
 * Helper to declare or define a struct type with capability of the same name.
 *
 * .. code-block:: c
 *
 *	struct_with_capability(my_handle) {
 *		int foo;
 *		long bar;
 *	};
 *
 *	struct some_state {
 *		...
 *	};
 *	// ... declared elsewhere ...
 *	struct_with_capability(some_state);
 *
 * Note: The implementation defines several helper functions that can acquire,
 * release, and assert the capability.
 */
# define struct_with_capability(name)									\
	struct __cap_type(name) name;									\
	static __always_inline void __acquire_cap(const struct name *var)				\
		__attribute__((overloadable)) __no_capability_analysis __acquires_cap(var) { }		\
	static __always_inline void __acquire_shared_cap(const struct name *var)			\
		__attribute__((overloadable)) __no_capability_analysis __acquires_shared_cap(var) { }	\
	static __always_inline bool __try_acquire_cap(const struct name *var, bool ret)			\
		__attribute__((overloadable)) __no_capability_analysis __try_acquires_cap(1, var)	\
	{ return ret; }											\
	static __always_inline bool __try_acquire_shared_cap(const struct name *var, bool ret)		\
		__attribute__((overloadable)) __no_capability_analysis __try_acquires_shared_cap(1, var) \
	{ return ret; }											\
	static __always_inline void __release_cap(const struct name *var)				\
		__attribute__((overloadable)) __no_capability_analysis __releases_cap(var) { }		\
	static __always_inline void __release_shared_cap(const struct name *var)			\
		__attribute__((overloadable)) __no_capability_analysis __releases_shared_cap(var) { }	\
	static __always_inline void __assert_cap(const struct name *var)				\
		__attribute__((overloadable)) __asserts_cap(var) { }					\
	static __always_inline void __assert_shared_cap(const struct name *var)				\
		__attribute__((overloadable)) __asserts_shared_cap(var) { }				\
	struct name

/**
 * disable_capability_analysis() - disables capability analysis
 *
 * Disables capability analysis. Must be paired with a later
 * enable_capability_analysis().
 */
# define disable_capability_analysis()				\
	__diag_push();						\
	__diag_ignore_all("-Wunknown-warning-option", "")	\
	__diag_ignore_all("-Wthread-safety", "")		\
	__diag_ignore_all("-Wthread-safety-pointer", "")

/**
 * enable_capability_analysis() - re-enables capability analysis
 *
 * Re-enables capability analysis. Must be paired with a prior
 * disable_capability_analysis().
 */
# define enable_capability_analysis() __diag_pop()

/**
 * __no_capability_analysis - function attribute, disables capability analysis
 *
 * Function attribute denoting that capability analysis is disabled for the
 * whole function. Prefer use of `capability_unsafe()` where possible.
 */
# define __no_capability_analysis	__attribute__((no_thread_safety_analysis))

#else /* !WARN_CAPABILITY_ANALYSIS */

# define __cap_type(name)
# define __acquires_cap(var)
# define __acquires_shared_cap(var)
# define __try_acquires_cap(ret, var)
# define __try_acquires_shared_cap(ret, var)
# define __releases_cap(var)
# define __releases_shared_cap(var)
# define __asserts_cap(var)
# define __asserts_shared_cap(var)
# define __returns_cap(var)
# define __guarded_by(var)
# define __pt_guarded_by(var)
# define __excludes_cap(var)
# define __requires_cap(var)
# define __requires_shared_cap(var)
# define __acquire_cap(var)			do { } while (0)
# define __acquire_shared_cap(var)		do { } while (0)
# define __try_acquire_cap(var, ret)		(ret)
# define __try_acquire_shared_cap(var, ret)	(ret)
# define __release_cap(var)			do { } while (0)
# define __release_shared_cap(var)		do { } while (0)
# define __assert_cap(var)			do { (void)(var); } while (0)
# define __assert_shared_cap(var)		do { (void)(var); } while (0)
# define struct_with_capability(name)		struct name
# define disable_capability_analysis()
# define enable_capability_analysis()
# define __no_capability_analysis

#endif /* WARN_CAPABILITY_ANALYSIS */

/**
 * capability_unsafe() - disable capability checking for contained code
 *
 * Disables capability checking for contained statements or expression.
 *
 * .. code-block:: c
 *
 *	struct some_data {
 *		spinlock_t lock;
 *		int counter __guarded_by(&lock);
 *	};
 *
 *	int foo(struct some_data *d)
 *	{
 *		// ...
 *		// other code that is still checked ...
 *		// ...
 *		return capability_unsafe(d->counter);
 *	}
 */
#define capability_unsafe(...)		\
({					\
	disable_capability_analysis();	\
	__VA_ARGS__;			\
	enable_capability_analysis()	\
})

/**
 * __capability_unsafe() - function attribute, disable capability checking
 * @comment: comment explaining why opt-out is safe
 *
 * Function attribute denoting that capability analysis is disabled for the
 * whole function. Forces adding an inline comment as argument.
 */
#define __capability_unsafe(comment) __no_capability_analysis

/**
 * token_capability() - declare an abstract global capability instance
 * @name: token capability name
 *
 * Helper that declares an abstract global capability instance @name that can be
 * used as a token capability, but not backed by a real data structure (linker
 * error if accidentally referenced). The type name is `__capability_@name`.
 */
#define token_capability(name)				\
	struct_with_capability(__capability_##name) {};	\
	extern const struct __capability_##name *name

/**
 * token_capability_instance() - declare another instance of a global capability
 * @cap: token capability previously declared with token_capability()
 * @name: name of additional global capability instance
 *
 * Helper that declares an additional instance @name of the same token
 * capability class @name. This is helpful where multiple related token
 * capabilities are declared, as it also allows using the same underlying type
 * (`__capability_@cap`) as function arguments.
 */
#define token_capability_instance(cap, name)		\
	extern const struct __capability_##cap *name

/*
 * Common keywords for static capability analysis.
 */

/**
 * __must_hold() - function attribute, caller must hold exclusive capability
 * @x: capability instance pointer
 *
 * Function attribute declaring that the caller must hold the given capability
 * instance @x exclusively.
 */
#define __must_hold(x)		__requires_cap(x)

/**
 * __must_not_hold() - function attribute, caller must not hold capability
 * @x: capability instance pointer
 *
 * Function attribute declaring that the caller must not hold the given
 * capability instance @x.
 */
#define __must_not_hold(x)	__excludes_cap(x)

/**
 * __acquires() - function attribute, function acquires capability exclusively
 * @x: capability instance pointer
 *
 * Function attribute declaring that the function acquires the the given
 * capability instance @x exclusively, but does not release it.
 */
#define __acquires(x)		__acquires_cap(x)

/*
 * Clang's analysis does not care precisely about the value, only that it is
 * either zero or non-zero. So the __cond_acquires() interface might be
 * misleading if we say that @ret is the value returned if acquired. Instead,
 * provide symbolic variants which we translate.
 */
#define __cond_acquires_impl_true(x, ...)     __try_acquires##__VA_ARGS__##_cap(1, x)
#define __cond_acquires_impl_false(x, ...)    __try_acquires##__VA_ARGS__##_cap(0, x)
#define __cond_acquires_impl_nonzero(x, ...)  __try_acquires##__VA_ARGS__##_cap(1, x)
#define __cond_acquires_impl_0(x, ...)        __try_acquires##__VA_ARGS__##_cap(0, x)
#define __cond_acquires_impl_nonnull(x, ...)  __try_acquires##__VA_ARGS__##_cap(1, x)
#define __cond_acquires_impl_NULL(x, ...)     __try_acquires##__VA_ARGS__##_cap(0, x)

/**
 * __cond_acquires() - function attribute, function conditionally
 *                     acquires a capability exclusively
 * @ret: abstract value returned by function if capability acquired
 * @x: capability instance pointer
 *
 * Function attribute declaring that the function conditionally acquires the
 * given capability instance @x exclusively, but does not release it. The
 * function return value @ret denotes when the capability is acquired.
 *
 * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
 */
#define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)

/**
 * __releases() - function attribute, function releases a capability exclusively
 * @x: capability instance pointer
 *
 * Function attribute declaring that the function releases the given capability
 * instance @x exclusively. The capability must be held on entry.
 */
#define __releases(x)		__releases_cap(x)

/**
 * __acquire() - function to acquire capability exclusively
 * @x: capability instance pinter
 *
 * No-op function that acquires the given capability instance @x exclusively.
 */
#define __acquire(x)		__acquire_cap(x)

/**
 * __release() - function to release capability exclusively
 * @x: capability instance pinter
 *
 * No-op function that releases the given capability instance @x.
 */
#define __release(x)		__release_cap(x)

/**
 * __cond_lock() - function that conditionally acquires a capability
 *                 exclusively
 * @x: capability instance pinter
 * @c: boolean expression
 *
 * Return: result of @c
 *
 * No-op function that conditionally acquires capability instance @x
 * exclusively, if the boolean expression @c is true. The result of @c is the
 * return value, to be able to create a capability-enabled interface; for
 * example:
 *
 * .. code-block:: c
 *
 *	#define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
 */
#define __cond_lock(x, c)	__try_acquire_cap(x, c)

/**
 * __must_hold_shared() - function attribute, caller must hold shared capability
 * @x: capability instance pointer
 *
 * Function attribute declaring that the caller must hold the given capability
 * instance @x with shared access.
 */
#define __must_hold_shared(x)	__requires_shared_cap(x)

/**
 * __acquires_shared() - function attribute, function acquires capability shared
 * @x: capability instance pointer
 *
 * Function attribute declaring that the function acquires the the given
 * capability instance @x with shared access, but does not release it.
 */
#define __acquires_shared(x)	__acquires_shared_cap(x)

/**
 * __cond_acquires_shared() - function attribute, function conditionally
 *                            acquires a capability shared
 * @ret: abstract value returned by function if capability acquired
 * @x: capability instance pointer
 *
 * Function attribute declaring that the function conditionally acquires the
 * given capability instance @x with shared access, but does not release it. The
 * function return value @ret denotes when the capability is acquired.
 *
 * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
 */
#define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)

/**
 * __releases_shared() - function attribute, function releases a
 *                       capability shared
 * @x: capability instance pointer
 *
 * Function attribute declaring that the function releases the given capability
 * instance @x with shared access. The capability must be held on entry.
 */
#define __releases_shared(x)	__releases_shared_cap(x)

/**
 * __acquire_shared() - function to acquire capability shared
 * @x: capability instance pinter
 *
 * No-op function that acquires the given capability instance @x with shared
 * access.
 */
#define __acquire_shared(x)	__acquire_shared_cap(x)

/**
 * __release_shared() - function to release capability shared
 * @x: capability instance pinter
 *
 * No-op function that releases the given capability instance @x with shared
 * access.
 */
#define __release_shared(x)	__release_shared_cap(x)

/**
 * __cond_lock_shared() - function that conditionally acquires a capability
 *                        shared
 * @x: capability instance pinter
 * @c: boolean expression
 *
 * Return: result of @c
 *
 * No-op function that conditionally acquires capability instance @x with shared
 * access, if the boolean expression @c is true. The result of @c is the return
 * value, to be able to create a capability-enabled interface.
 */
#define __cond_lock_shared(x, c) __try_acquire_shared_cap(x, c)

#endif /* _LINUX_COMPILER_CAPABILITY_ANALYSIS_H */
