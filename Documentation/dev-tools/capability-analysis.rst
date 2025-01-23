.. SPDX-License-Identifier: GPL-2.0
.. Copyright (C) 2025, Google LLC.

.. _capability-analysis:

Compiler-Based Capability Analysis
==================================

Capability analysis is a C language extension, which enables statically
checking that user-definable "capabilities" are acquired and released where
required. An obvious application is lock-safety checking for the kernel's
various synchronization primitives (each of which represents a "capability"),
and checking that locking rules are not violated.

The Clang compiler currently supports the full set of capability analysis
features. To enable for Clang, configure the kernel with::

    CONFIG_WARN_CAPABILITY_ANALYSIS=y

The analysis is *opt-in by default*, and requires declaring which modules and
subsystems should be analyzed in the respective `Makefile`::

    CAPABILITY_ANALYSIS_mymodule.o := y

Or for all translation units in the directory::

    CAPABILITY_ANALYSIS := y

It is possible to enable the analysis tree-wide, however, which will result in
numerous false positive warnings currently and is *not* generally recommended::

    CONFIG_WARN_CAPABILITY_ANALYSIS_ALL=y

Programming Model
-----------------

The below describes the programming model around using capability-enabled
types.

.. note::
   Enabling capability analysis can be seen as enabling a dialect of Linux C with
   a Capability System. Some valid patterns involving complex control-flow are
   constrained (such as conditional acquisition and later conditional release
   in the same function, or returning pointers to capabilities from functions.

Capability analysis is a way to specify permissibility of operations to depend
on capabilities being held (or not held). Typically we are interested in
protecting data and code by requiring some capability to be held, for example a
specific lock. The analysis ensures that the caller cannot perform the
operation without holding the appropriate capability.

Capabilities are associated with named structs, along with functions that
operate on capability-enabled struct instances to acquire and release the
associated capability.

Capabilities can be held either exclusively or shared. This mechanism allows
assign more precise privileges when holding a capability, typically to
distinguish where a thread may only read (shared) or also write (exclusive) to
guarded data.

The set of capabilities that are actually held by a given thread at a given
point in program execution is a run-time concept. The static analysis works by
calculating an approximation of that set, called the capability environment.
The capability environment is calculated for every program point, and describes
the set of capabilities that are statically known to be held, or not held, at
that particular point. This environment is a conservative approximation of the
full set of capabilities that will actually held by a thread at run-time.

More details are also documented `here
<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_.

.. note::
   Clang's analysis explicitly does not infer capabilities acquired or released
   by inline functions. It requires explicit annotations to (a) assert that
   it's not a bug if a capability is released or acquired, and (b) to retain
   consistency between inline and non-inline function declarations.

Supported Kernel Primitives
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Currently the following synchronization primitives are supported:
`raw_spinlock_t`, `spinlock_t`, `rwlock_t`.

For capabilities with an initialization function (e.g., `spin_lock_init()`),
calling this function on the capability instance before initializing any
guarded members or globals prevents the compiler from issuing warnings about
unguarded initialization.

Lockdep assertions, such as `lockdep_assert_held()`, inform the compiler's
capability analysis that the associated synchronization primitive is held after
the assertion. This avoids false positives in complex control-flow scenarios
and encourages the use of Lockdep where static analysis is limited. For
example, this is useful when a function doesn't *always* require a lock, making
`__must_hold()` inappropriate.

Keywords
~~~~~~~~

.. kernel-doc:: include/linux/compiler-capability-analysis.h
   :identifiers: struct_with_capability
                 token_capability token_capability_instance
                 __guarded_by __pt_guarded_by
                 __must_hold
                 __must_not_hold
                 __acquires
                 __cond_acquires
                 __releases
                 __must_hold_shared
                 __acquires_shared
                 __cond_acquires_shared
                 __releases_shared
                 __acquire
                 __release
                 __cond_lock
                 __acquire_shared
                 __release_shared
                 __cond_lock_shared
                 capability_unsafe
                 __capability_unsafe
                 disable_capability_analysis enable_capability_analysis

.. note::
   The function attribute `__no_capability_analysis` is reserved for internal
   implementation of capability-enabled primitives, and should be avoided in
   normal code.

Background
----------

Clang originally called the feature `Thread Safety Analysis
<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_, with some
terminology still using the thread-safety-analysis-only names. This was later
changed and the feature became more flexible, gaining the ability to define
custom "capabilities".

Indeed, its foundations can be found in `capability systems
<https://www.cs.cornell.edu/talc/papers/capabilities.pdf>`_, used to specify
the permissibility of operations to depend on some capability being held (or
not held).

Because the feature is not just able to express capabilities related to
synchronization primitives, the naming chosen for the kernel departs from
Clang's initial "Thread Safety" nomenclature and refers to the feature as
"Capability Analysis" to avoid confusion. The implementation still makes
references to the older terminology in some places, such as `-Wthread-safety`
being the warning option that also still appears in diagnostic messages.
