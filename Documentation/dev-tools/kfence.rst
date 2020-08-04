.. SPDX-License-Identifier: GPL-2.0

Kernel Electric-Fence
=====================

Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory
debugger. KFENCE detects heap out-of-bounds access, use-after-free, and
invalid-free errors.

KFENCE is designed to be enabled in production kernels, and has near zero
performance overhead. Compared to KASAN, KFENCE trades performance for
precision. The main motivation behind KFENCE's design, is that with enough
total uptime KFENCE will detect bugs in code paths not typically exercised by
non-production test workloads. One way to quickly achieve a large enough total
uptime is when the tool is deployed across a large fleet of machines.

Usage
-----

To enable KFENCE configure the kernel with::

    CONFIG_KFENCE=y

KFENCE provides several other configuration options to customize behaviour (see
the respective help text in ``lib/Kconfig.kfence`` for more info).

Error reports
~~~~~~~~~~~~~

TODO

DebugFS interface
~~~~~~~~~~~~~~~~~

The file ``/sys/kernel/debug/kfence/objects`` provides a list of objects
allocated via KFENCE.

Tuning performance
~~~~~~~~~~~~~~~~~~

TODO

Implementation Details
----------------------

TODO

Interface
---------

The following describes the functions which are used by allocators as well page
handling code to set up and deal with KFENCE allocations.

.. kernel-doc:: include/linux/kfence.h
   :functions: is_kfence_address
               kfence_shutdown_cache
               kfence_alloc kfence_free
               kfence_ksize kfence_object_start
               kfence_handle_page_fault

Related Tools
-------------

TODO: Talk about GWP-ASan
