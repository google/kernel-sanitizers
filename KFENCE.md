Kernel Electric-Fence (KFENCE)
==============================

**Status:** [Upstream](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/mm/kfence); in mainline [since 5.12](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=245137cdf0cd92077dad37868fe4859c90dada36)

**Documentation:** [Documentation/dev-tools/kfence.rst](https://www.kernel.org/doc/html/latest/dev-tools/kfence.html)

**Found bugs:** [here](/kfence/FOUND_BUGS.md)

**Contacts:** Alexander Potapenko <[@ramosian-glider](https://github.com/ramosian-glider)>, Marco Elver <[@melver](https://github.com/melver)>, Dmitry Vyukov <[@dvyukov](https://github.com/dvyukov)>

## Overview

*Kernel Electric-Fence (KFENCE)* is a low-overhead sampling-based memory safety
error detector for the Linux kernel.  It detects heap out-of-bounds accessess,
use-after-free, and invalid-free errors.  It is designed to have negligible cost
to permit enabling it in production environments.

KFENCE is inspired by [GWP-ASan](http://llvm.org/docs/GwpAsan.html), a
userspace tool with similar properties, and can be seen as its kernel sibling.

Compared to [KASAN](/KASAN.md), KFENCE trades performance for precision.
However, with enough total uptime KFENCE will detect bugs in code paths not
typically exercised by non-production test workloads. One way to quickly achieve
a large enough total uptime is to deploy the tool across a large fleet of
machines.  Indeed, KASAN and KFENCE are complementary, with different target
environments.  For instance, KASAN is the better debugging-aid, where a simple
reproducer exists: due to the lower chance to detect the error, it would require
more effort using KFENCE to debug. Deployments at scale, however, would benefit
from using KFENCE to discover bugs due to code paths not exercised by test cases
or fuzzers.

The name "KFENCE" is a homage to the [Electric Fence Malloc Debugger](https://linux.die.net/man/3/efence).

## Usage

To start using KFENCE, build your kernel with `CONFIG_KFENCE=y`. For more
information, please see the kernel's [documentation](https://www.kernel.org/doc/html/latest/dev-tools/kfence.html).

## How it works

KFENCE allocates a small pool of object pages (typically 4 KiB each) separated
by guard (protected) pages. Each page contains at most one object, which is
placed randomly at either end of that page. As a result, there is always a
guard page next to a KFENCE-allocated object, so either a buffer-overflow or
buffer-underflow on that object will result in a page fault. Such faults are
then reported as out-of-bounds errors and printed to the kernel log.

Setting up whole pages for heap objects typically smaller than a whole page is
costly, both in terms of memory but also performance overheads. Therefore,
integration into the main heap allocators (SLAB or SLUB) is amortized by
redirecting heap allocations to be allocated via KFENCE with a relatively low
frequency (by default max. 2 allocations per second).

Upon redirecting a heap allocation to KFENCE, a page from the KFENCE pool
freelist is obtained to prepare space for the requested object. Objects smaller
than a full page are randomly placed at either end of the page. The object page
is unprotected, and the unused portion of the page is set to a canary pattern
to detect out-of-bounds writes within the object page itself. Various other
metadata is stored to generate useful bug reports, such as the allocation stack
trace. Finally, the address of the object is returned to the main allocator.

When an object is deallocated, KFENCE marks the corresponding page
inaccessible, so that further accesses to that object will also result in a
page fault, which will be reported as a use-after-free error. KFENCE also
reports on invalid frees. The least recently freed objects will be reused for
new allocations.

For more details, please see the
[documentation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/dev-tools/kfence.rst).
