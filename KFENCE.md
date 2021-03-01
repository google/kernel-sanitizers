# KFENCE: A low-overhead sampling-based memory safety error detector for the Linux kernel

**Contacts:** Alexander Potapenko <[@ramosian-glider](https://github.com/ramosian-glider)>, Marco Elver <[@melver](https://github.com/melver)>, Dmitry Vyukov <[@dvyukov](https://github.com/dvyukov)>

**Status:** [Upstream; in mainline since 5.12](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=245137cdf0cd92077dad37868fe4859c90dada36)

**Documentation:** [Documentation/dev-tools/kfence.rst](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/dev-tools/kfence.rst)


*Kernel Electric-Fence (KFENCE)* is a low-overhead sampling-based detector for
heap out-of-bounds accessess, use-after-free, and invalid-free errors.  It is
designed to have negligible cost to permit enabling it in production
environments.

KFENCE is inspired by [GWP-ASan](http://llvm.org/docs/GwpAsan.html), a
userspace tool with similar properties, and can be seen as its kernel sibling.

Compared to KASAN, KFENCE trades performance for precision.  However, with
enough total uptime KFENCE will detect bugs in code paths not typically
exercised by non-production test workloads. One way to quickly achieve a large
enough total uptime is to deploy the tool across a large fleet of machines.
Indeed, KASAN and KFENCE are complementary, with different target environments.
For instance, KASAN is the better debugging-aid, where a simple reproducer
exists: due to the lower chance to detect the error, it would require more
effort using KFENCE to debug. Deployments at scale, however, would benefit
from using KFENCE to discover bugs due to code paths not exercised by test cases
or fuzzers.

The name "KFENCE" is a homage to the [Electric Fence Malloc Debugger](https://linux.die.net/man/3/efence).

## Usage

To start using KFENCE, build your kernel with `CONFIG_KFENCE=y`.

The tool's behavior can be tweaked via config flags:

  * Sample interval: `CONFIG_KFENCE_SAMPLE_INTERVAL` (in milliseconds, 100 by
    default); or the boot-time `kfence.sample_interval` parameter.
  * Number of available objects: `CONFIG_KFENCE_NUM_OBJECTS` (255 by default).

## How does it work?

KFENCE allocates a small (255 by default) pool of object pages (typically 4 KiB) separated by
guard (inaccessible) pages, and provides an API to allocate and deallocate
objects from that pool.  Each page contains at most one object, which is placed
randomly at either end of that page. As a result, there is always a guard page
next to a KFENCE-allocated object, so either a buffer-overflow or
buffer-underflow on that object will result in a page fault.
Such faults are then reported as out-of-bounds errors and printed to the kernel log.

When an object is deallocated, KFENCE marks the corresponding page
inaccessible, so that further accesses to that object will also result in a page
fault, which will be reported as a use-after-free error.
KFENCE also reports on invalid frees, as it can afford to accurately track the object's state.
The least recently freed objects will be reused for new allocations.

Allocating an object from the KFENCE pool is costly, which is
amortized by making such allocations less frequent, while ensuring that skipped allocations
have zero cost through the main allocator's fast-path.

To achieve this, KFENCE introduces a static branch (using static keys) into the fast path of
SLAB and SLUB. This branch is disabled by default and thus has zero cost.
When enabled, it routes the allocation to KFENCE allocator:

```
static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
        return static_branch_unlikely(&kfence_allocation_key) ?
                __kfence_alloc(s, size, flags) : NULL;
}
```

The branch is enabled periodically by a kernel delayed work, and after a successful guarded allocation disabled again.
The frequency with which guarded allocations occur is controlled by the sample interval, which can be set by the boot parameter `kfence.sample_interval`.

For more details, please see the included [documentation](https://github.com/google/kasan/blob/kfence/Documentation/dev-tools/kfence.rst).
