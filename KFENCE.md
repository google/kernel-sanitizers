# KFENCE: A sampling-based memory safety error detector for the Linux kernel

Contacts: Alexander Potapenko <@ramosian-glider>, Marco Elver <@melver>, Dmitry Vyukov <@dvyukov>

Source: [development branch](http://github.com/google/kasan/tree/kfence), [patches for mainline](https://github.com/google/kasan/commits/kfence-rebase-wip).

*Kernel Electric-Fence (KFENCE)* is a low-overhead sampling-based detector for heap out-of-bounds accessess, use-after-free, and invalid-free errors.
It is designed to have negligible cost to permit enabling it in production environments.

Compared to KASAN, KFENCE trades performance for precision.
However, with enough total uptime KFENCE will detect bugs in code paths not typically exercised by
non-production test workloads. One way to quickly achieve a large enough total uptime is to deploy the tool
across a large fleet of machines.
Indeed, KASAN and KFENCE are complementary, with different target environments. For instance, KASAN is the better debugging-aid, where a simple reproducer exists: due to the lower change to detect the error, it would require more effort using KFENCE to debug.

KFENCE is inspired by [GWP-ASan](http://llvm.org/docs/GwpAsan.html), a userspace tool with similar properties. The name "KFENCE" is a homage to the [Electric Fence Malloc Debugger](https://linux.die.net/man/3/efence).

## Status

The tool is under development (with plans to upstream it in 2020).

## Usage

To start using KFENCE, build your kernel with `CONFIG_KFENCE=y`.

The tool's behavior can be tweaked via config flags:

  * Sample interval: `CONFIG_KFENCE_SAMPLE_INTERVAL` (in milliseconds, 100 by default); or the boot-time `kfence.sample_interval` parameter.
  * Number of available objects: `CONFIG_KFENCE_NUM_OBJECTS` (255 by default).

## How does it work?

### KFENCE memory pool

KFENCE allocates a small (255 by default) pool of 4K object pages separated by guard (inaccessible) pages,
and provides an API to allocate and deallocate objects from that pool.
Each page contains at most one object, which is placed randomly at either end of that page.
As a result, there is always a guard page next to a KFENCE-allocated object,
so either a buffer-overflow or buffer-underflow on that object will result in a page fault.

When an object is deallocated, KFENCE marks the corresponding page inaccessible,
so further accesses to that object will also result in a page fault, until the page is reused by the allocator.

### Allocation sampling

Allocating an object from the KFENCE pool has a big performance cost, which is amortized by making such allocations
less frequent.

KFENCE introduces a static branch (using static keys) into the fast path of SLAB and SLUB.
This branch is disabled by default and thus has zero cost.
When enabled, it routes the allocation to KFENCE allocator:

```
static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
        return static_branch_unlikely(&kfence_allocation_key) ?
                __kfence_alloc(s, size, flags) : NULL;
}
```

The branch is enabled periodically (at the rate controlled by the `kfence.sample_interval` boot parameter)
by a kernel delayed work.

### Error reporting

When a page fault occurs on a page belonging to the KFENCE pool, the tool reports an error.

A fault on a guard page indicates an out-of-bounds error, which is reported as follows:

```
BUG: KFENCE: out-of-bounds in test_out_of_bounds_read+0x119/0x2a4 [kfence_test]

Out-of-bounds access at 0xffffffff93e06fff (left of kfence-#162):
 test_out_of_bounds_read+0x119/0x2a4 [kfence_test]
 kunit_run_case_internal lib/kunit/test.c:256
 kunit_try_run_case+0x6b/0xa0 lib/kunit/test.c:295
 kunit_generic_run_threadfn_adapter+0x24/0x40 lib/kunit/try-catch.c:28
 kthread+0x199/0x1f0 kernel/kthread.c:291
 ret_from_fork+0x22/0x30 arch/x86/entry/entry_64.S:293

kfence-#162 [0xffffffff93e07000-0xffffffff93e0701f, size=32, cache=kmalloc-32] allocated in:
 kfence_guarded_alloc mm/kfence/core.c:280
 __kfence_alloc+0x4e7/0x550 mm/kfence/core.c:627
 kfence_alloc ./include/linux/kfence.h:87
 slab_alloc_node mm/slub.c:2760
 slab_alloc mm/slub.c:2846
 __kmalloc+0x16e/0x260 mm/slub.c:3924
 test_alloc+0x1b0/0x2cb [kfence_test]
 test_out_of_bounds_read+0x106/0x2a4 [kfence_test]
 kunit_run_case_internal lib/kunit/test.c:256
 kunit_try_run_case+0x6b/0xa0 lib/kunit/test.c:295
 kunit_generic_run_threadfn_adapter+0x24/0x40 lib/kunit/try-catch.c:28
 kthread+0x199/0x1f0 kernel/kthread.c:291
 ret_from_fork+0x22/0x30 arch/x86/entry/entry_64.S:293
```

A fault on a protected object page indicates a use-after-free error, reported as follows:
```
BUG: KFENCE: use-after-free in test_use_after_free_read+0x109/0x1b7 [kfence_test]

Use-after-free access at 0xffffffff93e13fe0:
 test_use_after_free_read+0x109/0x1b7 [kfence_test]
 kunit_run_case_internal lib/kunit/test.c:256
 kunit_try_run_case+0x6b/0xa0 lib/kunit/test.c:295
 kunit_generic_run_threadfn_adapter+0x24/0x40 lib/kunit/try-catch.c:28
 kthread+0x199/0x1f0 kernel/kthread.c:291
 ret_from_fork+0x22/0x30 arch/x86/entry/entry_64.S:293

kfence-#168 [0xffffffff93e13fe0-0xffffffff93e13fff, size=32, cache=kmalloc-32] allocated in:
 kfence_guarded_alloc mm/kfence/core.c:280
 __kfence_alloc+0x286/0x550 mm/kfence/core.c:627
 kfence_alloc ./include/linux/kfence.h:87
 slab_alloc_node mm/slub.c:2760
 slab_alloc mm/slub.c:2846
 __kmalloc+0x16e/0x260 mm/slub.c:3924
 test_alloc+0x1b0/0x2cb [kfence_test]
 test_use_after_free_read+0xd5/0x1b7 [kfence_test]
 kunit_run_case_internal lib/kunit/test.c:256
 kunit_try_run_case+0x6b/0xa0 lib/kunit/test.c:295
 kunit_generic_run_threadfn_adapter+0x24/0x40 lib/kunit/try-catch.c:28
 kthread+0x199/0x1f0 kernel/kthread.c:291
 ret_from_fork+0x22/0x30 arch/x86/entry/entry_64.S:293
freed in:
 kfence_guarded_free+0x17f/0x3a0 mm/kfence/core.c:352
 test_use_after_free_read+0xfa/0x1b7 [kfence_test]
 kunit_run_case_internal lib/kunit/test.c:256
 kunit_try_run_case+0x6b/0xa0 lib/kunit/test.c:295
 kunit_generic_run_threadfn_adapter+0x24/0x40 lib/kunit/try-catch.c:28
 kthread+0x199/0x1f0 kernel/kthread.c:291
 ret_from_fork+0x22/0x30 arch/x86/entry/entry_64.S:293
```

