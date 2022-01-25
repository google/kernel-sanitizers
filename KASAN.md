Kernel Address Sanitizer (KASAN)
================================

**Status:** [Upstream](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/mm/kasan); in mainline [since 4.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0b24becc810dc3be6e3f94103a866f214c282394)

**Documentation:** [Documentation/dev-tools/kasan.rst](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html)

**Found bugs:** [here](/kasan/FOUND_BUGS.md)

**Contacts:** Andrey Konovalov <[@xairy](https://github.com/xairy)>, Alexander Potapenko <[@ramosian-glider](https://github.com/ramosian-glider)>, Dmitry Vyukov <[@dvyukov](https://github.com/dvyukov)>

## Overview

*Kernel Address Sanitizer (KASAN)* is a fast memory safety error detector for the Linux kernel. It detects out-of-bounds and use-after-free bugs in slab, page_alloc, vmalloc, stack, and global memory.

KASAN has a [Hardware Tag-Based mode](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html#hardware-tag-based-kasan) intended to be used in production as a security mitigation. This mode is based on the Arm Memory Tagging Extension and is expected to have a low performance overhead.
