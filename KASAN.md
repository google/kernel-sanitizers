Kernel Address Sanitizer (KASAN)
================================

**Status:** [Upstream](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/mm/kasan); in mainline [since 4.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0b24becc810dc3be6e3f94103a866f214c282394)

**Documentation:** [Documentation/dev-tools/kasan.rst](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html)

**Found bugs:** [here](/kasan/FOUND_BUGS.md)

**Contacts:** Andrey Konovalov <[@xairy](https://github.com/xairy)>, Alexander Potapenko <[@ramosian-glider](https://github.com/ramosian-glider)>, Dmitry Vyukov <[@dvyukov](https://github.com/dvyukov)>

## Overview

*Kernel Address Sanitizer (KASAN)* is a fast memory corruption detector for the Linux kernel.
KASAN detects out-of-bounds, use-after-free, and invalid-free bugs in slab, page_alloc, vmalloc, stack, and global memory.

KASAN has 3 modes:

* [Generic KASAN](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html#generic-kasan), which is intended to be used for debugging.
This mode is supported by many CPU architectures.

* [Software Tag-Based KASAN](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html#software-tag-based-kasan), which is intended for testing in near-production environments.
This mode has a lower RAM overhead than the Generic mode but is only supported on arm64.

* [Hardware Tag-Based KASAN](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html#hardware-tag-based-kasan), which intended to be used in production as an in-field bug detector or a security mitigation.
This mode is based on the Arm Memory Tagging Extension and is expected to have a very low performance overhead.

For more details about each mode, see the [kernel documentation](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html) and these talks:

* [Sanitizing the Linux kernel](https://docs.google.com/presentation/d/1qA8fqRDHKX_WM_ZdDN37EQQZwSTNJ4FFws82tbUSKxY/edit?usp=sharing) at Linux Security Summit Europe 2022

* [Memory Tagging for the kernel: Tag-Based KASAN](https://docs.google.com/presentation/d/10V_msbtEap9dNerKvTrRAzvfzYdrQFC8e2NYHCZYJDE/edit?usp=sharing) [[video](https://www.youtube.com/watch?v=9wRT2hNwbkA)] at Android Security Symposium 2020

* [Mitigating Linux kernel memory corruptions with Arm Memory Tagging](https://docs.google.com/presentation/d/1IpICtHR1T3oHka858cx1dSNRu2XcT79-RCRPgzCuiRk/edit?usp=sharing) [[video](https://www.youtube.com/watch?v=UwMt0e_dC_Q)] at Linux Security Summit 2021

See [KFENCE](/KFENCE.md) for an alternative sampling-based low-overhead memory corruption detector that can be used in production enviroments.
