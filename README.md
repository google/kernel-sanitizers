Linux Kernel Sanitizers
=======================

**Note: Most Sanitizers are maintained in the Linux kernel repository and are not hosted here**.

This repository contains out-of-tree information and prototypes for [KASAN](/KASAN.md), [KCSAN](/KCSAN.md), [KFENCE](/KFENCE.md), [KMSAN](/KMSAN.md), and [KTSAN](/KTSAN.md).
Note, that KMSAN's code is hosted [separately](https://github.com/google/kmsan).

Questions about KASAN and other Sanitizers can be asked on the [kasan-dev@googlegroups.com](https://groups.google.com/forum/#!forum/kasan-dev) mailing list.
You can subscribe to it either with a Google account or by sending an email to kasan-dev+subscribe@googlegroups.com.

Kernel bugs found with Sanitizers should be reported to kernel maintainers.
Issues in Sanitizers themselves can be reported on the [Sanitizers Bugzilla](https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management&resolution=---).

See the [Symbolizer](/SYMBOLIZER.md) page for information about symplifying reading bug reports produced by Sanitizers.
