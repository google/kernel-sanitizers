Kernel Thread Sanitizer (KTSAN)
===============================

**Status:** [Prototype](https://github.com/google/kasan/tree/ktsan) on-hold

**Documentation:** [Documentation/ktsan.txt](https://github.com/google/kernel-sanitizers/blob/ktsan/Documentation/ktsan.txt) (somewhat outdated)

**Found bugs:** [here](/ktsan/FOUND_BUGS.md)

**Contacts:** Dmitry Vyukov <[@dvyukov](https://github.com/dvyukov)>, Andrey Konovalov <[@xairy](https://github.com/xairy)>

## Overview

*Kernel Thread Sanitizer (KTSAN)* is a happens-before dynamic data-race detector for the Linux kernel.

KTSAN adapts the data-race detection algorithm of the userspace [ThreadSanitizer](https://github.com/google/sanitizers/wiki/ThreadSanitizerAlgorithm) (version 2; don't confuse with [version 1](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/35604.pdf)) to the Linux kernel.

Due to a significant complexity of the bug-detection algorithm when adapted to the Linux kernel and large CPU and RAM overheads, the project was put on-hold.

See [Kernel Concurrency Sanitizer (KCSAN)](/KCSAN.md) for an alternative approach that uses watchpoints.

The latest KTSAN version based on 5.3 can be found in the [ktsan](https://github.com/google/kasan/tree/ktsan) branch.
The original prototype based on 4.2 can be found under the tag [ktsan_v4.2-with-fixes](https://github.com/google/kasan/releases/tag/ktsan_v4.2-with-fixes) (also includes fixes for found data-races).

For more details about KTSAN, see:

* [KernelThreadSanitizer (KTSAN): a data race detector for the Linux kernel](https://docs.google.com/presentation/d/1OsihHNut6E26ACTnT-GplQrdJuByRPNqUmN0HkqurIM/edit?usp=sharing)

* [Автоматический поиск состояний гонок в ядре ОС Linux](http://w27001.vdi.mipt.ru/wp/wp-content/uploads/2017/03/%D0%9A%D0%9E%D0%9D%D0%9E%D0%92%D0%90%D0%9B%D0%9E%D0%92-%D0%90%D0%9D%D0%94%D0%A0%D0%95%D0%99.-%D0%90%D0%92%D0%A2%D0%9E%D0%9C%D0%90%D0%A2%D0%98%D0%A7%D0%95%D0%A1%D0%9A%D0%98%D0%99-%D0%9F%D0%9E%D0%98%D0%A1%D0%9A-%D0%A1%D0%9E%D0%A1%D0%A2%D0%9E%D0%AF%D0%9D%D0%98%D0%99-%D0%93%D0%9E%D0%9D%D0%9E%D0%9A-%D0%92-%D0%AF%D0%94%D0%A0%D0%95-%D0%9E%D0%A1-LINUX.pdf) [in Russian]

## Bugs, notes, and potential improvements

* See [this](https://github.com/google/kernel-sanitizers/issues?q=is%3Aissue+is%3Aopen+label%3AKTSAN) for unresolved issues in KTSAN.

* Make some internal structures per CPU instead of per thread (VC cache, what else?). VCs themselves stay per thread.

* Monitor some kernel thread scheduler events (thread execution started/stopped on CPU).

* Disable interrupts during TSAN events (kernel scheduler events, synchronization events) (CLI, STI).

* Use 4 bytes per slot: 1 for thread id, 2 for clock, 1 for everything else (flags, ...).

* Different threads might have the same thread id (only 256 different values available).

* When clock overflows it is possible to change thread id and connect "old" and "new" threads with a happens-before relation.

* Find races in both kmalloc and vmalloc ranges.

* Use two-level shadow memory mapping scheme for now.

* Do a flush when we run out of clocks. The flush might work as follows. There is a global epoch variable which is increased during each flush. Each thread have a local epoch variable. When a thread is starting it will flush itself if the thread local epoch is less than the global one.
