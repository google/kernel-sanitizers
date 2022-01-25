Kernel Concurrency Sanitizer (KCSAN)
====================================

**Status:** [Upstream](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/kernel/kcsan); in mainline [since 5.5](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dfd402a4c4baae42398ce9180ff424d589b8bffc)

**Documentation:** [Documentation/dev-tools/kcsan.rst](https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html)

**Found bugs:** [here](/kcsan/FOUND_BUGS.md)

**Contacts:** Marco Elver <[@melver](https://github.com/melver)>, Dmitry Vyukov <[@dvyukov](https://github.com/dvyukov)>

## Overview

*Kernel Concurrency Sanitizer (KCSAN)* is a watchpoint-based dynamic race-detector for the Linux kernel.

For details, see the LWN articles:

* [Concurrency bugs should fear the big bad data-race detector (part 1)](https://lwn.net/Articles/816850/)
* [Concurrency bugs should fear the big bad data-race detector (part 2)](https://lwn.net/Articles/816854/)

And a talk:

* [Data-race detection in the Linux kernel at Linux Plumbers Conference 2020](/kcsan/LPC2020-KCSAN.pdf)

For an alternative approach based on a happens-before algorithm, see [Kernel Thread Sanitizer (KCSAN)](/KTSAN.md).

## Continuous testing & fuzzing

We have a [public syzbot instance](https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce). Reports will appear on the dashboard after internal review, to keep the volume of bugs manageable (which gives us a chance to carefully react to KCSAN reports while best practices are still evolving).
