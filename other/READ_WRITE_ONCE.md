# Why kernel code should use READ_ONCE and WRITE_ONCE for shared memory accesses

There are several reasons to use at least ```READ_ONCE``` and ```WRITE_ONCE``` for _all_ concurrent non-read-only shared memory accesses:

* [It makes code easier to understand](#it-makes-code-easier-to-understand)
* [It is required by relevant standards](#it-is-required-by-relevant-standards)
* [It enables automatic data race detection](#it-enables-automatic-data-race-detection)
* [It is required for kernel memory model](#it-is-required-for-kernel-memory-model)
* [It may improve performance](#it-may-improve-performance)

And there are no reasons to not use them (see [Performance considerations](#performance-considerations) if you are worried about performance).

## It makes code easier to understand

Accesses to shared memory are an important thing and they should be clearly visible in the source code. Whether the accessed memory location can be concurrently read/written significantly affects the way you reason about the code. For example, consider the following code:

```c
    tty = port->itty;
    if (tty == NULL)
        return;
```

It looks like nothing special and does not suggest that this "simple" piece of code actually hides non-trivial synchronization protocol. If the code would look like:

```c
    tty = READ_ONCE(port->itty);
    if (tty == NULL)
        return;
```

It would be clear that concurrent mutations of port->itty are possible, and thus greater attention is required (especially if you are tracking a bug somewhere around). For example, what is the ownership story here? If ```port->itty``` can become ```NULL``` concurrently, can't it also be deleted?

Consider another piece of code which waits for a response from a device and then copies out reply:

```c
	int rc = -1;
	...
	wait_event_timeout(ps2dev->wait, !(ps2dev->flags & PS2_FLAG_CMD), timeout);
	for (i = 0; i < receive; i++)
		resp[i] = ps2dev->cmdbuf[(receive - 1) - i];
	if (ps2dev->cmdcnt)
		goto out;
	rc = 0;
out:
	return rc;
```

This code contains a subtle bug: if the reply arrives right after timeout, then we can copy out uninitialized garbage as response expecting that we will return an error from the function;  but at the point we check ```cmdcnt``` response has already arrived, so we return success and garbage as response. If the code would use ```READ_ONCE``` to read ```ps2dev->flags``` and ```ps2dev->cmdcnt```, then it would be more visible that we are doing a sequence of loads of potentially mutating state, and hopefully draw attention to the possibility of the bad scenario described above. A fix can look as follows:

```c
	int rc = -1;
	...
	wait_event_timeout(ps2dev->wait, !(READ_ONCE(ps2dev->flags) & PS2_FLAG_CMD), timeout);
	if (smp_load_acquire(&ps2dev->cmdcnt) == 0) {
		for (i = 0; i < receive; i++)
			resp[i] = ps2dev->cmdbuf[(receive - 1) - i];
		rc = 0;
	}
	return rc;
```

## It is required by relevant standards

[Linux-Kernel Memory Model](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2015/n4374.html) says:

> Loads from and stores to normal variables should be protected with the ACCESS_ONCE() macro.

C standard is even more uncompromising:

> 5.1.2.4/25
> The execution of a program contains a data race if it contains two conflicting actions in
> different threads, at least one of which is not atomic, and neither happens before the
> other. Any such data race results in **undefined behavior**.

As the consequence C compilers stopped guarantying that "word accesses are atomic". There is a number of ways how compilers can miscompile _non-race-free_ programs, see, for example, [ACCESS_ONCE() article](http://lwn.net/Articles/508991/) and [How to miscompile programs with “benign” data races](https://www.usenix.org/legacy/event/hotpar11/tech/final_files/Boehm.pdf). Some particularly nasty compiler transformations include:

* If code makes a plain write to a variable, then compiler can conclude that there are no concurrent accesses to the variable and use it as scratch storage prior to the write to reduce stack usage. This will make concurrent reads observe garbage values.
* If x is a shared location, ```x = NULL; ...; x = NULL;``` can often be correctly "optimized" by removing one of those assignments if you omit the ```WRITE_ONCE()```. Note that this is true even if there is a single critical section between the two. And this optimization can cross function boundaries.
* If code writes to a bit-field, then compiler can introduce writes to adjacent bit-fields that are not present in the code. For example, the following transformation can reduce code size or improve performance if case 1 is more likely to happen:

```c
x.bits1 = 1;
switch(i) {
case 1:
	x.bits2 = 1;
	...;
	break;
case 2:
	x.bits2 = 1;
	...;
	break;
case 3:
	...;
	break;
}
```
transformed to:
```c
x.bits1 = 1;
tmp = x.bits2;
x.bits2 = 1;
switch(i) {
case 1:
	...;
	break;
case 2:
	...;
	break;
case 3:
	x.bits2 = tmp;
	...;
	break;
}
```

Even if you believe that none of nasty "optimizations" can happen for your code, it seems entirely unreasonable to require that every reader of the code to convince himself of that.

## It enables automatic data race detection

If intentional accesses to shared memory are not marked in some way, then it is also impossible to automatically detect _non-intentional_ accesses to shared memory (that is, forgotten locks, accesses from wrong threads, inconsistent reads of uint64, etc). There are tools that try to find these unpleasant classes of bugs ([KTSAN](/KTSAN.md), [KernelStrider](http://lwn.net/Articles/588630/)), but they cannot accomplish this task while kernel source code is sprinkled with intentional racy accesses that are indistinguishable from bugs.

## It is required for kernel memory model

The [Kernel Memory Consistency Model](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/README)
effort requires marking of all shared accesses. There is no way to give any
formal semantics to unmarked accesses in C.

## It may improve performance

Consider a common way to avoid write sharing:

```c
if (foo->bar != x)
	foo->bar = x;
```

On most architectures compiler if free to compile this as:

```c
foo->bar = x;
```

This is a legal transformation for C code. However, it introduces the write sharing we wanted to avoid. Looking at this sole example, one may conclude that a sane compiler should never do such transformation. But consider another example:

```c
if (foo->bar == 1)
	DEBUG_ONLY_OR_DISABLED_IN_CURRENT_CONFIG();
else
	*foo->bar = 1;
```

This is a single-threaded logic where we want to, say, invoke a debug check on second and subsequent iterations. For this code we do want compiler to transform this to (assuming foo->bar is used somewhere else, or compiler can't prove otherwise):

```c
*foo->bar = 1;
```

At this point it becomes reasonable from performance perspective too to express the original example as:

```c
if (READ_ONCE(foo->bar) != x)
	WRITE_ONCE(foo->bar, x);
```

If compiler sees that it deals with concurrent code, it may use a different set of heuristics for optimization and, in particular, recognize this write-sharing-avoidance pattern and preserve it.

## Performance considerations

Given a sufficiently expressive atomic API and a good implementation, you pay only for what you really need (if you pay just a bit less, generated code becomes incorrect). So performance is not an argument here. Note that if these assumptions do not hold then it is an issue in itself; it is orthogonal to this topic and should be fixed separately.

## Real-world examples

https://lkml.org/lkml/2015/10/5/400
