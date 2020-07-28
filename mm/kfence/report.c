// SPDX-License-Identifier: GPL-2.0

#include <stdarg.h>

#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/printk.h>
#include <linux/stacktrace.h>
#include <linux/string.h>

#include "kfence.h"

/* Helper function to either print to a seq_file or to console. */
static void seq_con_printf(struct seq_file *seq, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (seq)
		seq_vprintf(seq, fmt, args);
	else
		vprintk(fmt, args);
	va_end(args);
}

/* Get the number of stack entries to skip get out of MM internals. */
static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries,
			    enum kfence_error_type type)
{
	char buf[64];
	int skipnr, fallback = 0;

	for (skipnr = 0; skipnr < num_entries; skipnr++) {
		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);

		/* Depending on error type, find different stack entries. */
		switch (type) {
		case KFENCE_ERROR_UAF:
		case KFENCE_ERROR_OOB:
		case KFENCE_ERROR_INVALID:
			if (strnstr(buf, "asm_exc_page_fault", len))
				goto found;
			break;
		case KFENCE_ERROR_CORRUPTION:
		case KFENCE_ERROR_INVALID_FREE:
			if (!strncmp(buf, "kfence_", sizeof("kfence_") - 1) ||
			    !strncmp(buf, "__kfence_", sizeof("__kfence_") - 1))
				fallback = skipnr + 1; /* In case kfree tail calls into kfence. */

			/* Also the *_bulk() variants by only checking prefixes. */
			if (!strncmp(buf, "kfree", sizeof("kfree") - 1) ||
			    !strncmp(buf, "kmem_cache_free", sizeof("kmem_cache_free") - 1))
				goto found;
			break;
		}
	}
	if (fallback < num_entries)
		return fallback;
found:
	skipnr++;
	return skipnr < num_entries ? skipnr : 0;
}

static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadata *meta,
			       bool show_alloc)
{
	const unsigned long *entries = show_alloc ? meta->alloc_stack : meta->free_stack;
	const int nentries = show_alloc ? meta->num_alloc_stack : meta->num_free_stack;

	if (nentries) {
		int i;

		/* stack_trace_seq_print() does not exist; open code our own. */
		for (i = 0; i < nentries; i++)
			seq_con_printf(seq, " %pS\n", entries[i]);
	} else {
		seq_con_printf(seq, " no %s stack\n", show_alloc ? "allocation" : "deallocation");
	}
}

void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta)
{
	const int size = abs(meta->size);
	const unsigned long start = meta->addr;
	const struct kmem_cache *const cache = meta->cache;

	lockdep_assert_held(&meta->lock);

	if (meta->state == KFENCE_OBJECT_UNUSED) {
		seq_con_printf(seq, "kfence-#%ld unused\n", meta - kfence_metadata);
		return;
	}

	seq_con_printf(seq,
		       "kfence-#%ld [0x" PTR_FMT "-0x" PTR_FMT
		       ", size=%d, cache=%s] allocated in:\n",
		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1), size,
		       (cache && cache->name) ? cache->name : "<destroyed>");
	kfence_print_stack(seq, meta, true);

	if (meta->state == KFENCE_OBJECT_FREED) {
		seq_con_printf(seq, "freed in:\n");
		kfence_print_stack(seq, meta, false);
	}
}

/*
 * Show bytes at @addr that are different from the expected canary values, up to
 * @max_bytes.
 */
static void print_diff_canary(const u8 *addr, size_t max_bytes)
{
	const u8 *max_addr =
		min((const u8 *)ALIGN((unsigned long)addr, PAGE_SIZE), addr + max_bytes);

	pr_cont("[");
	for (; addr < max_addr; addr++) {
		if (*addr == KFENCE_CANARY_PATTERN(addr))
			pr_cont(" .");
		else if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
			pr_cont(" 0x%02x", *addr);
		else /* Do not leak kernel memory in non-debug builds. */
			pr_cont(" !");
	}
	pr_cont(" ]");
}

void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
			 enum kfence_error_type type)
{
	unsigned long stack_entries[KFENCE_STACK_DEPTH] = { 0 };
	int num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 1);
	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries, type);

	pr_err("==================================================================\n");
	/* Print report header. */
	switch (type) {
	case KFENCE_ERROR_OOB:
		pr_err("BUG: KFENCE: out-of-bounds in %pS\n\n", (void *)stack_entries[skipnr]);
		pr_err("Out-of-bounds access at 0x" PTR_FMT " (%s of kfence-#%ld):\n",
		       (void *)address, address < meta->addr ? "left" : "right",
		       meta - kfence_metadata);
		break;
	case KFENCE_ERROR_UAF:
		pr_err("BUG: KFENCE: use-after-free in %pS\n\n", (void *)stack_entries[skipnr]);
		pr_err("Use-after-free access at 0x" PTR_FMT ":\n", (void *)address);
		break;
	case KFENCE_ERROR_CORRUPTION:
		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entries[skipnr]);
		pr_err("Detected corrupted memory at 0x" PTR_FMT " ", (void *)address);
		print_diff_canary((u8 *)address, 16);
		pr_cont(":\n");
		break;
	case KFENCE_ERROR_INVALID:
		pr_err("BUG: KFENCE: invalid access in %pS\n\n", (void *)stack_entries[skipnr]);
		pr_err("Invalid access at 0x" PTR_FMT ":\n", (void *)address);
		break;
	case KFENCE_ERROR_INVALID_FREE:
		pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[skipnr]);
		pr_err("Invalid free of 0x" PTR_FMT ":\n", (void *)address);
		break;
	}

	/* Print stack trace and object info. */
	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);

	if (meta) {
		pr_err("\n");
		kfence_print_object(NULL, meta);
	}

	/* Print report footer. */
	pr_err("\n");
	dump_stack_print_info(KERN_DEFAULT);
	pr_err("==================================================================\n");
	if (panic_on_warn)
		panic("panic_on_warn set ...\n");

	/* We encountered a memory unsafety error, taint the kernel! */
	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
}
