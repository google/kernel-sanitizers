// SPDX-License-Identifier: GPL-2.0

#include <stdarg.h>

#include <linux/kernel.h>
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
	const char *substring;
	int skipnr;
	int offset = 1;

	/* Depending on error type, find different stack entries. */
	switch (type) {
	case KFENCE_ERROR_UAF:
	case KFENCE_ERROR_OOB:
		substring = "asm_exc_page_fault";
		break;
	case KFENCE_ERROR_CORRUPTION:
		substring = "__slab_free";
		offset = 2; /* Jump over kfree() etc. */
		break;
	}

	for (skipnr = 0; skipnr < num_entries; skipnr++) {
		const int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);

		if (strnstr(buf, substring, len))
			return (skipnr + offset < num_entries) ? (skipnr + offset) : 0;
	}

	/* Could not find a match. */
	return 0;
}

static void kfence_dump_stack(struct seq_file *seq, const struct kfence_alloc_metadata *metadata,
			      bool is_alloc)
{
	const unsigned long *entries = is_alloc ? metadata->stack_alloc : metadata->stack_free;
	unsigned long nr_entries = is_alloc ? metadata->nr_alloc : metadata->nr_free;

	if (nr_entries) {
		/*
		 * Unfortunately stack_trace_seq_print() does not exist, and we
		 * require a temporary buffer for printing the stack trace. We
		 * expect that printing KFENCE metadata information is
		 * serialized under kfence_alloc_lock.
		 */
		static char buf[PAGE_SIZE];

		stack_trace_snprint(buf, sizeof(buf), entries, nr_entries, 0);
		seq_con_printf(seq, "%s", buf);
	} else {
		seq_con_printf(seq, "  no %s stack.\n", is_alloc ? "allocation" : "deallocation");
	}
}

void kfence_dump_object(struct seq_file *seq, const struct kfence_alloc_metadata *metadata)
{
	const int size = abs(metadata->size);
	const unsigned long start = metadata->addr;
	const struct kmem_cache *const cache = metadata->cache;

	if (metadata->state == KFENCE_OBJECT_UNUSED) {
		seq_con_printf(seq, "kfence-#%ld unused.\n", metadata - kfence_metadata);
		return;
	}

	seq_con_printf(seq, "kfence-#%ld [0x%px-0x%px, size=%d, cache=%s] allocated in:\n",
		       metadata - kfence_metadata, (void *)start, (void *)(start + size - 1), size,
		       (cache && cache->name) ? cache->name : "");
	kfence_dump_stack(seq, metadata, true);

	if (metadata->state == KFENCE_OBJECT_FREED) {
		seq_con_printf(seq, "freed in:\n");
		kfence_dump_stack(seq, metadata, false);
	}
}

static void kfence_print_object(const struct kfence_alloc_metadata *metadata)
{
	kfence_dump_object(NULL, metadata);
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
		else
			pr_cont(" 0x%02x", *addr);
	}
	pr_cont(" ]");
}

void kfence_report_error(unsigned long address, const struct kfence_alloc_metadata *metadata,
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
		pr_err("Out-of-bounds access at 0x%px (%s of kfence-#%ld):\n", (void *)address,
		       address < metadata->addr ? "left" : "right", metadata - kfence_metadata);
		break;
	case KFENCE_ERROR_UAF:
		pr_err("BUG: KFENCE: use-after-free in %pS\n\n", (void *)stack_entries[skipnr]);
		pr_err("Use-after-free access at 0x%px:\n", (void *)address);
		break;
	case KFENCE_ERROR_CORRUPTION:
		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entries[skipnr]);
		pr_err("Detected corrupted memory at 0x%px ", (void *)address);
		print_diff_canary((u8 *)address, 16);
		pr_cont(":\n");
		break;
	}

	/* Print stack trace and object info. */
	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
	pr_err("\n");
	kfence_print_object(metadata);

	/* Print report footer. */
	pr_err("\n");
	dump_stack_print_info(KERN_DEFAULT);
	pr_err("==================================================================\n");

	if (panic_on_warn)
		panic("panic_on_warn set ...\n");

	// TODO(elver): Do we want to taint kernel here?
}
