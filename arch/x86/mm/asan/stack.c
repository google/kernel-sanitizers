#include <asm-generic/bug.h>
#include <linux/printk.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>

#define MAX_STACK_TRACE_ENTRIES 64

unsigned int asan_save_stack(unsigned long *stack, unsigned int max_entries)
{
	struct stack_trace trace = {
		.nr_entries = 0,
		.entries = stack,
		.max_entries = max_entries,
		.skip = 2 /* Skip save_stack_trace() and asan_save_stack(). */
	};
	save_stack_trace(&trace);
	return trace.nr_entries;
}

void asan_print_stack(unsigned long *stack, unsigned int entries)
{
	unsigned int i;
	for (i = 0; i < entries; i++)
		pr_err("  [<%p>] %pS\n", (void *)stack[i], (void *)stack[i]);
}

void asan_print_current_stack(void)
{
	unsigned long stack[MAX_STACK_TRACE_ENTRIES];
	unsigned int entries = asan_save_stack(&stack[0], MAX_STACK_TRACE_ENTRIES);
	pr_err("Stack trace:\n");
	asan_print_stack(&stack[0], entries);
}
