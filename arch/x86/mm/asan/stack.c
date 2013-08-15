#include <linux/printk.h>
#include <linux/stacktrace.h>
#include <linux/types.h>

unsigned int asan_save_stack(unsigned long *stack, unsigned int max_entries)
{
	struct stack_trace trace = {
		.nr_entries = 0,
		.entries = stack,
		.max_entries = max_entries,
		.skip = 0
	};
	save_stack_trace(&trace);
	return trace.nr_entries;
}

void asan_print_stack(unsigned long *stack, unsigned int entries)
{
	unsigned int i;

	pr_err("Stack trace:\n");
	for (i = 0; i < entries; i++)
		pr_err("  [<%p>] %pS\n", (void *)stack[i], (void *)stack[i]);
}

/*
void asan_print_stack(unsigned long *stack, unsigned int entries)
{
	struct stack_trace trace = {
		.nr_entries = entries,
		.entries = stack,
		.max_entries = 0,
		.skip = 0
	};
	print_stack_trace(&trace, 1);
}
*/

void asan_print_current_stack(void)
{
	const size_t max_entries = 64;
	unsigned long stack[max_entries];
	unsigned int entries = asan_save_stack(&stack[0], max_entries);
	asan_print_stack(&stack[0], entries);
}

/*
#include <asm/stacktrace.h>

void asan_print_current_stack(void)
{
	show_stack_log_lvl(NULL, NULL, NULL, 0, KERN_ERR);
}
*/
